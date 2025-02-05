import base64
import struct
import zlib
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from keylime import cert_utils, config, json, keylime_logging
from keylime.agentstates import AgentAttestState, TPMClockInfo
from keylime.common.algorithms import Hash
from keylime.failure import Component, Failure
from keylime.ima import ima
from keylime.ima.file_signatures import ImaKeyrings
from keylime.ima.types import RuntimePolicyType
from keylime.mba import mba
from keylime.tpm import tpm2_objects, tpm_util

logger = keylime_logging.init_logging("tpm")


class Tpm:
    @staticmethod
    def encrypt_aik_with_ek(uuid: str, ek_tpm: bytes, aik_tpm: bytes) -> Optional[Tuple[bytes, str]]:
        if ek_tpm is None or aik_tpm is None:
            logger.error("Missing parameters for encryptAIK")
            return None

        aik_name = tpm2_objects.get_tpm2b_public_name(aik_tpm)

        try:
            # write out the challenge
            challenge_str = tpm_util.random_password(32)
            challenge = challenge_str.encode()

            logger.info("Encrypting AIK with EK for UUID %s", uuid)

            # read in the aes key
            key = base64.b64encode(challenge).decode("utf-8")

            credentialblob = tpm_util.makecredential(ek_tpm, challenge, bytes.fromhex(aik_name))
            keyblob = base64.b64encode(credentialblob)

        except Exception:
            logger.exception("Error encrypting AIK with EK")
            raise

        return (keyblob, key)

    @staticmethod
    def verify_aik_with_iak(uuid: str, aik_tpm: bytes, iak_tpm: bytes, iak_attest: bytes, iak_sign: bytes) -> bool:
        attest_body = iak_attest.split(b"\x00$")[1]
        iak_pub = tpm2_objects.pubkey_from_tpm2b_public(iak_tpm)

        # check UUID in certify matches UUID registering
        if attest_body[: len(uuid)] != bytes(uuid, "utf-8"):
            logger.warning("Agent %s AIK verification failed, uuid does not match attest info", uuid)
            return False

        # check aik in certify matches aik being registered
        if tpm2_objects.get_tpm2b_public_name(aik_tpm) != attest_body[len(uuid) + 27 : len(uuid) + 61].hex():
            logger.warning(" Agent %s AIK verification failed, name of aik does not match attest info", uuid)
            return False

        # generate digest of attest info
        digest, hashfunc = tpm_util.crypt_hash(iak_attest, iak_sign[2:4])

        # process iak pub key and import into tpm, get pub key context from tpm
        sig_alg, _, sig_size = struct.unpack_from(">HHH", iak_sign, 0)

        if not isinstance(iak_pub, (RSAPublicKey, EllipticCurvePublicKey)):
            raise ValueError(f"Unsupported key type {type(iak_pub).__name__}")

        if isinstance(iak_pub, RSAPublicKey):
            if sig_alg in [tpm2_objects.TPM_ALG_RSASSA, tpm2_objects.TPM_ALG_RSAPSS]:
                try:
                    (signature,) = struct.unpack_from(f"{sig_size}s", iak_sign, 6)
                    tpm_util.verify(iak_pub, signature, digest, hashfunc, sig_alg, hashfunc.digest_size)
                    logger.info("Agent %s AIK verified with IAK", uuid)
                    return True
                except InvalidSignature:
                    logger.error("Agent %s AIK verification failed with IAK (RSA)", uuid)
                    return False

            else:
                raise ValueError(f"Unsupported quote signature algorithm '{sig_alg:#x}' for RSA keys")

        if isinstance(iak_pub, EllipticCurvePublicKey):
            if sig_alg in [tpm2_objects.TPM_ALG_ECDSA]:
                try:
                    der_sig = tpm_util.ecdsa_der_from_tpm(iak_sign)
                    tpm_util.verify(iak_pub, der_sig, digest, hashfunc)
                    logger.info("Agent %s AIK verified with IAK", uuid)
                    return True
                except InvalidSignature:
                    logger.error("Agent %s AIK verification failed with IAK (ECC)", uuid)
                    return False
            else:
                raise ValueError(f"Unsupported quote signature algorithm '{sig_alg:#x}' for EC keys")
        return False

    @staticmethod
    def verify_ek(ekcert: bytes, tpm_cert_store: str) -> bool:
        """Verify that the provided EK certificate is signed by a trusted root
        :param ekcert: The Endorsement Key certificate in DER format
        :returns: True if the certificate can be verified, false otherwise
        """
        return cert_utils.verify_ek(ekcert, tpm_cert_store)

    @staticmethod
    def _get_quote_parameters(quote: str, compressed: bool) -> Tuple[bytes, bytes, bytes]:
        if quote[0] != "r":
            raise Exception(f"Invalid quote type {quote[0]}")
        quote = quote[1:]

        quote_tokens = quote.split(":")
        if len(quote_tokens) < 3:
            raise Exception(f"Quote is not compound! {quote}")

        quoteblob = base64.b64decode(quote_tokens[0])
        sigblob = base64.b64decode(quote_tokens[1])
        pcrblob = base64.b64decode(quote_tokens[2])

        if compressed:
            logger.warning("Decompressing quote data which is unsafe!")
            quoteblob = zlib.decompress(quoteblob)
            sigblob = zlib.decompress(sigblob)
            pcrblob = zlib.decompress(pcrblob)

        return quoteblob, sigblob, pcrblob

    @staticmethod
    def _tpm2_clock_info_from_quote(quote: str, compressed: bool) -> Dict[str, Any]:
        """Get TPM timestamp info from quote
        :param quote: quote data in the format 'r<b64-compressed-quoteblob>:<b64-compressed-sigblob>:<b64-compressed-pcrblob>
        :param compressed: if the quote data is compressed with zlib or not
        :returns: Returns a dict holding the TPMS_CLOCK_INFO fields
        This function throws an Exception on bad input.
        """

        quoteblob, _, _ = Tpm._get_quote_parameters(quote, compressed)

        try:
            return tpm2_objects.get_tpms_attest_clock_info(quoteblob)
        except Exception:
            logger.exception("Error extracting clock info from quote")
            return {}

    @staticmethod
    def _tpm2_checkquote(
        aikTpmFromRegistrar: str, quote: str, nonce: str, hash_alg: str, compressed: bool
    ) -> Tuple[Dict[int, str], str]:
        """Write the files from data returned from tpm2_quote for running tpm2_checkquote
        :param aikTpmFromRegistrar: AIK used to generate the quote and is needed for verifying it now.
        :param quote: quote data in the format 'r<b64-compressed-quoteblob>:<b64-compressed-sigblob>:<b64-compressed-pcrblob>
        :param nonce: nonce that was used to create the quote
        :param hash_alg: the hash algorithm that was used
        :param compressed: if the quote data is compressed with zlib or not
        :returns: Returns the 'retout' from running tpm2_checkquote and True in case of success, None and False in case of error.
        This function throws an Exception on bad input.
        """
        aikFromRegistrar = tpm2_objects.pubkey_from_tpm2b_public(
            base64.b64decode(aikTpmFromRegistrar),
        ).public_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        quoteblob, sigblob, pcrblob = Tpm._get_quote_parameters(quote, compressed)

        try:
            pcrs_dict = tpm_util.checkquote(aikFromRegistrar, nonce, sigblob, quoteblob, pcrblob, hash_alg)
        except Exception as e:
            logger.exception("Error verifying quote")
            return {}, str(e)

        return pcrs_dict, ""

    @staticmethod
    def __check_ima(
        agentAttestState: AgentAttestState,
        pcrval: str,
        ima_measurement_list: str,
        runtime_policy: Optional[RuntimePolicyType],
        ima_keyrings: Optional[ImaKeyrings],
        boot_aggregates: Optional[Dict[str, List[str]]],
        hash_alg: Hash,
    ) -> Failure:
        failure = Failure(Component.IMA)
        logger.info("Checking IMA measurement list on agent: %s", agentAttestState.get_agent_id())
        _, ima_failure = ima.process_measurement_list(
            agentAttestState,
            ima_measurement_list.split("\n"),
            runtime_policy,
            pcrval=pcrval,
            ima_keyrings=ima_keyrings,
            boot_aggregates=boot_aggregates,
            hash_alg=hash_alg,
        )
        failure.merge(ima_failure)
        if not failure:
            logger.debug("IMA measurement list of agent %s validated", agentAttestState.get_agent_id())
        return failure

    def check_pcrs(
        self,
        agentAttestState: AgentAttestState,
        tpm_policy: Union[str, Dict[str, Any]],
        pcrs_dict: Dict[int, str],
        data: str,
        ima_measurement_list: Optional[str],
        runtime_policy: Optional[RuntimePolicyType],
        ima_keyrings: Optional[ImaKeyrings],
        mb_measurement_list: Optional[str],
        mb_policy: Optional[str],
        hash_alg: Hash,
        count: int,
    ) -> Failure:
        failure = Failure(Component.PCR_VALIDATION)

        agent_id = agentAttestState.get_agent_id()

        if isinstance(tpm_policy, str):
            tpm_policy_dict = json.loads(tpm_policy)
        else:
            tpm_policy_dict = tpm_policy

        pcr_allowlist = tpm_policy_dict.copy()

        if "mask" in pcr_allowlist:
            del pcr_allowlist["mask"]
        # convert all pcr num keys to integers
        pcr_allowlist = {int(k): v for k, v in list(pcr_allowlist.items())}

        mb_pcrs_hashes, boot_aggregates, mb_measurement_data, mb_failure = mba.bootlog_parse(
            mb_measurement_list, hash_alg
        )
        failure.merge(mb_failure)

        pcrs_in_quote: Set[int] = set()  # PCRs in quote that were already used for some kind of validation

        pcr_nums = set(pcrs_dict.keys())

        # Validate data PCR
        if config.TPM_DATA_PCR in pcr_nums and data is not None:
            expectedval = self.sim_extend(data, hash_alg)
            if expectedval != pcrs_dict[config.TPM_DATA_PCR]:
                logger.error(
                    "PCR #%s: invalid bind data %s from quote (from agent %s) does not match expected value %s",
                    config.TPM_DATA_PCR,
                    pcrs_dict[config.TPM_DATA_PCR],
                    agent_id,
                    expectedval,
                )
                failure.add_event(
                    f"invalid_pcr_{config.TPM_DATA_PCR}",
                    {"got": pcrs_dict[config.TPM_DATA_PCR], "expected": expectedval},
                    True,
                )
            pcrs_in_quote.add(config.TPM_DATA_PCR)
        else:
            logger.error(
                "Binding PCR #%s was not included in the quote (from agent %s), but is required",
                config.TPM_DATA_PCR,
                agent_id,
            )
            failure.add_event(
                f"missing_pcr_{config.TPM_DATA_PCR}",
                f"Data PCR {config.TPM_DATA_PCR} is missing in quote, but is required",
                True,
            )
        # Check for ima PCR
        if config.IMA_PCR in pcr_nums:
            if ima_measurement_list is None:
                logger.error("IMA PCR in policy, but no measurement list provided by agent %s", agent_id)
                failure.add_event(
                    f"unused_pcr_{config.IMA_PCR}", "IMA PCR in policy, but no measurement list provided", True
                )
            else:
                ima_failure = Tpm.__check_ima(
                    agentAttestState,
                    pcrs_dict[config.IMA_PCR],
                    ima_measurement_list,
                    runtime_policy,
                    ima_keyrings,
                    boot_aggregates,
                    hash_alg,
                )
                failure.merge(ima_failure)

            pcrs_in_quote.add(config.IMA_PCR)

        # Collect mismatched measured boot PCRs as measured_boot failures
        mb_pcr_failure = Failure(Component.MEASURED_BOOT)
        # Handle measured boot PCRs only if the parsing worked
        if not mb_failure:
            for pcr_num in set(config.MEASUREDBOOT_PCRS) & pcr_nums:
                if mba.policy_is_valid(mb_policy):
                    if not mb_measurement_list:
                        logger.error(
                            "Measured Boot PCR %d in policy, but no measurement list provided by agent %s",
                            pcr_num,
                            agent_id,
                        )
                        failure.add_event(
                            f"unused_pcr_{pcr_num}",
                            f"Measured Boot PCR {pcr_num} in policy, but no measurement list provided",
                            True,
                        )
                        continue

                    val_from_log_int = mb_pcrs_hashes.get(str(pcr_num), 0)
                    val_from_log_hex = hex(val_from_log_int)[2:]
                    val_from_log_hex_stripped = val_from_log_hex.lstrip("0")
                    pcrval_stripped = pcrs_dict[pcr_num].lstrip("0")
                    if val_from_log_hex_stripped != pcrval_stripped:
                        logger.error(
                            "For PCR %d and hash %s the boot event log has value %r but the agent %s returned %r",
                            pcr_num,
                            str(hash_alg),
                            val_from_log_hex,
                            agent_id,
                            pcrs_dict[pcr_num],
                        )
                        mb_pcr_failure.add_event(
                            f"invalid_pcr_{pcr_num}",
                            {
                                "context": "SHA256 boot event log PCR value does not match",
                                "got": pcrs_dict[pcr_num],
                                "expected": val_from_log_hex,
                            },
                            True,
                        )

                    if pcr_num in pcr_allowlist and pcrs_dict[pcr_num] not in pcr_allowlist[pcr_num]:
                        logger.error(
                            "PCR #%s: %s from quote (from agent %s) does not match expected value %s",
                            pcr_num,
                            pcrs_dict[pcr_num],
                            agent_id,
                            pcr_allowlist[pcr_num],
                        )
                        failure.add_event(
                            f"invalid_pcr_{pcr_num}",
                            {
                                "context": "PCR value is not in allowlist",
                                "got": pcrs_dict[pcr_num],
                                "expected": pcr_allowlist[pcr_num],
                            },
                            True,
                        )
                    pcrs_in_quote.add(pcr_num)
        failure.merge(mb_pcr_failure)

        # Check the remaining non validated PCRs
        for pcr_num in pcr_nums - pcrs_in_quote:
            if pcr_num not in list(pcr_allowlist.keys()):
                logger.warning(
                    "PCR #%s in quote (from agent %s) not found in tpm_policy, skipping.",
                    pcr_num,
                    agent_id,
                )
                continue
            if pcrs_dict[pcr_num] not in pcr_allowlist[pcr_num]:
                logger.error(
                    "PCR #%s: %s from quote (from agent %s) does not match expected value %s",
                    pcr_num,
                    pcrs_dict[pcr_num],
                    agent_id,
                    pcr_allowlist[pcr_num],
                )
                failure.add_event(
                    f"invalid_pcr_{pcr_num}",
                    {
                        "context": "PCR value is not in allowlist",
                        "got": pcrs_dict[pcr_num],
                        "expected": pcr_allowlist[pcr_num],
                    },
                    True,
                )

            pcrs_in_quote.add(pcr_num)

        missing = set(pcr_allowlist.keys()) - pcrs_in_quote
        if len(missing) > 0:
            logger.error("PCRs specified in policy not in quote (from agent %s): %s", agent_id, missing)
            failure.add_event("missing_pcrs", {"context": "PCRs are missing in quote", "data": list(missing)}, True)

        if not mb_failure and mba.policy_is_valid(mb_policy):
            mb_evaluate = config.get("verifier", "measured_boot_evaluate", fallback="once")

            # Value of measured_boot_evaluate can be only 'once' or 'always'
            if mb_evaluate not in ("once", "always"):
                logger.error("Invalid value %s of measured_boot_evaluate", mb_evaluate)
                failure.add_event(
                    "invalid_measured_boot_evaluate", "correct value of measured_boot_evaluate is required", True
                )

            if mb_evaluate == "always":
                mb_policy_failure = mba.bootlog_evaluate(
                    mb_policy,
                    mb_measurement_data,
                    pcrs_in_quote,
                    agentAttestState.get_agent_id(),
                )
                failure.merge(mb_policy_failure)

            elif mb_evaluate == "once" and count == 0:
                mb_policy_failure = mba.bootlog_evaluate(
                    mb_policy,
                    mb_measurement_data,
                    pcrs_in_quote,
                    agentAttestState.get_agent_id(),
                )
                failure.merge(mb_policy_failure)

        return failure

    def check_quote(
        self,
        agentAttestState: AgentAttestState,
        nonce: str,
        data: str,
        quote: str,
        aikTpmFromRegistrar: str,
        tpm_policy: Optional[Union[str, Dict[str, Any]]] = None,
        ima_measurement_list: Optional[str] = None,
        runtime_policy: Optional[RuntimePolicyType] = None,
        hash_alg: Hash = Hash.SHA256,
        ima_keyrings: Optional[ImaKeyrings] = None,
        mb_measurement_list: Optional[str] = None,
        mb_policy: Optional[str] = None,
        compressed: bool = False,
        count: int = -1,
        skip_pcr_check: bool = False,
        skip_clock_check: bool = False,
    ) -> Failure:
        if tpm_policy is None:
            tpm_policy = {}

        if runtime_policy is None:
            runtime_policy = ima.EMPTY_RUNTIME_POLICY

        failure = Failure(Component.QUOTE_VALIDATION)

        # First and foremost, the quote needs to be validated
        pcrs_dict, err = Tpm._tpm2_checkquote(aikTpmFromRegistrar, quote, nonce, str(hash_alg), compressed)
        if err:
            # If the quote validation fails we will skip all other steps therefore this failure is irrecoverable.
            failure.add_event("quote_validation", {"message": "Quote data validation", "error": err}, False)
            return failure

        if not skip_clock_check:
            # Only after validating the quote, the TPM clock information can be extracted from it.
            clock_failure, current_clock_info = Tpm.check_quote_timing(
                agentAttestState.get_tpm_clockinfo(), quote, compressed
            )
            if clock_failure:
                failure.add_event(
                    "quote_validation",
                    {"message": "Validation of clockinfo from quote using tpm2-tools", "data": clock_failure},
                    False,
                )
                return failure
            if current_clock_info:
                agentAttestState.set_tpm_clockinfo(current_clock_info)

        if not skip_pcr_check:
            if len(pcrs_dict) == 0:
                logger.warning(
                    "Quote for agent %s does not contain any PCRs. Make sure that the TPM supports %s PCR banks",
                    agentAttestState.agent_id,
                    str(hash_alg),
                )

            return self.check_pcrs(
                agentAttestState,
                tpm_policy,
                pcrs_dict,
                data,
                ima_measurement_list,
                runtime_policy,
                ima_keyrings,
                mb_measurement_list,
                mb_policy,
                hash_alg,
                count,
            )

        return failure

    @staticmethod
    def check_quote_timing(
        previous_clockinfo: TPMClockInfo, quote: str, compressed: bool
    ) -> Tuple[Optional[str], Optional[TPMClockInfo]]:
        # Sanity check quote clock information

        current_clockinfo = None

        clock_info_dict = Tpm._tpm2_clock_info_from_quote(quote, compressed)
        if not clock_info_dict:
            return "_tpm2_clock_info_from_quote failed ", current_clockinfo

        tentative_current_clockinfo = TPMClockInfo.from_dict(clock_info_dict)

        resetdiff = tentative_current_clockinfo.resetcount - previous_clockinfo.resetcount
        restartdiff = tentative_current_clockinfo.restartcount - previous_clockinfo.restartcount

        if resetdiff < 0:
            return "resetCount value decreased on TPM between two consecutive quotes", current_clockinfo

        if restartdiff < 0:
            return "restartCount value decreased on TPM between two consecutive quotes", current_clockinfo

        if tentative_current_clockinfo.safe != 1:
            return "clock safe flag is disabled", current_clockinfo

        if not (resetdiff and restartdiff):
            if tentative_current_clockinfo.clock - previous_clockinfo.clock <= 0:
                return (
                    "clock timestamp did issued by TPM did not increase between two consecutive quotes",
                    current_clockinfo,
                )

            current_clockinfo = tentative_current_clockinfo

        return None, current_clockinfo

    @staticmethod
    def sim_extend(hashval_1: str, hash_alg: Hash) -> str:
        """Compute expected value  H(0|H(data))"""
        hdata = hash_alg.hash(hashval_1.encode("utf-8"))
        hext = hash_alg.hash(hash_alg.get_start_hash() + hdata)
        return hext.hex()
