import argparse
import base64
import io
import json
import logging
import os
import ssl
import sys
import tempfile
import time
import zipfile
from typing import Any, Dict, List, Optional, Union, cast

import requests
from cryptography.hazmat.primitives import serialization as crypto_serialization

from keylime import api_version as keylime_api_version
from keylime import ca_util, cert_utils, config, crypto, keylime_logging, registrar_client, signing, web_util
from keylime.agentstates import AgentAttestState
from keylime.cli import options, policies
from keylime.cmd import user_data_encrypt
from keylime.common import algorithms, retry, states, validators
from keylime.ip_util import bracketize_ipv6
from keylime.mba import mba
from keylime.requests_client import RequestsClient
from keylime.tpm import tpm2_objects, tpm_util
from keylime.tpm.tpm_main import Tpm
from keylime.cert_utils import x509_pem_cert, x509_der_cert, cert_signature_check

# setup logging
logger = keylime_logging.init_logging("tenant")


# special exception that suppresses stack traces when it happens
class UserError(Exception):
    pass


class Tenant:
    """Simple command processor example."""

    config = None

    verifier_ip: Optional[str] = None
    verifier_port: Optional[str] = None

    nonce: Optional[str]

    agent_ip: Optional[str] = None
    cv_cloudagent_ip: Optional[str] = None
    agent_port: Optional[str] = None

    registrar_ip: Optional[str] = None
    registrar_port: Optional[str] = None
    registrar_data: Optional[registrar_client.RegistrarData] = None

    api_version: Optional[str] = None

    # uuid_service_generate_locally = None
    agent_uuid: str = ""

    K: bytes = b""
    V: bytes = b""
    U: bytes = b""
    auth_tag = None

    tpm_policy = None
    metadata: Dict[str, Union[int, str]] = {}
    runtime_policy: str = ""
    runtime_policy_name: str = ""
    runtime_policy_key = None
    ima_sign_verification_keys: Optional[str] = ""
    revocation_key: str = ""
    accept_tpm_hash_algs: List[str] = []
    accept_tpm_encryption_algs: List[str] = []
    accept_tpm_signing_algs: List[str] = []

    mb_policy = None
    mb_policy_name: str = ""
    supported_version: Optional[str] = None

    client_cert = None
    client_key = None
    client_key_password: Optional[str] = None
    trusted_server_ca: List[str] = []
    enable_agent_mtls: bool = False
    verify_server_cert: bool = False
    verify_custom: Optional[str] = None

    request_timeout: Optional[int] = None

    agent_fid_str: Optional[str] = None
    verifier_fid_str: Optional[str] = None
    registrar_fid_str: Optional[str] = None

    # Context with the trusted CA certificates from the configuration
    tls_context: Optional[ssl.SSLContext] = None

    # Context with the agent's mTLS certificate
    agent_tls_context: Optional[ssl.SSLContext] = None

    payload: Optional[bytes] = None

    tpm_instance: Tpm = Tpm()

    def __init__(self) -> None:
        """Set up required values and TLS"""
        self.nonce = None
        self.agent_ip = None
        self.agent_port = None
        self.verifier_id = None
        self.verifier_ip = config.get("tenant", "verifier_ip")
        self.verifier_port = config.get("tenant", "verifier_port")
        self.registrar_ip = config.get("tenant", "registrar_ip")
        self.registrar_port = config.get("tenant", "registrar_port")
        self.api_version = keylime_api_version.current_version()
        self.enable_agent_mtls = config.getboolean("tenant", "enable_agent_mtls")
        self.request_timeout = config.getint("tenant", "request_timeout", fallback=60)
        self.retry_interval = config.getfloat("tenant", "retry_interval")
        self.exponential_backoff = config.getboolean("tenant", "exponential_backoff")
        self.maxr = config.getint("tenant", "max_retries")

        logger.info("Setting up client TLS...")
        (cert, key, trusted_ca, key_password), verify_server_cert = web_util.get_tls_options(
            "tenant", is_client=True, logger=logger
        )

        if not self.enable_agent_mtls:
            logger.warning(
                "Warning: agent mTLS is currently disabled, keys will be sent in the clear! This should only be used for testing."
            )

        if not verify_server_cert:
            logger.warning(
                "Warning: server certificate verification is disabled as 'trusted_server_ca' option is set to 'all'. This should only be used for testing."
            )

        if not trusted_ca:
            logger.warning("No certificates provided in 'trusted_server_ca'")

        if cert and not os.path.isfile(cert):
            logger.warning("Could not find file %s provided in 'client_cert'", cert)

        if key and not os.path.isfile(key):
            logger.warning("Could not find file %s provided in 'client_key'", key)

        if all([(cert and os.path.isfile(cert)), (key and os.path.isfile(key))]):
            self.client_cert = cert
            self.client_key = key
            self.client_key_password = key_password
            self.verify_server_cert = verify_server_cert
            self.trusted_server_ca = trusted_ca

            self.tls_context = web_util.generate_tls_context(
                cert, key, trusted_ca, key_password, verify_server_cert, is_client=True, logger=logger
            )

            logger.info("TLS is enabled.")
        else:
            logger.warning("TLS is disabled.")

        mba.load_imports(skip_custom_policies=True)

    @property
    def verifier_base_url(self) -> str:
        return f"{bracketize_ipv6(self.verifier_ip)}:{self.verifier_port}"

    def set_full_id_str(self) -> None:
        self.agent_fid_str = f"Agent {self.agent_uuid}"
        if self.agent_ip:
            self.agent_fid_str = f"{self.agent_fid_str} ({self.agent_ip}:{self.agent_port})"
        self.verifier_fid_str = "Verifier"
        if self.verifier_id:
            self.verifier_fid_str = f"{self.verifier_fid_str} {self.verifier_id}"
        if self.verifier_ip:
            self.verifier_fid_str = f"{self.verifier_fid_str} ({self.verifier_ip}:{self.verifier_port})"
        self.registrar_fid_str = "Registrar"
        if self.registrar_ip:
            self.registrar_fid_str = f"{self.registrar_fid_str} ({self.registrar_ip}:{self.registrar_port})"

    def init_add(self, args: Dict[str, Any]) -> None:
        """Set up required values. Command line options can overwrite these config values

        Arguments:
            args {[string]} -- agent_ip|agent_port|cv_agent_ip
        """
        if "agent_ip" in args:
            self.agent_ip = args["agent_ip"]

        if "agent_port" in args and args["agent_port"] is not None:
            self.agent_port = args["agent_port"]

        if not self.registrar_ip or not self.registrar_port:
            raise UserError("registrar_ip and registrar_port have both to be set in the configuration")
        self.registrar_data = registrar_client.getData(
            self.registrar_ip, self.registrar_port, self.agent_uuid, self.tls_context
        )

        if self.registrar_data is None:
            raise UserError(f"Agent ${self.agent_uuid} data not found in the Registrar.")

        # try to get the port or ip from the registrar if it is missing
        if (self.agent_ip is None or self.agent_port is None) and self.registrar_data is not None:
            if self.agent_ip is None:
                if self.registrar_data["ip"] is not None:
                    self.agent_ip = self.registrar_data["ip"]
                else:
                    raise UserError("No Ip was specified or found in the Registrar")

            if self.agent_port is None and self.registrar_data["port"] is not None:
                self.agent_port = self.registrar_data["port"]

        # Check if a contact ip and port for the agent was found
        if self.agent_ip is None:
            raise UserError("The contact ip address for the agent was not specified.")

        if self.agent_port is None:
            raise UserError("The contact port for the agent was not specified.")

        self.set_full_id_str()

        # Auto-detection for API version
        self.supported_version = args["supported_version"]
        # Default to 1.0 if the agent did not send a mTLS certificate
        if self.registrar_data.get("mtls_cert", None) is None and self.supported_version is None:
            self.supported_version = "1.0"
        else:
            # Try to connect to the agent to get supported version
            if self.registrar_data["mtls_cert"] == "disabled":
                self.enable_agent_mtls = False
                logger.warning(
                    "Warning: mTLS for %s is disabled: the identity of each node will be based on the properties of the TPM only. "
                    "Unless you have strict control of your network, it is strongly advised that remote code execution should be disabled, "
                    'by setting "payload_script=" and "extract_payload_zip=False" under "[agent]" in agent configuration file.',
                    self.agent_fid_str,
                )
                tls_context = None
            else:
                # Store the agent self-signed certificate as a string
                self.verify_custom = self.registrar_data["mtls_cert"]

                if not self.agent_tls_context:
                    self.agent_tls_context = web_util.generate_tls_context(
                        self.client_cert,
                        self.client_key,
                        self.trusted_server_ca,
                        self.client_key_password,
                        self.verify_server_cert,
                        is_client=True,
                        ca_cert_string=self.verify_custom,
                        logger=logger,
                    )
                tls_context = self.agent_tls_context

            with RequestsClient(
                f"{bracketize_ipv6(self.agent_ip)}:{self.agent_port}",
                tls_enabled=self.enable_agent_mtls,
                tls_context=tls_context,
            ) as get_version:
                try:
                    res = get_version.get("/version")
                except requests.exceptions.SSLError as ssl_error:
                    if "TLSV1_ALERT_UNKNOWN_CA" in str(ssl_error):
                        raise UserError(
                            "Keylime agent does not recognize mTLS certificate form tenant. "
                            "Check if agents trusted_client_ca is configured correctly"
                        ) from ssl_error

                    raise ssl_error from ssl_error
                if res and res.status_code == 200:
                    try:
                        data = res.json()
                        api_version = data["results"]["supported_version"]
                        if keylime_api_version.validate_version(api_version) and self.supported_version is None:
                            self.supported_version = api_version
                        else:
                            logger.warning("API version provided by the agent is not valid")
                    except (TypeError, KeyError):
                        pass

        if self.supported_version is None:
            api_version = keylime_api_version.current_version()
            logger.warning("Could not detect supported API version. Defaulting to %s", api_version)
            self.supported_version = api_version

        # Now set the cv_agent_ip
        if "cv_agent_ip" in args and args["cv_agent_ip"] is not None:
            self.cv_cloudagent_ip = args["cv_agent_ip"]
        else:
            self.cv_cloudagent_ip = self.agent_ip

        # Make sure all keys exist in dictionary
        if "file" not in args:
            args["file"] = None
        if "keyfile" not in args:
            args["keyfile"] = None
        if "payload" not in args:
            args["payload"] = None
        if "ca_dir" not in args:
            args["ca_dir"] = None
        if "incl_dir" not in args:
            args["incl_dir"] = None
        if "ca_dir_pw" not in args:
            args["ca_dir_pw"] = None

        # Set up accepted algorithms
        self.accept_tpm_hash_algs = config.getlist("tenant", "accept_tpm_hash_algs")
        self.accept_tpm_encryption_algs = config.getlist("tenant", "accept_tpm_encryption_algs")
        self.accept_tpm_signing_algs = config.getlist("tenant", "accept_tpm_signing_algs")

        (
            self.tpm_policy,
            self.mb_policy,
            self.mb_policy_name,
            self.runtime_policy_name,
            self.ima_sign_verification_keys,
            self.runtime_policy,
            self.runtime_policy_key,
        ) = policies.process_policy(cast(policies.ArgsType, args))

        # Check if verify flag is not set when no payload is added
        if args["verify"] and not (args["file"] or args["ca_dir"] or args["keyfile"]):
            raise UserError("--verify only works when a payload is provided to the agent via -k, -f, or --cert")

        if args["keyfile"] is not None:
            if args["file"] is not None or args["ca_dir"] is not None:
                raise UserError(
                    "You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the agent"
                )

            # read the keys in
            f: Union[io.StringIO, io.TextIOWrapper, io.BufferedReader]
            if isinstance(args["keyfile"], dict) and "data" in args["keyfile"]:
                if isinstance(args["keyfile"]["data"], list) and len(args["keyfile"]["data"]) == 1:
                    keyfile = args["keyfile"]["data"][0]
                    if keyfile is None:
                        raise UserError("Invalid key file contents")
                    f = io.StringIO(keyfile)
                else:
                    raise UserError("Invalid key file provided")
            else:
                f = open(str(args["keyfile"]), encoding="utf-8")  # pylint: disable=consider-using-with
            self.K = base64.b64decode(f.readline())
            self.U = base64.b64decode(f.readline())
            self.V = base64.b64decode(f.readline())
            f.close()

            # read the payload in (opt.)
            if isinstance(args["payload"], dict) and "data" in args["payload"]:
                if isinstance(args["payload"]["data"], list) and len(args["payload"]["data"]) > 0:
                    self.payload = args["payload"]["data"][0]
            else:
                if args["payload"] is not None:
                    with open(str(args["payload"]), "rb") as f:
                        self.payload = f.read()

        if args["file"] is not None:
            if args["keyfile"] is not None or args["ca_dir"] is not None:
                raise UserError(
                    "You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the agent"
                )

            if isinstance(args["file"], dict) and "data" in args["file"]:
                if isinstance(args["file"]["data"], list) and len(args["file"]["data"]) > 0:
                    contents = args["file"]["data"][0]
                    if contents is None:
                        raise UserError("Invalid file payload contents")
                else:
                    raise UserError("Invalid file payload provided")
            else:
                with open(str(args["file"]), "rb") as f:
                    contents = f.read()
            ret = user_data_encrypt.encrypt(contents)
            self.K = ret["k"]
            self.U = ret["u"]
            self.V = ret["v"]
            self.payload = ret["ciphertext"]

        if args["ca_dir"] is None and args["incl_dir"] is not None:
            raise UserError("--include option is only valid when used with --cert")
        if args["ca_dir"] is not None:
            if args["file"] is not None or args["keyfile"] is not None:
                raise UserError(
                    "You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the agent"
                )
            if args["ca_dir"] == "default":
                args["ca_dir"] = config.CA_WORK_DIR

            ca_util.ask_password(args["ca_dir_pw"])

            if not os.path.exists(args["ca_dir"]) or not os.path.exists(os.path.join(args["ca_dir"], "cacert.crt")):
                logger.warning("CA directory does not exist. Creating...")
                ca_util.cmd_init(args["ca_dir"])
            if not os.path.exists(os.path.join(args["ca_dir"], f"{self.agent_uuid}-private.pem")):
                ca_util.cmd_mkcert(args["ca_dir"], self.agent_uuid)

            try:
                cert_pkg, serial, subject = ca_util.cmd_certpkg(args["ca_dir"], self.agent_uuid)
            except Exception as e:
                raise UserError(f"Error reading the keystore from {args['ca_dir']}: {e}") from e

            # support revocation
            if not os.path.exists(os.path.join(args["ca_dir"], "RevocationNotifier-private.pem")):
                ca_util.cmd_mkcert(args["ca_dir"], "RevocationNotifier")
            rev_package, _, _ = ca_util.cmd_certpkg(args["ca_dir"], "RevocationNotifier")

            # extract public and private keys from package
            sf = io.BytesIO(rev_package)
            with zipfile.ZipFile(sf) as zf:
                privkey = zf.read("RevocationNotifier-private.pem")
                cert = zf.read("RevocationNotifier-cert.crt")

            # put the cert of the revoker into the cert package
            sf = io.BytesIO(cert_pkg)
            with zipfile.ZipFile(sf, "a", compression=zipfile.ZIP_STORED) as zf:
                zf.writestr("RevocationNotifier-cert.crt", cert)

                # add additional files to zip
                if args["incl_dir"] is not None:
                    if isinstance(args["incl_dir"], dict) and "data" in args["incl_dir"] and "name" in args["incl_dir"]:
                        if isinstance(args["incl_dir"]["data"], list) and isinstance(args["incl_dir"]["name"], list):
                            if len(args["incl_dir"]["data"]) != len(args["incl_dir"]["name"]):
                                raise UserError("Invalid incl_dir provided")
                            for i in range(len(args["incl_dir"]["data"])):
                                zf.writestr(os.path.basename(args["incl_dir"]["name"][i]), args["incl_dir"]["data"][i])
                    else:
                        incl_dir = str(args["incl_dir"])
                        if os.path.exists(incl_dir):
                            files = next(os.walk(incl_dir))[2]
                            for filename in files:
                                with open(os.path.join(incl_dir, filename), "rb") as f:
                                    zf.writestr(os.path.basename(f.name), f.read())
                        else:
                            logger.warning(
                                "Specified include directory %s does not exist. Skipping...", args["incl_dir"]
                            )

            cert_pkg = sf.getvalue()

            # put the private key into the data to be send to the CV
            self.revocation_key = privkey.decode("utf-8")

            # encrypt up the cert package
            ret = user_data_encrypt.encrypt(cert_pkg)
            self.K = ret["k"]
            self.U = ret["u"]
            self.V = ret["v"]
            self.metadata = {"cert_serial": serial, "subject": subject}
            self.payload = ret["ciphertext"]

        if self.payload is not None:
            max_payload_size = config.getint("tenant", "max_payload_size")
            if len(self.payload) > max_payload_size:
                raise UserError(f"Payload size {len(self.payload)} exceeds max size {max_payload_size}")

    def preloop(self) -> None:
        """encrypt the agent UUID as a check for delivering the correct key"""
        self.auth_tag = crypto.do_hmac(self.K, self.agent_uuid)
        # be very careful printing K, U, or V as they leak in logs stored on unprotected disks
        if config.INSECURE_DEBUG:
            logger.debug("K: %s", base64.b64encode(self.K))
            logger.debug("V: %s", base64.b64encode(self.V))
            logger.debug("U: %s", base64.b64encode(self.U))
            logger.debug("Auth Tag: %s", self.auth_tag)

    def check_ek_ca_chain(self, ekcert: str, ek_ca_chain: Optional[str]) -> (bool, bytes):
        certificates = []
        # Load certificates from chain
        for cert in ek_ca_chain.split('-----END CERTIFICATE-----'):
            if '-----BEGIN CERTIFICATE-----' in cert:
                cert += '-----END CERTIFICATE-----'
                try:
                    certificates.append(x509_pem_cert(cert))
                except Exception as err:
                    logger.error("Error processing ek_ca_chain. Does this TPM have a valid EK CA Chain stored in the TPM?: %s", err)
                    return False, None
        # Load ekcert
        try:
            ek509 = x509_der_cert(ekcert)
            certificates.append(ek509)
        except Exception as err:
            # Log the exception so we don't lose the raw message
            logger.error("Error processing ek/ekcert. Does this TPM have a valid EK?: %s", err)
            return False, None

        # Verify chain
        for i in range(len(certificates) - 1, 0, -1):
            if not cert_signature_check(certificates[i], certificates[i-1]):
                logger.error("Broken certificate chain: %s not signed by %s", certificates[i].issuer, certificates[i-1].subject)
                return False, None

        return True, certificates[0].public_bytes(crypto_serialization.Encoding.DER)

    def check_ek(self, ekcert: Optional[str], ek_ca_chain: Optional[str] = "") -> bool:
        """Check the Entity Key

        Arguments:
            ekcert {str} -- The endorsement key, either None, "emulator", or base64 encoded der cert

        Returns:
            [type] -- [description]
        """
        if config.getboolean("tenant", "require_ek_cert"):
            if ekcert == "emulator" and config.DISABLE_EK_CERT_CHECK_EMULATOR:
                logger.info("Not checking ekcert of TPM emulator for %s", self.agent_fid_str)
            elif ekcert is None:
                logger.warning(
                    "No EK cert provided, require_ek_cert option in config set to True for %s", self.agent_fid_str
                )
                return False
            else:
                # In case of a provided ek_ca_chain verify the ek against the provided chain. In case of success replace
                # the ekcert with the toplevel ca from the chain. This toplevel certificate can be verified against the
                # tpm_cert_store.
                ok: bool = False
                ekcert = base64.b64decode(ekcert)
                if ek_ca_chain:
                    ok, ekcert = self.check_ek_ca_chain(ekcert, ek_ca_chain)
                    if not ok:
                        logger.warning("Invalid EK certificate chain for %s", self.agent_fid_str)
                        return False

                if not self.tpm_instance.verify_ek(ekcert, config.get("tenant", "tpm_cert_store")):
                    logger.warning("Invalid EK certificate for %s", self.agent_fid_str)
                    return False

        return True

    def validate_tpm_quote(self, public_key: str, quote: str, hash_alg: algorithms.Hash) -> bool:
        """Validate TPM Quote received from the Agent

        Arguments:
            public_key {[type]} -- [description]
            quote {[type]} -- [description]
            hash_alg {bool} -- [description]

        Raises:
            UserError: [description]

        Returns:
            [type] -- [description]
        """
        if self.registrar_data is None:
            logger.warning(
                "AIK not found in %s, quote not validated for %s", self.registrar_fid_str, self.agent_fid_str
            )
            return False

        if not self.nonce:
            logger.warning("Nonce has not been set for %s!", self.agent_fid_str)
            return False

        failure = self.tpm_instance.check_quote(
            AgentAttestState(self.agent_uuid),
            self.nonce,
            public_key,
            quote,
            self.registrar_data["aik_tpm"],
            hash_alg=hash_alg,
            compressed=(self.supported_version == "1.0"),
        )
        if failure:
            if self.registrar_data["regcount"] > 1:
                logger.error(
                    "WARNING: %s had more than one ek-ekcert registered to it! This might indicate that your system is misconfigured or a malicious host is present. Run 'regdelete' for this agent and restart",
                    self.agent_fid_str,
                )
            return False

        if not config.getboolean("tenant", "require_ek_cert") and config.get("tenant", "ek_check_script") == "":
            logger.warning(
                "DANGER: EK cert checking is disabled and no additional checks on EKs have been specified with ek_check_script option for %s. Keylime is not secure!!",
                self.agent_fid_str,
            )
            return True

        # check EK cert and make sure it matches EK
        if not self.check_ek(self.registrar_data["ekcert"], self.registrar_data["ek_ca_chain"]):
            return False
        # if agent is virtual, check phyisical EK cert and make sure it matches phyiscal EK
        if "provider_keys" in self.registrar_data:
            if not self.check_ek(self.registrar_data["provider_keys"]["ekcert"]):
                return False

        # check all EKs with optional script:
        script = config.get("tenant", "ek_check_script")
        if not script:
            return True

        if script[0] != "/":
            script = os.path.join(config.WORK_DIR, script)

        logger.info("Checking EK for %s with script %s", self.agent_fid_str, script)
        # now we need to exec the script with the ek and ek cert in vars
        env = os.environ.copy()
        env["AGENT_UUID"] = self.agent_uuid
        env["EK"] = (
            tpm2_objects.pubkey_from_tpm2b_public(
                base64.b64decode(self.registrar_data["ek_tpm"]),
            )
            .public_bytes(
                crypto_serialization.Encoding.PEM,
                crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        env["EK_TPM"] = self.registrar_data["ek_tpm"]
        if self.registrar_data["ekcert"] is not None:
            env["EK_CERT"] = self.registrar_data["ekcert"]
        else:
            env["EK_CERT"] = ""

        env["PROVKEYS"] = json.dumps(self.registrar_data.get("provider_keys", {}))

        # Define the TPM cert store for the external script.
        env["TPM_CERT_STORE"] = config.get("tenant", "tpm_cert_store")

        return cert_utils.verify_ek_script(script, env, config.WORK_DIR)

    def do_cvadd(self) -> None:
        """Initiate v, agent_id and ip and initiate the cloudinit sequence"""
        b64_v = base64.b64encode(self.V).decode("utf-8") if self.V else None
        logger.debug("b64_v: %s", b64_v)
        assert self.registrar_data
        data = {
            "v": b64_v,
            "cloudagent_ip": self.cv_cloudagent_ip,
            "cloudagent_port": self.agent_port,
            "verifier_ip": self.verifier_ip,
            "verifier_port": self.verifier_port,
            "tpm_policy": json.dumps(self.tpm_policy),
            "runtime_policy": self.runtime_policy,
            "runtime_policy_name": self.runtime_policy_name,
            "runtime_policy_key": self.runtime_policy_key,
            "mb_policy": self.mb_policy,
            "mb_policy_name": self.mb_policy_name,
            "ima_sign_verification_keys": self.ima_sign_verification_keys,
            "metadata": json.dumps(self.metadata),
            "revocation_key": self.revocation_key,
            "accept_tpm_hash_algs": self.accept_tpm_hash_algs,
            "accept_tpm_encryption_algs": self.accept_tpm_encryption_algs,
            "accept_tpm_signing_algs": self.accept_tpm_signing_algs,
            "ak_tpm": self.registrar_data["aik_tpm"],
            "mtls_cert": self.registrar_data.get("mtls_cert", None),
            "supported_version": self.supported_version,
        }
        json_message = json.dumps(data)
        do_cv = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = do_cv.post(
            (f"/v{self.api_version}/agents/{self.agent_uuid}"), data=json_message, timeout=self.request_timeout
        )

        if response.status_code == 503:
            raise UserError(
                f"Cannot connect to {self.verifier_fid_str} while adding {self.agent_fid_str}. Connection refused."
            )

        if response.status_code == 504:
            logger.error("%s timed out while adding %s.", self.verifier_fid_str, self.agent_fid_str)
            raise UserError(f"{self.verifier_fid_str} timed out while adding {self.agent_fid_str}")

        response_json = Tenant._jsonify_response(response, print_response=False, raise_except=True)

        if response.status_code == 409:
            raise UserError(
                f'{self.verifier_fid_str} responded indicating a conflict for agent {self.agent_fid_str}. Run "delete" or "update" first.'
            )

        if response.status_code != 200:
            keylime_logging.log_http_response(logger, logging.ERROR, response_json)
            raise UserError(
                f"POST command response: {response.status_code} Unexpected response from {self.verifier_fid_str}: {response.text}",
            )

        numtries = 0
        added = False

        while not added:
            reponse_json = self.do_cvstatus(not_found_fail=False)
            if reponse_json["code"] != 200:
                numtries += 1
                if numtries >= self.maxr:
                    raise UserError(
                        f"{self.agent_fid_str} still not added to {self.verifier_fid_str} after ${numtries} tries"
                    )

                next_retry = retry.retry_time(self.exponential_backoff, self.retry_interval, numtries, logger)
                logger.info(
                    "%s still not added to %s at try %d/%d, trying again in %d seconds...",
                    self.agent_fid_str,
                    self.verifier_fid_str,
                    numtries,
                    self.maxr,
                    next_retry,
                )
                time.sleep(next_retry)
            else:
                added = True

            if added:
                logger.info(
                    "%s added to %s after %d tries",
                    self.agent_fid_str,
                    self.verifier_fid_str,
                    numtries,
                )

    def do_cvstatus(self, not_found_fail: bool = True) -> Dict[str, Any]:
        """Perform operational state look up for agent on the verifier"""

        self.set_full_id_str()

        do_cvstatus = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)

        response = do_cvstatus.get((f"/v{self.api_version}/agents/{self.agent_uuid}"), timeout=self.request_timeout)

        response_json = Tenant._jsonify_response(response, print_response=False, raise_except=True)

        if response.status_code == 503:
            raise UserError(f"Cannot connect to {self.verifier_fid_str}. Connection refused.")

        if response.status_code == 504:
            logger.error("%s timed out.", self.verifier_fid_str)
            raise UserError("{self.verifier_fid_str} timed out.")

        if response.status_code == 404:
            # Marked for deletion (need to modify the code on CI tests)
            logger.info(
                "Verifier at %s with Port %s does not have agent %s.",
                self.verifier_ip,
                self.verifier_port,
                self.agent_uuid,
            )
            if not_found_fail:
                raise UserError(f"{self.agent_fid_str} does not exist on {self.verifier_fid_str}.")

            return response_json

        if response.status_code == 200:
            res = response_json.pop("results")
            response_json["results"] = {self.agent_uuid: res}

            operational_state = states.state_to_str(response_json["results"][self.agent_uuid]["operational_state"])
            response_json["results"][self.agent_uuid]["operational_state"] = operational_state

            logger.info("Agent Info from %s:\n%s", self.verifier_fid_str, json.dumps(response_json["results"]))

            return response_json

        # EVALUATE DELETION
        #        logger.info(
        #            "Status command response: %s. Unexpected response from %s. %s",
        #            response.status_code,
        #            self.verifier_fid_str,
        #            str(response),
        #        )
        raise UserError(
            f"Status command response: {response.status_code}. Unexpected response from {self.verifier_fid_str} while checking status for {self.agent_fid_str} : {response}"
        )

    def do_cvlist(self) -> Union[requests.Response, Dict[str, Any]]:
        """List all agent statuses in cloudverifier"""

        do_cvstatus = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)

        verifier_id = ""
        if self.verifier_id is not None:
            verifier_id = self.verifier_id

        self.set_full_id_str()

        response = do_cvstatus.get(f"/v{self.api_version}/agents/?verifier={verifier_id}", timeout=self.request_timeout)

        response_json = Tenant._jsonify_response(response, print_response=False, raise_except=True)

        if response.status_code == 503:
            logger.error(
                "Cannot connect to %s. Connection refused.",
                self.verifier_fid_str,
            )
            return response_json
        if response.status_code == 504:
            logger.error("%s timed out.", self.verifier_fid_str)
            return response_json
        if response.status_code == 404:
            logger.info(
                "%s does not have any agents",
                self.verifier_fid_str,
            )
            return response_json

        if response.status_code == 200:
            # Marked for deletion (need to modify the code on CI tests)
            logger.info(
                'From verifier %s port %s retrieved: "%s"\n', self.verifier_ip, self.verifier_port, response_json
            )

            logger.info(
                "Agent list from %s retrieved: \n%s", self.verifier_fid_str, json.dumps(response_json["results"])
            )

            return response

        raise UserError(
            f"Status command response: {response.status_code}. Unexpected response from {self.verifier_fid_str} while providing agent list : {response}"
        )

    def do_cvbulkinfo(self) -> Dict[str, Any]:
        """Perform operational state look up for all agents"""

        do_cvstatus = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)

        verifier_id = ""
        if self.verifier_id is not None:
            verifier_id = self.verifier_id

        self.set_full_id_str()

        response = do_cvstatus.get(
            f"/v{self.api_version}/agents/?bulk={True}&verifier={verifier_id}", timeout=self.request_timeout
        )

        response_json = Tenant._jsonify_response(response, print_response=False)

        if response.status_code == 200:
            for agent in response_json["results"].keys():
                response_json["results"][agent]["operational_state"] = states.state_to_str(
                    response_json["results"][agent]["operational_state"]
                )
            logger.info("Bulk Agent Info:\n%s", json.dumps(response_json["results"]))

            return response_json

        raise UserError(
            f"Status command response: {response.status_code}. Unexpected response from {self.verifier_fid_str} while providing bulk status for all agents : {response}"
        )

    def do_cvdelete(self, verifier_check: bool = True) -> None:
        """Delete agent from Verifier."""

        self.set_full_id_str()

        if verifier_check:
            cvresponse = self.do_cvstatus(not_found_fail=False)

            if not isinstance(cvresponse, dict):
                keylime_logging.log_http_response(logger, logging.ERROR, cvresponse)
                sys.exit()

            if cvresponse["code"] == 404:
                logger.info(
                    "The %s is deleted from %s",
                    self.agent_fid_str,
                    self.verifier_fid_str,
                )
                return

            if self.agent_uuid in cvresponse["results"]:
                self.verifier_ip = cvresponse["results"][self.agent_uuid]["verifier_ip"]
                self.verifier_port = cvresponse["results"][self.agent_uuid]["verifier_port"]
                self.verifier_id = cvresponse["results"][self.agent_uuid]["verifier_id"]
                self.agent_ip = cvresponse["results"][self.agent_uuid]["ip"]
                self.agent_port = cvresponse["results"][self.agent_uuid]["port"]
                self.set_full_id_str()

        do_cvdelete = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = do_cvdelete.delete(f"/v{self.api_version}/agents/{self.agent_uuid}", timeout=self.request_timeout)

        response_json = Tenant._jsonify_response(response, print_response=False, raise_except=True)

        if response_json["code"] == 503:
            # EVALUATE DELETION
            #            logger.error(
            #                "Cannot connect to %s to delete %s. Connection refused.",
            #                self.verifier_fid_str,
            #                self.agent_fid_str,
            #            )
            #            keylime_logging.log_http_response(logger, logging.ERROR, response_json)
            raise UserError(
                f"Cannot connect to {self.verifier_fid_str} to delete {self.agent_fid_str}. Connection refused."
            )

        if response_json["code"] == 504:
            # EVALUATE DELETION
            #            logger.error("%s timed out while deleting %s.", self.verifier_fid_str, self.agent_fid_str)
            #            keylime_logging.log_http_response(logger, logging.ERROR, response_json)
            raise UserError(f"{self.verifier_fid_str} timed out while deleting {self.agent_fid_str}.")

        if response_json["code"] == 202:
            numtries = 0
            deleted = False

            while not deleted:
                reponse_json = self.do_cvstatus(not_found_fail=False)
                if reponse_json["code"] != 404:
                    numtries += 1
                    if numtries >= self.maxr:
                        # EVALUATE DELETION
                        #                        logger.error(
                        #                            "%s was not deleted from %s after %d tries",
                        #                            self.agent_fid_str,
                        #                            self.verifier_fid_str,
                        #                            numtries,
                        #                        )
                        raise UserError(
                            f"{self.agent_fid_str,} was not deleted from {self.verifier_fid_str} after {numtries} tries"
                        )

                    next_retry = retry.retry_time(self.exponential_backoff, self.retry_interval, numtries, logger)
                    logger.info(
                        "%s still not deleted from %s at try %d/%d, trying again in %s seconds...",
                        self.agent_fid_str,
                        self.verifier_fid_str,
                        numtries,
                        self.maxr,
                        next_retry,
                    )
                    time.sleep(next_retry)
                else:
                    deleted = True

            if deleted:
                logger.info(
                    "%s was deleted from %s after %d tries",
                    self.agent_fid_str,
                    self.verifier_fid_str,
                    numtries,
                )
                # Marked for deletion (need to modify the code on CI tests)
                logger.info("Agent %s deleted from the CV", self.agent_uuid)

    def do_regstatus(self) -> Dict[str, Any]:
        if not self.registrar_ip or not self.registrar_port:
            raise UserError("registrar_ip and registrar_port have both to be set in the configuration")

        self.set_full_id_str()

        agent_info = registrar_client.getData(self.registrar_ip, self.registrar_port, self.agent_uuid, self.tls_context)

        if not agent_info:
            logger.info(
                # Marked for deletion (the message should be replaced by the 3 following commented out lines)
                "Agent %s does not exist on the registrar. Please register the agent with the registrar.",
                self.agent_uuid,
                # "%s does not exist on %s. Check the agent logs to for error messages while attempting to get registered.",
                # self.agent_fid_str,
                # self.registrar_fid_str,
            )
            response = {
                "code": 404,
                # Marked for deletion. The "status" field should be replaced by "status": f"{self.agent_fid_str} does not exist on {self.registrar_fid_str}.",
                "status": f"Agent {self.agent_uuid} does not exist on "
                f"registrar {self.registrar_ip} port {self.registrar_port}.",
                "results": {},
            }
            # should be DEBUG # EVALUATE DELETION
            logger.info(json.dumps(response))
            raise UserError(
                f"{self.agent_fid_str} does not exist on {self.registrar_fid_str}. Check the agent logs to for error messages while attempting to get registered."
            )

        # Marked for deletion (the "status" line need to be changed to f"registrar {self.registrar_ip} port {self.registrar_port}.")
        response = {
            "code": 200,
            "status": f"Agent {self.agent_uuid} exists on "
            f"registrar {self.registrar_ip} port {self.registrar_port}.",
            "results": {},
        }

        assert isinstance(response["results"], dict)
        response["results"][self.agent_uuid] = agent_info
        response["results"][self.agent_uuid]["operational_state"] = states.state_to_str(states.REGISTERED)

        logger.info("Status from %s: %s", self.registrar_fid_str, response["status"])
        # should be DEBUG
        logger.info(json.dumps(response))
        logger.info("Agent Info from %s:\n%s", self.registrar_fid_str, json.dumps(response["results"]))

        return response

    def do_reglist(self) -> Optional[Dict[str, Any]]:
        """List agents from Registrar"""
        if not self.registrar_ip or not self.registrar_port:
            raise UserError("registrar_ip and registrar_port have both to be set in the configuration")

        self.set_full_id_str()

        response = registrar_client.doRegistrarList(
            self.registrar_ip, self.registrar_port, tls_context=self.tls_context
        )

        # Marked for deletion (need to modify the code on CI tests)
        logger.info(
            "From registrar %s port %s retrieved %s\n", self.registrar_ip, self.registrar_port, json.dumps(response)
        )
        assert isinstance(response, dict)
        assert isinstance(response["results"], dict)
        logger.info("Agent list from %s retrieved: \n%s", self.registrar_fid_str, json.dumps(response["results"]))

        return response

    def do_regdelete(self) -> Dict[str, Any]:
        """Delete agent from Registrar"""
        if not self.registrar_ip or not self.registrar_port:
            raise UserError("registrar_ip and registrar_port have both to be set in the configuration")

        response = registrar_client.doRegistrarDelete(
            self.registrar_ip, self.registrar_port, self.agent_uuid, tls_context=self.tls_context
        )

        return response

    def do_status(self) -> Dict[str, Any]:
        """Perform operational state look up for agent"""

        regresponse = self.do_regstatus()

        if regresponse["code"] == 404:
            return regresponse

        cvresponse = self.do_cvstatus()

        if not isinstance(cvresponse, dict):
            logger.error(
                "Unexpected response from %s: %s",
                self.verifier_fid_str,
                str(cvresponse),
            )
            return cvresponse

        if regresponse["code"] == 200 and cvresponse["code"] == 200:
            return cvresponse
        if regresponse["code"] == 200 and cvresponse["code"] != 200:
            return regresponse

        logger.error(
            "Unknown inconsistent state between %s and %s occured. Got %s from the former and %s from the latter",
            self.registrar_fid_str,
            self.verifier_fid_str,
            str(regresponse),
            str(cvresponse),
        )

        return {"registrar": regresponse, "verifier": cvresponse}

    def do_cvreactivate(self, verifier_check: bool = True) -> Dict[str, Any]:
        """Reactive Agent."""
        if verifier_check:
            cvresponse = self.do_cvstatus()
            self.verifier_ip = cvresponse["results"][self.agent_uuid]["verifier_ip"]
            self.verifier_port = cvresponse["results"][self.agent_uuid]["verifier_port"]
            self.verifier_id = cvresponse["results"][self.agent_uuid]["verifier_id"]

        self.set_full_id_str()

        do_cvreactivate = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = do_cvreactivate.put(
            f"/v{self.api_version}/agents/{self.agent_uuid}/reactivate",
            data=b"",
            timeout=self.request_timeout,
        )

        response_json = Tenant._jsonify_response(response, print_response=False, raise_except=True)

        if response.status_code == 503:
            raise UserError(f"Cannot connect to {self.verifier_fid_str}. Connection refused.")

        if response.status_code == 504:
            raise UserError(f"{self.verifier_fid_str} timed out.")

        if response.status_code == 200:
            # Marked for deletion (need to modify the code on CI tests)
            logger.info("Agent %s re-activated", self.agent_uuid)
            logger.info("%s re-activated", self.agent_fid_str)
            return response_json

        raise UserError(
            f"Reactivate command response: {response.status_code} Unexpected response from {self.verifier_fid_str}."
        )

    def do_cvstop(self) -> None:
        """Stop declared active agent"""
        params = f"/v{self.api_version}/agents/{self.agent_uuid}/stop"
        do_cvstop = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = do_cvstop.put(params, data=b"", timeout=self.request_timeout)

        self.set_full_id_str()

        if response.status_code == 503:
            raise UserError(f"Cannot connect to {self.verifier_fid_str}. Connection refused.")

        if response.status_code == 504:
            # EVALUATE DELETION
            #            logger.error("%s timed out.", self.verifier_fid_str)
            raise UserError(f"{self.verifier_fid_str} timed out.")

        if response.status_code != 200:
            raise UserError(
                f"Stop command response: {response.status_code} Unexpected response from {self.verifier_fid_str}."
            )

        logger.info("%s stopped", self.agent_fid_str)

    def do_quote(self) -> None:
        """Perform TPM quote by GET towards Agent

        Raises:
            UserError: Connection handler
        """
        self.nonce = tpm_util.random_password(20)

        numtries = 0
        response = None
        # Note: We need a specific retry handler (perhaps in common), no point having localised unless we have too.
        while True:
            try:
                params = f"/v{self.supported_version}/quotes/identity?nonce=%s" % (self.nonce)
                cloudagent_base_url = f"{bracketize_ipv6(self.agent_ip)}:{self.agent_port}"

                if self.enable_agent_mtls and self.registrar_data and self.registrar_data["mtls_cert"]:
                    with RequestsClient(
                        cloudagent_base_url,
                        self.enable_agent_mtls,
                        tls_context=self.agent_tls_context,
                    ) as do_quote:
                        response = do_quote.get(params, timeout=self.request_timeout)
                else:
                    logger.warning("Connecting to %s without using mTLS!", self.agent_fid_str)
                    do_quote = RequestsClient(cloudagent_base_url, tls_enabled=False)
                    response = do_quote.get(params, timeout=self.request_timeout)

                response_json = Tenant._jsonify_response(response, print_response=True, raise_except=True)

            except Exception as e:
                if response is None or response.status_code in (503, 504):
                    numtries += 1
                    if numtries >= self.maxr:
                        raise UserError(f"Tenant cannot establish connection to {self.agent_fid_str}") from e

                    next_retry = retry.retry_time(self.exponential_backoff, self.retry_interval, numtries, logger)
                    logger.info(
                        "Tenant connection to %s refused %s/%s times, trying again in %s seconds...",
                        self.agent_fid_str,
                        numtries,
                        self.maxr,
                        next_retry,
                    )
                    time.sleep(next_retry)
                    continue

                raise e
            break

        if response is not None and response.status_code != 200:
            raise UserError(
                f"TPM Quote command response: {response.status_code} Unexpected response from {self.agent_fid_str}."
            )

        if "results" not in response_json:
            raise UserError(
                f"Error: unexpected http response body from {self.agent_fid_str}: {str(response.status_code)}"
            )

        quote = response_json["results"]["quote"]
        logger.debug("Tenant received quote from %s: %s", self.agent_fid_str, quote)

        public_key = response_json["results"]["pubkey"]
        logger.debug("Tenant received public key from %s: %s", self.agent_fid_str, public_key)

        # Ensure hash_alg is in accept_tpm_hash_algs list
        hash_alg = response_json["results"]["hash_alg"]
        logger.debug("Tenant received hash algorithm from %s: %s", self.agent_fid_str, hash_alg)
        if not algorithms.is_accepted(
            hash_alg, config.getlist("tenant", "accept_tpm_hash_algs")
        ) or not algorithms.Hash.is_recognized(hash_alg):
            raise UserError(f"TPM Quote from {self.agent_fid_str} is using an unaccepted hash algorithm: {hash_alg}")

        # Ensure enc_alg is in accept_tpm_encryption_algs list
        enc_alg = response_json["results"]["enc_alg"]
        logger.debug("Tenant received received encryption algorithm from %s: %s", self.agent_fid_str, enc_alg)
        if not algorithms.is_accepted(enc_alg, config.getlist("tenant", "accept_tpm_encryption_algs")):
            raise UserError(
                f"TPM Quote from {self.agent_fid_str} is using an unaccepted encryption algorithm: {enc_alg}"
            )

        # Ensure sign_alg is in accept_tpm_encryption_algs list
        sign_alg = response_json["results"]["sign_alg"]
        logger.debug("Tenant received signing algorithm from %s: %s", self.agent_fid_str, sign_alg)
        if not algorithms.is_accepted(sign_alg, config.getlist("tenant", "accept_tpm_signing_algs")):
            raise UserError(f"TPM Quote from {self.agent_fid_str} is using an unaccepted signing algorithm: {sign_alg}")

        if not self.validate_tpm_quote(public_key, quote, algorithms.Hash(hash_alg)):
            raise UserError(f"TPM Quote from {self.agent_fid_str} is invalid for nonce: {self.nonce}")

        logger.info("Quote from %s validated", self.agent_fid_str)

        if self.U:
            # encrypt U with the public key
            encrypted_U = crypto.rsa_encrypt(crypto.rsa_import_pubkey(public_key), self.U)

            b64_encrypted_u = base64.b64encode(encrypted_U)
            logger.debug("b64_encrypted_u: %s", b64_encrypted_u.decode("utf-8"))
            data = {"encrypted_key": b64_encrypted_u.decode("utf-8"), "auth_tag": self.auth_tag}

            if self.payload is not None:
                data["payload"] = self.payload.decode("utf-8")

            # post encrypted U back to CloudAgent
            params = f"/v{self.supported_version}/keys/ukey"
            cloudagent_base_url = f"{bracketize_ipv6(self.agent_ip)}:{self.agent_port}"

            if self.enable_agent_mtls and self.registrar_data and self.registrar_data["mtls_cert"]:
                with RequestsClient(
                    cloudagent_base_url,
                    self.enable_agent_mtls,
                    tls_context=self.agent_tls_context,
                ) as post_ukey:
                    response = post_ukey.post(params, json=data, timeout=self.request_timeout)
            else:
                logger.warning("Connecting to %s without using mTLS!", self.agent_fid_str)
                post_ukey = RequestsClient(cloudagent_base_url, tls_enabled=False)
                response = post_ukey.post(params, json=data, timeout=self.request_timeout)

            if response.status_code == 503:
                raise UserError(f"Cannot connect to {self.agent_fid_str} to post encrypted U. Connection refused.")

            if response.status_code == 504:
                raise UserError(f"{self.agent_fid_str} timed out while posting encrypted U")

            if response.status_code != 200:
                keylime_logging.log_http_response(logger, logging.ERROR, response_json)
                raise UserError(
                    f"Posting of encrypted U to {self.agent_fid_str} failed with response code {response.status_code} ({response.text})"
                )

    def do_verify(self) -> None:
        """Perform verify using a random generated challenge"""
        challenge = tpm_util.random_password(20)
        numtries = 0

        while True:
            response = None
            try:
                cloudagent_base_url = f"{bracketize_ipv6(self.agent_ip)}:{self.agent_port}"

                if self.registrar_data and self.registrar_data["mtls_cert"]:
                    with RequestsClient(
                        cloudagent_base_url,
                        self.enable_agent_mtls,
                        tls_context=self.agent_tls_context,
                    ) as do_verify:
                        response = do_verify.get(
                            f"/v{self.supported_version}/keys/verify?challenge={challenge}",
                            timeout=self.request_timeout,
                        )
                else:
                    logger.warning("Connecting to %s without using mTLS!", self.agent_fid_str)
                    do_verify = RequestsClient(cloudagent_base_url, tls_enabled=False)
                    response = do_verify.get(
                        f"/v{self.supported_version}/keys/verify?challenge={challenge}", timeout=self.request_timeout
                    )

                response_json = Tenant._jsonify_response(response, print_response=False, raise_except=True)

            except Exception as e:
                if response is not None and response.status_code in (503, 504):
                    numtries += 1
                    if numtries >= self.maxr:
                        self.do_cvstop()
                        raise UserError(f"Cannot establish connection to {self.agent_fid_str}") from e

                    next_retry = retry.retry_time(self.exponential_backoff, self.retry_interval, numtries, logger)
                    logger.info(
                        "Connection to %s refused %s/%s times, trying again in %s seconds...",
                        self.agent_fid_str,
                        numtries,
                        self.maxr,
                        next_retry,
                    )
                    time.sleep(next_retry)
                    continue
                self.do_cvstop()
                raise e

            mac = ""
            ex_mac = crypto.do_hmac(self.K, challenge)

            if response.status_code == 200:
                if "results" not in response_json or "hmac" not in response_json["results"]:
                    self.do_cvstop()
                    raise UserError(
                        f"Error: unexpected http response body from {self.agent_fid_str} : {response.status_code}"
                    )

                mac = response_json["results"]["hmac"]

                if mac == ex_mac:
                    logger.info("Successful key derivation for %s", self.agent_fid_str)

            if mac != ex_mac:
                if response.status_code != 200:
                    keylime_logging.log_http_response(logger, logging.ERROR, response_json)
                numtries += 1
                if numtries >= self.maxr:
                    # EVALUATE DELETION
                    #                    logger.error(
                    #                        "Failed key derivation for %s (expected length %d, received %d",
                    #                        self.agent_fid_str,
                    #                        len(ex_mac),
                    #                        len(mac),
                    #                    )
                    self.do_cvstop()
                    raise UserError(
                        f"Failed key derivation for {self.agent_fid_str} (expected length {len(ex_mac)}, received {len(mac)})"
                    )

                next_retry = retry.retry_time(self.exponential_backoff, self.retry_interval, numtries, logger)
                logger.info(
                    "Key derivation not yet complete for %s at try %d/%d (expected length %d, received length %d) trying again in %d seconds... (Ctrl-C to stop)",
                    self.agent_fid_str,
                    numtries,
                    self.maxr,
                    len(ex_mac),
                    len(mac),
                    next_retry,
                )
                time.sleep(next_retry)
                continue
            break

    def __convert_runtime_policy(self, args: Dict[str, str]) -> str:
        if args.get("runtime_policy_name") is None:
            if args.get("allowlist_name") is not None:
                logger.warning(
                    "WARNING: --allowlist-name is deprecated. Use --runtime-policy-name instead."
                    "Keylime has implemented support for a unified policy format, and will no longer accept separate allow/exclude lists in the near future."
                    "A conversion script to upgrade legacy allow/exclude lists to the new format is available under keylime/cmd/convert_runtime_policy.py."
                )
            else:
                raise UserError("runtime_policy_name is required to add a runtime policy")

        (
            self.tpm_policy,
            self.mb_policy,
            self.mb_policy_name,
            self.runtime_policy_name,
            self.ima_sign_verification_keys,
            self.runtime_policy,
            self.runtime_policy_key,
        ) = policies.process_policy(cast(policies.ArgsType, args))

        data = {
            "tpm_policy": json.dumps(self.tpm_policy),
            "runtime_policy": self.runtime_policy,
            "runtime_policy_key": self.runtime_policy_key,
        }
        return json.dumps(data)

    def do_add_runtime_policy(self, args: Dict[str, str]) -> None:
        body = self.__convert_runtime_policy(args)

        cv_client = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = cv_client.post(
            f"/v{self.api_version}/allowlists/{self.runtime_policy_name}", data=body, timeout=self.request_timeout
        )
        response_json = Tenant._jsonify_response(response)

        if response.status_code >= 400:
            raise UserError(response_json)

    def do_update_runtime_policy(self, args: Dict[str, str]) -> None:
        body = self.__convert_runtime_policy(args)

        cv_client = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = cv_client.put(
            f"/v{self.api_version}/allowlists/{self.runtime_policy_name}", data=body, timeout=self.request_timeout
        )
        response_json = Tenant._jsonify_response(response)

        if response.status_code >= 400:
            raise UserError(response_json)

    def do_delete_runtime_policy(self, name: Optional[str]) -> None:
        if not name:
            raise UserError("--allowlist_name or --runtime_policy_name is required to delete a runtime policy")
        cv_client = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = cv_client.delete(f"/v{self.api_version}/allowlists/{name}", timeout=self.request_timeout)
        response_json = Tenant._jsonify_response(response)

        if response.status_code >= 400:
            raise UserError(response_json)

    def do_show_runtime_policy(self, name: Optional[str]) -> None:  # pylint: disable=unused-argument
        if not name:
            raise UserError("--allowlist_name or --runtime_policy_name is required to show a runtime policy")
        cv_client = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = cv_client.get(f"/v{self.api_version}/allowlists/{name}", timeout=self.request_timeout)
        print(f"Show allowlist command response: {response.status_code}.")
        response_json = Tenant._jsonify_response(response)

        if response.status_code >= 400:
            raise UserError(response_json)

    def do_list_runtime_policy(self) -> None:
        cv_client = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = cv_client.get(f"/v{self.api_version}/allowlists/", timeout=self.request_timeout)
        print(f"list command response: {response.status_code}.")
        response_json = Tenant._jsonify_response(response)

        if response.status_code >= 400:
            raise UserError(response_json)

    def __convert_mb_policy(self, args: Dict[str, str]) -> str:
        if args.get("mb_policy_name") is None:
            raise UserError("mb_policy_name is required to add measure boot policy")

        (
            self.tpm_policy,
            self.mb_policy,
            self.mb_policy_name,
            self.runtime_policy_name,
            self.ima_sign_verification_keys,
            self.runtime_policy,
            self.runtime_policy_key,
        ) = policies.process_policy(cast(policies.ArgsType, args))

        data = {
            "mb_policy": self.mb_policy,
        }
        return json.dumps(data)

    def do_add_mb_policy(self, args: Dict[str, str]) -> None:
        body = self.__convert_mb_policy(args)

        cv_client = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = cv_client.post(
            f"/v{self.api_version}/mbpolicies/{self.mb_policy_name}", data=body, timeout=self.request_timeout
        )
        response_json = Tenant._jsonify_response(response)

        if response.status_code >= 400:
            raise UserError(response_json)

    def do_update_mb_policy(self, args: Dict[str, str]) -> None:
        body = self.__convert_mb_policy(args)

        cv_client = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = cv_client.put(
            f"/v{self.api_version}/mbpolicies/{self.mb_policy_name}", data=body, timeout=self.request_timeout
        )
        response_json = Tenant._jsonify_response(response)

        if response.status_code >= 400:
            raise UserError(response_json)

    def do_delete_mb_policy(self, name: Optional[str]) -> None:
        if not name:
            raise UserError("--mb_policy_name is required to delete a runtime policy")
        cv_client = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = cv_client.delete(f"/v{self.api_version}/mbpolicies/{name}", timeout=self.request_timeout)
        response_json = Tenant._jsonify_response(response)

        if response.status_code >= 400:
            raise UserError(response_json)

    def do_show_mb_policy(self, name: Optional[str]) -> None:  # pylint: disable=unused-argument
        if not name:
            raise UserError("--mb_policy_name is required to show a runtime policy")
        cv_client = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = cv_client.get(f"/v{self.api_version}/mbpolicies/{name}", timeout=self.request_timeout)
        print(f"showmbpolicy command response: {response.status_code}.")
        response_json = Tenant._jsonify_response(response)

        if response.status_code >= 400:
            raise UserError(response_json)

    def do_list_mb_policy(self) -> None:  # pylint: disable=unused-argument
        cv_client = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = cv_client.get(f"/v{self.api_version}/mbpolicies/", timeout=self.request_timeout)
        print(f"listmbpolicy command response: {response.status_code}.")
        response_json = Tenant._jsonify_response(response)

        if response.status_code >= 400:
            raise UserError(response_json)

    @staticmethod
    def _jsonify_response(
        response: requests.Response, print_response: bool = True, raise_except: bool = False
    ) -> Dict[str, Any]:
        json_response: Dict[str, Any]
        try:
            json_response = response.json()
        except ValueError as e:
            if raise_except:
                raise ValueError("Unable to convert response to JSON format") from e
            json_response = {}

        if print_response:
            print(json_response)
        return json_response


def write_to_namedtempfile(data: bytes, delete_tmp_files: bool) -> str:
    temp = tempfile.NamedTemporaryFile(  # pylint: disable=consider-using-with
        prefix="keylime-", delete=delete_tmp_files
    )
    temp.write(data)
    temp.flush()
    return temp.name


def main() -> None:
    """[summary]

    Keyword Arguments:
        argv {[type]} -- [description] (default: {sys.argv})

    Raises:
        UserError: [description]
        UserError: [description]
        UserError: [description]
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--command",
        action="store",
        dest="command",
        default="add",
        help="valid commands are add,delete,update,"
        "regstatus,cvstatus,status,reglist,cvlist,reactivate,"
        "regdelete,bulkinfo,addruntimepolicy,showruntimepolicy,"
        "deleteruntimepolicy,updateruntimepolicy,listruntimepolicy,"
        "addmbpolicy,showmbpolicy,deletembpolicy,updatembpolicy,"
        "listmbpolicy. defaults to add",
    )
    parser.add_argument(
        "-t", "--targethost", action="store", dest="agent_ip", help="the IP address of the host to provision"
    )
    parser.add_argument(
        "-tp", "--targetport", action="store", dest="agent_port", help="the Port of the host to provision"
    )
    parser.add_argument(
        "-r",
        "--registrarhost",
        action="store",
        dest="registrar_ip",
        help="the IP address of the registrar where to retrieve the agents data from.",
    )
    parser.add_argument(
        "-rp", "--registrarport", action="store", dest="registrar_port", help="the port of the registrar."
    )
    parser.add_argument(
        "--cv_targethost",
        action="store",
        default=None,
        dest="cv_agent_ip",
        help="the IP address of the host to provision that the verifier will use (optional).  Use only if different than argument to option -t/--targethost",
    )
    parser.add_argument("-v", "--cv", action="store", dest="verifier_ip", help="the IP address of the cloud verifier")
    parser.add_argument("-vp", "--cvport", action="store", dest="verifier_port", help="the port of the cloud verifier")
    parser.add_argument(
        "-vi", "--cvid", action="store", dest="verifier_id", help="the unique identifier of a cloud verifier"
    )
    parser.add_argument(
        "-nvc",
        "--no-verifier-check",
        action="store_false",
        dest="verifier_check",
        default=True,
        help="Disable the check to confirm if the agent is being processed by the specified verifier. Use only with -c/--command delete or reactivate",
    )
    parser.add_argument("-u", "--uuid", action="store", dest="agent_uuid", help="UUID for the agent to provision")
    parser.add_argument(
        "-f", "--file", action="store", default=None, help="Deliver the specified plaintext to the provisioned agent"
    )
    parser.add_argument(
        "--cert",
        action="store",
        dest="ca_dir",
        default=None,
        help='Create and deliver a certificate using a CA created by ca-util. Pass in the CA directory or use "default" to use the standard dir',
    )
    parser.add_argument(
        "-k", "--key", action="store", dest="keyfile", help="an intermedia key file produced by user_data_encrypt"
    )
    parser.add_argument(
        "-p",
        "--payload",
        action="store",
        default=None,
        help="Specify the encrypted payload to deliver with encrypted keys specified by -k",
    )
    parser.add_argument(
        "--include",
        action="store",
        dest="incl_dir",
        default=None,
        help="Include additional files in provided directory in certificate zip file.  Must be specified with --cert",
    )
    parser.add_argument(
        "--allowlist",
        action="store",
        dest="allowlist",
        default=None,
        help="DEPRECATED: Migrate to runtime policies for continued functionality. Specify the file path of an allowlist",
    )
    parser.add_argument(
        "--runtime-policy",
        action="store",
        dest="runtime_policy",
        default=None,
        help="Specify the file path of a runtime policy",
    )
    parser.add_argument(
        "--signature-verification-key",
        "--sign_verification_key",
        action="append",
        dest="ima_sign_verification_keys",
        default=[],
        help="DEPRECATED: Provide verification keys as part of a runtime policy for continued functionality. Specify an IMA file signature verification key",
    )
    parser.add_argument(
        "--signature-verification-key-sig",
        action="append",
        dest="ima_sign_verification_key_sigs",
        default=[],
        help="DEPRECATED: Provide verification keys as part of a runtime policy for continued functionality. Specify the GPG signature file for an IMA file signature verification key; pair this option with --signature-verification-key",
    )
    parser.add_argument(
        "--signature-verification-key-sig-key",
        action="append",
        dest="ima_sign_verification_key_sig_keys",
        default=[],
        help="DEPRECATED: Provide verification keys as part of a runtime policy for continued functionality. Specify the GPG public key file use to validate the --signature-verification-key-sig; pair this option with --signature-verification-key",
    )
    parser.add_argument(
        "--signature-verification-key-url",
        action="append",
        dest="ima_sign_verification_key_urls",
        default=[],
        help="DEPRECATED: Provide verification keys as part of a runtime policy for continued functionality. Specify the URL for a remote IMA file signature verification key",
    )
    parser.add_argument(
        "--signature-verification-key-sig-url",
        action="append",
        dest="ima_sign_verification_key_sig_urls",
        default=[],
        help="DEPRECATED: Provide verification keys as part of a runtime policy for continued functionality. Specify the URL for the remote GPG signature of a remote IMA file signature verification key; pair this option with --signature-verification-key-url",
    )
    parser.add_argument(
        "--signature-verification-key-sig-url-key",
        action="append",
        dest="ima_sign_verification_key_sig_url_keys",
        default=[],
        help="DEPRECATED: Provide verification keys as part of a runtime policy for continued functionality. Specify the GPG public key file used to validate the --signature-verification-key-sig-url; pair this option with --signature-verification-key-url",
    )
    parser.add_argument(
        "--mb_refstate",
        action="store",
        dest="mb_policy",
        default=None,
        help="Specify the location of a measure boot reference state (intended state). This option could be deprecated. Use --mb-policy instead.",
    )
    parser.add_argument(
        "--allowlist-url",
        action="store",
        dest="allowlist_url",
        default=None,
        help="DEPRECATED: Migrate to runtime policies for continued functionality. Specify the URL of a remote allowlist",
    )
    parser.add_argument(
        "--exclude",
        action="store",
        dest="ima_exclude",
        default=None,
        help="DEPRECATED: Migrate to runtime policies for continued functionality. Specify the location of an IMA exclude list",
    )
    parser.add_argument(
        "--runtime-policy-checksum",
        action="store",
        dest="runtime_policy_checksum",
        default=None,
        help="Specify the SHA-256 checksum of a runtime policy",
    )
    parser.add_argument(
        "--runtime-policy-sig-key",
        action="store",
        dest="runtime_policy_sig_key",
        default=None,
        help="Specify the public key file used to validate the --runtime-policy-sig or --runtime-policy-sig-url",
    )
    parser.add_argument(
        "--runtime-policy-url",
        action="store",
        dest="runtime_policy_url",
        default=None,
        help="Specify the URL of a remote runtime policy",
    )
    parser.add_argument(
        "--tpm_policy",
        action="store",
        dest="tpm_policy",
        default=None,
        help='Specify a TPM policy in JSON format. e.g., {"15":"0000000000000000000000000000000000000000"}',
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        default=False,
        help="Block on cryptographically checked key derivation confirmation from the agent once it has been provisioned",
    )
    parser.add_argument(
        "--allowlist-name",
        help="DEPRECATED: Migrate to runtime policies for continued functionality. The name of allowlist to operate with",
    )
    parser.add_argument("--runtime-policy-name", help="The name of the runtime policy to operate with")
    parser.add_argument(
        "--mb-policy",
        action="store",
        dest="mb_policy",
        default=None,
        help="The measure boot policy to operate with",
    )
    parser.add_argument(
        "--mb-policy-name",
        action="store",
        dest="mb_policy_name",
        default=None,
        help="The name of the measure boot policy to operate with",
    )
    parser.add_argument(
        "--supported-version",
        default=None,
        action="store",
        dest="supported_version",
        help="API version that is supported by the agent. Detected automatically by default",
    )

    args = parser.parse_args()

    argerr, argerrmsg = options.get_opts_error(args)
    if argerr:
        parser.error(argerrmsg)

    config.check_version("tenant", logger=logger)

    mytenant = Tenant()

    if args.agent_uuid is not None:
        mytenant.agent_uuid = args.agent_uuid
        if not validators.valid_agent_id(mytenant.agent_uuid):
            raise UserError("The agent ID set via agent uuid parameter use invalid characters")
    else:
        logger.warning("Using default UUID d432fbb3-d2f1-4a97-9ef7-75bd81c00000")
        mytenant.agent_uuid = "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"

    if args.verifier_id is not None:
        mytenant.verifier_id = args.verifier_id
    if args.verifier_ip is not None:
        mytenant.verifier_ip = args.verifier_ip
    if args.verifier_port is not None:
        mytenant.verifier_port = args.verifier_port

    if args.registrar_ip is not None:
        mytenant.registrar_ip = args.registrar_ip
    if args.registrar_port is not None:
        mytenant.registrar_port = args.registrar_port

    # we only need to fetch remote files if we are adding or updating
    if args.command in ["add", "update", "addallowlist", "addruntimepolicy", "updateruntimepolicy"]:
        delete_tmp_files = logger.level > logging.DEBUG  # delete tmp files unless in DEBUG mode

        if args.runtime_policy_url:
            logger.info("Downloading IMA policy from %s", args.runtime_policy_url)
            response = requests.get(args.runtime_policy_url, timeout=mytenant.request_timeout, allow_redirects=False)
            if response.status_code == 200:
                args.runtime_policy = write_to_namedtempfile(response.content, delete_tmp_files)
                logger.debug("IMA policy temporarily saved in %s", args.runtime_policy)
            else:
                raise Exception(
                    f"Downloading IMA policy ({args.runtime_policy_url}) failed with status code {response.status_code}!"
                )

        if args.allowlist_url:
            logger.info("Downloading Allowlist from %s", args.allowlist_url)
            response = requests.get(args.allowlist_url, timeout=mytenant.request_timeout, allow_redirects=False)
            if response.status_code == 200:
                args.allowlist = write_to_namedtempfile(response.content, delete_tmp_files)
                logger.debug("Allowlist temporarily saved in %s", args.allowlist)
            else:
                raise Exception(
                    f"Downloading allowlist ({args.allowlist_url}) failed with status code {response.status_code}!"
                )

        # verify all the local keys for which we have a signature file and a key to verify
        for i, key_file in enumerate(args.ima_sign_verification_keys):
            if len(args.ima_sign_verification_key_sigs) <= i:
                break
            keysig_file = args.ima_sign_verification_key_sigs[i]
            if len(args.ima_sign_verification_key_sig_keys) == 0:
                raise UserError(f"A gpg key is missing for key signature file '{keysig_file}'")

            gpg_key_file = args.ima_sign_verification_key_sig_keys[i]
            signing.verify_signature_from_file(gpg_key_file, key_file, keysig_file, "IMA file signing key")

            logger.info("Signature verification on %s was successful", key_file)

        # verify all the remote keys for which we have a signature URL and key to to verify
        # Append the downloaded key files to args.ima_sign_verification_keys
        for i, key_url in enumerate(args.ima_sign_verification_key_urls):
            logger.info("Downloading key from %s", key_url)
            response = requests.get(key_url, timeout=mytenant.request_timeout, allow_redirects=False)
            if response.status_code == 200:
                key_file = write_to_namedtempfile(response.content, delete_tmp_files)
                args.ima_sign_verification_keys.append(key_file)
                logger.debug("Key temporarily saved in %s", key_file)
            else:
                raise Exception(f"Downloading key ({key_url}) failed with status code {response.status_code}!")

            if len(args.ima_sign_verification_key_sig_urls) <= i:
                continue

            keysig_url = args.ima_sign_verification_key_sig_urls[i]

            if len(args.ima_sign_verification_key_sig_url_keys) == 0:
                raise UserError(f"A gpg key is missing for key signature URL '{keysig_url}'")

            logger.info("Downloading key signature from %s", keysig_url)
            response = requests.get(keysig_url, timeout=mytenant.request_timeout, allow_redirects=False)
            if response.status_code == 200:
                keysig_file = write_to_namedtempfile(response.content, delete_tmp_files)
                logger.debug("Key signature temporarily saved in %s", keysig_file)
            else:
                raise Exception(
                    f"Downloading key signature ({key_url}) failed with status code {response.status_code}!"
                )

            gpg_key_file = args.ima_sign_verification_key_sig_url_keys[i]
            signing.verify_signature_from_file(gpg_key_file, key_file, keysig_file, "IMA file signing key")
            logger.info("Signature verification on %s was successful", key_url)

    if args.command == "add":
        mytenant.init_add(vars(args))
        mytenant.preloop()
        mytenant.do_quote()
        mytenant.do_cvadd()
        if args.verify:
            mytenant.do_verify()
    elif args.command == "update":
        mytenant.init_add(vars(args))
        mytenant.do_cvdelete(args.verifier_check)
        mytenant.preloop()
        mytenant.do_quote()
        mytenant.do_cvadd()
        if args.verify:
            mytenant.do_verify()
    elif args.command == "delete":
        mytenant.do_cvdelete(args.verifier_check)
    elif args.command == "status":
        mytenant.do_status()
    elif args.command == "cvstatus":
        mytenant.do_cvstatus()
    elif args.command == "bulkinfo":
        mytenant.do_cvbulkinfo()
    elif args.command == "cvlist":
        mytenant.do_cvlist()
    elif args.command == "reactivate":
        mytenant.do_cvreactivate(args.verifier_check)
    elif args.command == "regstatus":
        mytenant.do_regstatus()
    elif args.command == "reglist":
        mytenant.do_reglist()
    elif args.command == "regdelete":
        mytenant.do_regdelete()
    elif args.command == "addallowlist":
        logger.warning(
            "WARNING: -c addallowlist is deprecated. Use -c addruntimepolicy instead."
            "Keylime has implemented support for a unified policy format, and will no longer accept separate allow/exclude lists in the near future."
            "A conversion script to upgrade legacy allow/exclude lists to the new format is available under keylime/cmd/convert_runtime_policy.py."
        )
        mytenant.do_add_runtime_policy(vars(args))
    elif args.command == "showallowlist":
        logger.warning(
            "WARNING: -c showallowlist is deprecated. Use -c showruntimepolicy instead."
            "Keylime has implemented support for a unified policy format, and will no longer accept separate allow/exclude lists in the near future."
            "A conversion script to upgrade legacy allow/exclude lists to the new format is available under keylime/cmd/convert_runtime_policy.py."
        )
        if args.allowlist_name:
            mytenant.do_show_runtime_policy(args.allowlist_name)
        elif args.runtime_policy_name:
            mytenant.do_show_runtime_policy(args.runtime_policy_name)
        else:
            mytenant.do_show_runtime_policy(None)
    elif args.command == "deleteallowlist":
        logger.warning(
            "WARNING: -c deleteallowlist is deprecated. Use -c deleteruntimepolicy instead."
            "Keylime has implemented support for a unified policy format, and will no longer accept separate allow/exclude lists in the near future."
            "A conversion script to upgrade legacy allow/exclude lists to the new format is available under keylime/cmd/convert_runtime_policy.py."
        )
        if args.allowlist_name:
            mytenant.do_delete_runtime_policy(args.allowlist_name)
        elif args.runtime_policy_name:
            mytenant.do_delete_runtime_policy(args.runtime_policy_name)
        else:
            mytenant.do_delete_runtime_policy(None)
    elif args.command == "addruntimepolicy":
        mytenant.do_add_runtime_policy(vars(args))
    elif args.command == "showruntimepolicy":
        if args.allowlist_name:
            mytenant.do_show_runtime_policy(args.allowlist_name)
        elif args.runtime_policy_name:
            mytenant.do_show_runtime_policy(args.runtime_policy_name)
        else:
            mytenant.do_show_runtime_policy(None)
    elif args.command == "deleteruntimepolicy":
        if args.allowlist_name:
            mytenant.do_delete_runtime_policy(args.allowlist_name)
        elif args.runtime_policy_name:
            mytenant.do_delete_runtime_policy(args.runtime_policy_name)
        else:
            mytenant.do_delete_runtime_policy(None)
    elif args.command == "updateruntimepolicy":
        mytenant.do_update_runtime_policy(vars(args))
    elif args.command == "listruntimepolicy":
        mytenant.do_list_runtime_policy()
    elif args.command == "addmbpolicy":
        mytenant.do_add_mb_policy(vars(args))
    elif args.command == "showmbpolicy":
        mytenant.do_show_mb_policy(args.mb_policy_name)
    elif args.command == "deletembpolicy":
        mytenant.do_delete_mb_policy(args.mb_policy_name)
    elif args.command == "updatembpolicy":
        mytenant.do_update_mb_policy(vars(args))
    elif args.command == "listmbpolicy":
        mytenant.do_list_mb_policy()
    else:
        raise UserError(f"Invalid command specified: {args.command}")
