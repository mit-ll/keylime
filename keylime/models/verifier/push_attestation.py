import copy
import json
from datetime import timedelta
from typing import Any, Optional

from keylime import config, keylime_logging
from keylime.agentstates import AgentAttestState, TPMState
from keylime.common import algorithms
from keylime.failure import Component, Failure
from keylime.ima import file_signatures, ima
from keylime.models.base import *
from keylime.tpm.tpm_main import Tpm

logger = keylime_logging.init_logging("verifier")

GLOBAL_TPM_INSTANCE: Optional[Tpm] = None


def get_tpm_instance() -> Tpm:
    global GLOBAL_TPM_INSTANCE
    if GLOBAL_TPM_INSTANCE is None:
        GLOBAL_TPM_INSTANCE = Tpm()
    return GLOBAL_TPM_INSTANCE


class PushAttestation(PersistableModel):
    """An instance of the PushAttestation class is used to manage state over the lifetime of an attestation received
    from an agent as a single push attestation is performed over multiple HTTP requests. When the push attestation
    protocol starts, the verifier receives a list of capabilities of the agent system and generates a nonce in response.
    The agent prepares evidence based on the nonce and the attestation method chosen by the verifier. This is sent in a
    second HTTP request as shown in the below diagram::

                      Agent                                       Verifier
                      -----                                       --------    PushAttestation
                        │                                             │            object
                        │    1. Attestation parameter negotiation     │      ┌────────────────┐
                        │ <-----------------------------------------> │ <--> │ ** Created **  │
                        │                                             │      │       │        │
                        │         2. Submission of evidence           │      │       ↓        │
                        │ <-----------------------------------------> │ <--> │ ** Updated **  │
                        │                                             │      │       │        │
                                                                             │       ↓        │
                                                                             │ ** Verified ** │
                                                                             └────────────────┘

    PushAttestation records are persisted to the database to ensure continuity across worker processes and across
    restarts of the verifier. These are cleaned up automatically to prevent exponential expansion of the stored data but
    a minimal history of the last few attestations are kept for audit and reporting purposes.

    Class Usage
    -----------

    When it is time to report the next scheduled attestation, the agent makes a POST request over HTTPS to the verifier.
    The request body consists of a list of TPM algorithms supported by the agent and these are used to create a new
    PushAttestation object by invoking the ``PushAttestation.create(agent_id, data)`` class method.

    The PushAttestation class determines the following values which are returned to the agent in the HTTP response:

        * A new randomly-generated nonce for the TPM to include in the quote
        * A mask indicating which PCRs should be included in the quote
        * An offset value indicating which IMA log entries should be sent by the agent
        * TPM algorithms to be used for the quote
        * The timestamp at which the nonce was generated
        * The time at which the nonce will expire calculated from the period configured by the user

    These values are persisted to the database by calling ``attestation.commit_changes()``.

    The agent gathers the evidence (UEFI log, IMA entries and quote) required for the verification using the values
    received from the verifier (such as the chosen TPM algorithms) and reports the prepared evidence by submitting a
    PUT request to the verifier. The verifier retrieves the attestation record from the database by calling
    ``PushAttestation.get_last(agent_id)`` and updates it with the received evidence by calling
    ``attestation.update(data)``.

    The verifier will reply with the number of seconds the agent should wait before performing the next attestation
    (obtained from ``attestation.next_attestation_expected_after``) and an indication of whether the request from
    the agent appeared well formed.

    Actual processing and verification of the measurements against policy is performed after the response is returned by
    calling ``attestation.verify_evidence()``.


    PushAttestation Lifecycle
    ---------------------

    For details on the lifecycle of an PushAttestation object, refer to the documentation for
    ``keylime.web.verifier.push_attestation_controller``.


    Management of IMA Logs
    ----------------------

    The agent reports a list of IMA measurements as part of the evidence for an attestation. The number of IMA
    measurement entries received are retained as `ima_count`. The list of IMA measurements to be reported for the
    verification is determined by the verifier as follows:

        * When an attestation request is initialised, the verfier checks if there was a previous successful attestation.
        * If there is no such attestation, the `starting_ima_offset` value for the newly created attestation is set to
          0  and the agent to expected to send the IMA measurements starting from the first entry.
        * If there was a previous successful attestation, the `starting_ima offset` value for the new attestation is
          calculated based on the `starting_ima_offset` value of the last successful attestation plus its `ima_count` .
          The verifier replies to the attestation initiation request with `starting_ima_offset` value calculated for the
          new attesation and the is agent to expected to send the IMA measurements starting from this value.

    The IMA entries received for the attestation are retained and undergoes under verfication. It is not expected to
    store all attestations in the database therefore only the subset of IMA measurements are persited.


    Management of Measured Boot (UEFI) Logs
    ---------------------------------------

    The agent reports the measured boot log if measured boot attestation if implemented. The measured boot log received
    for each attestation is retained.
    """

    def __init__(self, data: dict[str, Any] | object | None = None, process_associations: bool = True) -> None:
        super().__init__(data, process_associations)
        self._previous_successful_attestation = None
        self._previous_authenticated_attestation = None
        self._previous_attestation = None
        self._attest_state = None

    @classmethod
    def _schema(cls):
        # TODO: Uncomment
        # cls._belongs_to("agent", VerifierAgent, inverse_of="attestations", preload = False)

        # TODO: Check if some fields need to be marked as nullable:

        cls._persist_as("attestations")

        # IDENTIFIERS
        cls._field("agent_id", String(80), primary_key=True)  # pylint: disable=unexpected-keyword-arg
        cls._field("index", Integer, primary_key=True) # pylint: disable=unexpected-keyword-arg
        # Each attestation is uniquely identifiable by a (agent_id, index) tuple; each agent has zero or more
        # attestations numbered incrementally from 0

        # ATTESTATION AND VERIFICATION STATUS
        # Indicates the state of the attestation
        cls._field("status", OneOf("waiting", "received", "verified", "failed"))
        # Indicates the type of failure in case of failed verification
        cls._field("failure_type", OneOf("quote_authentication", "policy_violation"), nullable=True)
        
        # DATA RECEIVED DURING CAPABILITIES NEGOTIATION
        # The UTC datetime at which the attested system was last booted, as reported at attestation creation
        cls._field("boottime", Timestamp)
        # The algorithms which the TPM supports, as reported by the agent
        cls._virtual("supported_enc_algs", List)
        cls._virtual("supported_hash_algs", List)
        cls._virtual("supported_sign_algs", List)

        # VALUES DETERMINED BY THE VERIFIER DURING CAPABILITIES NEGOTIATION
        # The nonce to be used by the agent for an Attestation
        cls._field("nonce", Nonce)
        # The timestamp of when the nonce was created
        cls._field("nonce_created_at", Timestamp)
        # The timestamp of when the nonce is expired
        cls._field("nonce_expires_at", Timestamp)
        # The tpm hashing algorithm to be used by agent
        cls._field("hash_alg", String(10))
        ## The tpm encryption algorithm to be used by agent
        cls._field("enc_alg", String(10))
        # The tpm signing algorithm to be used by agent
        cls._field("sign_alg", String(10))
        # The starting ima offset for an Attestation
        cls._field("starting_ima_offset", Integer)

        # EVIDENCE RECEIVED
        # The tpm quote from the agent
        cls._field("tpm_quote", Text)
        # The ima entries from the agent
        cls._field("ima_entries", Text)
        # The measured boot entries from the agent
        cls._field("mb_entries", Binary)

        # VALUES DETERMINED BY THE VERIFIER BASED ON THE RECEIVED EVIDENCE
        # The count of ima entries quoted in an Attestation
        cls._field("quoted_ima_entries_count", Integer)
        # The timestamp of when the quote was received
        cls._field("evidence_received_at", Timestamp)
        # Note: the "failure_type" field (above) is also updated once verification is completed
        
    @classmethod
    def create(cls, agent_id, agent, data):
        """Create an empty Attestation and prepare the attestation details(nonce, timestamps of nonce, algorithms)

        :param data: list of TPM algorithms supported by the agent

        :returns: Attestation object
        """
        last_attestation = PushAttestation.get_last(agent_id)
        print("last_attestation:", last_attestation)

        if not last_attestation:
            attestation = PushAttestation.create_from_agent(agent, data)
            return attestation

        attestation = PushAttestation.empty()
        attestation.initialise(agent_id)
        attestation.receive_capabilities(data, agent)

        return attestation

    @classmethod
    def create_from_agent(cls, agent, data):
        # Migrating from verifiermain table for pull mode compatibility
        attestation = PushAttestation.empty()
        attestation.initialise(agent.agent_id)
        attestation.receive_capabilities(data, agent)

        if agent.next_ima_ml_entry:
            attestation.starting_ima_offset = agent.next_ima_ml_entry

        return attestation

        # TODO: Implement inverse of this function for when mode is changed from push to pull

    @classmethod
    def get_last(cls, agent_id):
        # Fetch the last attestation entry in the database for a particular agent
        last_attestations = PushAttestation.get(agent_id=agent_id, _sort=desc("index"))
        return last_attestations or None

    @classmethod
    def accept_new_attestations_in(cls, agent_id: str):
        last_attestation = PushAttestation.get_last(agent_id=agent_id)

        if not last_attestation:
            return 0

        # TODO: Handle case in which there is no last attestation but there is a value in the agent table

        current_timestamp = Timestamp.now()

        # Don't accept new attestations until after the configured quote interval has elapsed
        if current_timestamp < last_attestation.next_attestation_expected_after:
            return last_attestation.next_attestation_expected_after - current_timestamp

        # Don't accept new attestations if a previous attestation is still undergoing verification and the configured
        # timeout has not been exceeded
        if last_attestation.status == "received" and current_timestamp <= last_attestation.decision_expected_by:
            return last_attestation.decision_expected_by + current_timestamp

        return 0
    
    def cleanup_stale_priors(self):
        # This is implemented as an instance method, so that it can be called after a new attestation is created and
        # act only on prior attestations and thus not affect the newly created "waiting" attestation

        prev_att = self.previous_attestation

        if not prev_att:
            return

        # Delete previous attestation if evidence was not received
        if prev_att.status == "waiting":
            prev_att.delete()
            return

        # Delete previous attestation if verification did not complete before the verification timeout
        if prev_att.status == "received" and Timestamp.now() > prev_att.decision_expected_by:
            prev_att.delete()
            return
        
        # Currently this method only affects the previous attestation, but in future, its logic could be extended to
        # clear out very old attestations also

    def _set_index(self):
        if self.committed.get("index"):
            return

        last_attestation = PushAttestation.get_last(self.agent_id)
        self.index = PushAttestation.get_last(self.agent_id).index + 1 if last_attestation else 0

    def _set_nonce(self):
        if "nonce" not in self.values:
            self.nonce = Nonce.generate(128)

    def _set_timestamps(self):
        nonce_lifetime = config.getint("verifier", "nonce_lifetime")

        if self.changes.get("nonce"):
            self.nonce_created_at = Timestamp.now()
            self.nonce_expires_at = self.nonce_created_at + timedelta(nonce_lifetime)

        if self.changes.get("tpm_quote"):
            self.evidence_received_at = Timestamp.now()

    def _set_status(self):
        if not self.status:
            self.status = "waiting"

        if self.changes.get("tpm_quote"):
            self.status = "received"

        # status will be set to either "verified" or "failed" after tpm_quote verification is performed by
        # _verify_evidence()

    def _set_ima_offset(self):
        if not self.boottime:
            return 
        
        print("***from set ima offset - previous_attestation",self.previous_attestation)
        print("***from set ima offset - previous_authenticated_attestation",self.previous_authenticated_attestation)

        if not self.previous_authenticated_attestation:
            self.starting_ima_offset = 0
        elif self.boottime > self.previous_authenticated_attestation.boottime:
            self.starting_ima_offset = 0
        elif self.boottime == self.previous_authenticated_attestation.boottime:
            self.starting_ima_offset = self.previous_authenticated_attestation.next_ima_offset
        elif self.boottime < self.previous_authenticated_attestation.boottime:
            self._add_error("boottime", "must be equal to or greater than the boot time of last attestation")

    def _set_algs(self, data, agent):
        # pylint: disable=no-else-break

        supported_hash_algs = data.get("supported_hash_algs")
        supported_enc_algs = data.get("supported_enc_algs")
        supported_sign_algs = data.get("supported_sign_algs")

        # Set hashing algorithm that is first match from the list of hashing supported by the agent tpm
        # and the list of accpeted hashing algorithm
        for hash_alg in agent.accept_tpm_hash_algs:
            if hash_alg in supported_hash_algs:
                self.hash_alg = hash_alg
                break
            else:
                self._add_error(
                    "hash_alg", f"does not contain any accepted hashing algorithm for agent '{agent.agent_id}'"
                )

        # Set encryption algorithm that is first match from the list of encryption supported by the agent tpm
        # and the list of accpeted encryption algorithm
        for enc_alg in agent.accept_tpm_encryption_algs:
            if enc_alg in supported_enc_algs:
                self.enc_alg = enc_alg
                break
            else:
                self._add_error(
                    "enc_alg", f"supported_enc_alg not in list of accpeted_tpm_enc_algs for agent '{agent.agent_id}'"
                )

        # Set signing algorithm that is first match from the list of signing supported by the agent tpm
        # and the list of accpeted signing algorithm
        for sign_alg in agent.accept_tpm_signing_algs:
            if sign_alg in supported_sign_algs:
                self.sign_alg = sign_alg
                break
            else:
                self._add_error(
                    "sign_alg", f"supported_sign_alg not in list of accpeted_tpm_sign_algs for agent '{agent.agent_id}'"
                )

    def _validate_ima_entries(self, starting_ima_offset_received, runtime_policy):
        if runtime_policy and not self.ima_entries:
            self._add_error("ima_entries", "is required by agent policy")

        if self.ima_entries and not runtime_policy:
            self._add_error("ima_entries", "is not expected according to agent policy")

        if starting_ima_offset_received != self.starting_ima_offset:
            self._add_error("starting_ima_offset", "is not the expected starting ima offset for this attestation")

        if starting_ima_offset_received == 0:
            ima_entries = self.ima_entries or ""
            first_entry = ima_entries.split("\n")[0]
            if "boot_aggregate" not in first_entry:
                self._add_error(
                    "ima_entries", "should start with a 'boot_aggregate' entry when the starting offset is 0"
                )

    def initialise(self, agent_id):
        if self.committed:
            raise ValueError("Attestation object cannot be initialised once committed")
        
        self.agent_id = agent_id

        # Set attestation index to the next available integer as determined from the agent's last attestation
        self._set_index()

        # Set required metadata
        self._set_timestamps()
        self._set_status()

    def receive_capabilities(self, data, agent):
        if self.committed.get("status") == "waiting":
            raise ValueError("Attestation object cannot be updated as it has already received agent capabilities")
        
        # Set fields from capabilities reported by the agent
        self.cast_changes(data, ["boottime", "supported_enc_algs", "supported_hash_algs", "supported_sign_algs"])
        self.validate_required(["boottime", "supported_enc_algs", "supported_hash_algs", "supported_sign_algs"])
        
        # Generate the nonce the agent should use in the TPM quote
        self._set_nonce()
        # Determine the starting IMA offset from the boot time and previous attestations
        self._set_ima_offset()
        # From the list of supported algorithms reported by the agent, select the algorithms the agent should use to
        # prepare the TPM quote
        self._set_algs(data, agent)

        # Update required metadata
        self._set_timestamps() # will update nonce_created_at and nonce_expires_at
        self._set_status() # will be set to "waiting" until evidence is received

    def receive_evidence(self, data, runtime_policy):
        """Updates the attestation entry with evidence recieved from the agent"""

        if self.committed.get("status") == "received":
            raise ValueError("Attestation object cannot be updated as it has already received evidence")

        # Bind key-value pairs ('data') to those fields which are meant to be externally changeable
        self.cast_changes(data, ["tpm_quote", "ima_entries", "mb_entries"])

        # Basic validation of values
        self.validate_required(["tpm_quote", "hash_alg", "enc_alg", "sign_alg"])
        self._validate_ima_entries(data.get("starting_ima_offset"), runtime_policy)

        # Update required metadata
        self._set_timestamps() # will update evidence_received_at
        self._set_status() # will be set to "received" until verification is complete

    def _set_failure_type(self, failure: Failure):
        if not failure:
            logger.info("Attestation %s for agent '%s' verified successfully", self.index, self.agent_id)
            return

        events = failure.events

        for event in events:
            if event.event_id == "quote_validation.quote_validation":
                self.failure_type = "quote_authentication"

                logger.warning(
                    "Attestation %s for agent '%s' failed verification because the TPM quote could not be authenticated",
                    self.index,
                    self.agent_id,
                )

                return

            if event.event_id.startswith("measured_boot.invalid_pcr_"):
                self.failure_type = "log_authentication"

                logger.warning(
                    "Attestation %s for agent '%s' failed verification because the boot log could not be authenticated "
                    "against the TPM quote",
                    self.index,
                    self.agent_id,
                )

                return

            if event.event_id == "ima.pcr_mismatch":
                self.failure_type = "log_authentication"

                logger.warning(
                    "Attestation %s for agent '%s' failed verification because the IMA log could not be authenticated "
                    "against the TPM quote",
                    self.index,
                    self.agent_id,
                )

                return

        self.failure_type = "policy_violation"

        logger.warning(
            "Attestation %s for agent '%s' failed verification because of the following policy violations:",
            self.index,
            self.agent_id,
        )

        for event in failure.events:
            logger.warning("  - %s", event.context)

    def verify_evidence(self, runtime_policy, mb_policy: Optional[str], agent, session):
        """Verifies the evidence recieved from the agent and set the attestation status. ('verified' or 'failed' based
        on verification)
        If the verification of the measurements fails against the policy, ``accept_attestation`` flag is set to False.
        This stops verifier from accepting new attestation until the ``accept_attestation`` flag is set to True by the
        user.

        """
        logger.debug("Starting verification of attestation %s for agent '%s'...", self.index, agent.agent_id)

        # TODO: Replace session
        failure = Failure(Component.QUOTE_VALIDATION)
        pub_key = None
        ima_entries = self.ima_entries or None
        mb_entries = Binary().render(self.mb_entries) or None
        # TODO add support for receiving ak_tpm from agent for an attestation
        ak_tpm = agent.ak_tpm
        tpm_policy = agent.tpm_policy

        if not self.changes_valid:
            raise ValueError("Attestation object cannot be verified as it has pending changes with errors")

        if self.status in ("verified", "failed"):
            raise ValueError("Attestation object has already undergone verification")

        if isinstance(runtime_policy, str):
            runtime_policy = json.loads(runtime_policy)
        
        # Initially attest_state reflects the result of the previous authenticated attestation plus the bootime received
        # at attestation creation and any values which depend on this bootime (e.g., starting IMA offset, IMA keyrings)
        attest_state = self.attest_state(agent, runtime_policy)
        # Note: there is no need to call attest_state.reset_ima_attestation() after reboot as the IMA-relevant values
        # are already properly initialised by self.attest_state

        quote_validation_failure = get_tpm_instance().check_quote(
            attest_state,
            self.nonce,
            pub_key,
            self.tpm_quote,
            ak_tpm,
            tpm_policy,
            ima_entries,
            runtime_policy,
            algorithms.Hash(self.hash_alg),
            attest_state.get_ima_keyrings(),
            mb_entries,
            mb_policy,
            compressed=False,
            count=agent.attestation_count,
        )
        failure.merge(quote_validation_failure)

        self._clear_agent_fields(agent, session)

        # At this point, attest_state reflects the outcome of the verification including the next expected IMA entry
        self.quoted_ima_entries_count = attest_state.next_ima_ml_entry - self.starting_ima_offset

        self.status = "verified" if not failure else "failed"
        agent.accept_attestations = self.status == "verified"
        self._set_failure_type(failure)

        if (
            self.status == "verified"
            and self.previous_attestation
            and self.previous_attestation.status == "verified"
            and self.previous_attestation.starting_ima_offset != 0
        ):
            self.previous_attestation.delete()

        # Only save new learned keyrings if quote was authenticated
        if self.failure_type != "quote_authentication":
            agent.learned_ima_keyrings = attest_state.get_ima_keyrings().to_json()

        self.commit_changes()

    def _clear_agent_fields(self, agent, session):
        if PushAttestation.get_last(self.agent_id):
            return

        agent.hash_alg = None
        agent.enc_alg = None
        agent.sign_alg = None
        agent.operational_state = None
        agent.ima_sign_verification_keys = None
        agent.ima_pcr = None  # This is ignored by Tpm.check_quote()
        agent.pcr10 = None
        agent.next_ima_ml_entry = None
        agent.severity_level = None
        agent.last_event_id = None
        agent.supported_version = None
        agent.attestation_count = None
        agent.tpm_clockinfo = None
        agent.tpm_version = None
        agent.last_received_quote = None
        agent.last_successful_attestation = None

        session.add(agent)

    def commit_changes(self):
        if self.status == "waiting":
            last_attestation = PushAttestation.get_last(self.agent_id)
            print("****last_attestation from commit changes",last_attestation)
            print("self.index",self.index)

            if last_attestation and last_attestation.index >= self.index:
                raise ValueError(f"An attestation for agent '{self.agent_id}' was created while another was mid-creation")

        return super().commit_changes()

    def render(self, only=None):
        if not only:
            only = ["agent_id", "status", "tpm_quote", "evidence_received_at", "tpm_pcrs", "starting_ima_offset"]

        return super().render(only)

    @property
    def previous_authenticated_attestation(self):
        if not self._previous_authenticated_attestation:
            if not self.agent_id:
                return None

            # TODO: Move sorting logic into model query API and possibly improve query expressiveness (Jean)

            """ all_attestations = PushAttestation.all(agent_id=self.agent_id)
            all_attestations = sorted(all_attestations, key=lambda attestation: attestation.index, reverse=True)

            #PushAttestation.get(agent_id=self.agent_id, status = ("verified", "failed")  _sort=desc("index"))

            previous_authenticated_attestation = None
            for attestation in all_attestations:
                if attestation.status in ("waiting", "received") or attestation.failure_type == "quote_authentication":
                    continue

                if attestation.index < self.index:
                    previous_authenticated_attestation = attestation """
            previous_authenticated_attestation =  PushAttestation.get(
                PushAttestation.agent_id==self.agent_id,
                or_(PushAttestation.status == "verified", PushAttestation.status == "failed"),
                or_(PushAttestation.failure_type != "quote_authentication", PushAttestation.failure_type == None),
                PushAttestation.index < self.index,
                _sort=desc("index")
            )

            if not previous_authenticated_attestation:
                return None

            self._previous_authenticated_attestation = previous_authenticated_attestation

        return self._previous_authenticated_attestation 

    @property
    def previous_successful_attestation(self):
        if not self._previous_successful_attestation:
            if not self.agent_id:
                return None

            """ all_attestations = PushAttestation.all(agent_id=self.agent_id, status="verified")
            all_attestations = sorted(
                all_attestations, key=lambda attestation: attestation.nonce_created_at, reverse=True
            )

            previous_successful_attestation = None
            for attestation in all_attestations:
                if attestation.nonce_created_at < self.nonce_created_at:
                    previous_successful_attestation = attestation """

            previous_successful_attestation = PushAttestation.get(agent_id = self.agent_id,
                                                                  status="verified",
                                                                  _sort=desc("index"))
            if not previous_successful_attestation:
                return None

            self._previous_successful_attestation = previous_successful_attestation

        return self._previous_successful_attestation

    @property
    def previous_attestation(self):
        if not self._previous_attestation:
            if not self.agent_id:
                return None

            """ all_attestations = PushAttestation.all(agent_id=self.agent_id)
            all_attestations = sorted(
                all_attestations, key=lambda attestation: attestation.nonce_created_at, reverse=True
            )

            previous_attestation = None
            for attestation in all_attestations:
                if attestation.nonce_created_at < self.nonce_created_at:
                    previous_attestation = attestation """
            
            previous_attestation = PushAttestation.get(agent_id=self.agent_id, _sort=desc("index"))

            if not previous_attestation:
                return None

            self._previous_attestation = previous_attestation

        return self._previous_attestation

    @property
    def next_ima_offset(self):
        if self.starting_ima_offset is not None and self.quoted_ima_entries_count is not None:
            return self.starting_ima_offset + self.quoted_ima_entries_count
        else:
            return None

    @property
    def next_attestation_expected_after(self):
        if self.evidence_received_at:
            basis = self.evidence_received_at
        else:
            basis = self.nonce_created_at

        return basis + timedelta(seconds=config.getint("verifier", "quote_interval"))

    @property
    def decision_expected_by(self):
        if self.evidence_received_at:
            basis = self.evidence_received_at
        else:
            basis = self.nonce_created_at + timedelta(seconds=config.getint("verifier", "quote_interval"))

        return basis + timedelta(seconds=config.getint("verifier", "verification_timeout"))

    @property
    def tpm_clock_info(self):
        if not self.tpm_quote:
            return None

        return Tpm._tpm2_clock_info_from_quote(self.tpm_quote, False)

    # TODO: make this a property
    def ima_pcrs(self, agent):
        if not self.tpm_pcrs:
            return None

        return {pcr_num: self.tpm_pcrs.get(pcr_num) for pcr_num in agent.ima_pcrs}

    @property
    def received_ima_entries_count(self):
        if not self.ima_entries:
            return 0

        return self.ima_entries.count("\n")

    # TODO: make this a property
    def attest_state(self, agent, runtime_policy):
        if not self._attest_state:
            # Create new attest state object for agent
            self._attest_state = AgentAttestState(self.agent_id)

            # Set attest state values which are known from attestation creation
            self._attest_state.set_boottime(self.boottime)
            self._attest_state.set_ima_dm_state(runtime_policy.get("dm_policy"))

            # Retrieve keys learned from ima-buf entries received in prior IMA logs
            if self.starting_ima_offset != 0:
                learned_keyrings = file_signatures.ImaKeyrings.from_json(agent.learned_ima_keyrings)
                if learned_keyrings:
                    self._attest_state.set_ima_keyrings(learned_keyrings)

            # Retrieve trusted keys from IMA policy
            ima_keyrings = self._attest_state.get_ima_keyrings()
            policy_keys = runtime_policy["verification-keys"]
            policy_keyring = file_signatures.ImaKeyring.from_string(policy_keys)
            ima_keyrings.set_tenant_keyring(policy_keyring)

            if self.status in ("verified", "failed"):
                self._attest_state.quote_progress = (self.quoted_ima_entries_count, self.received_ima_entries_count)

        # Attest state values which are extracted from the TPM quote can only be trusted if the quote is found to be
        # genuine. As a result, we only set these values once verification has completed and no authentication failure
        # has occured
        if self.status in ("verified", "failed") and self.failure_type != "quote_authentication":
            self._attest_state.set_tpm_clockinfo(self.tpm_clock_info)  # type: ignore
            self._attest_state.set_ima_pcrs(self.ima_pcrs(agent)) # type: ignore
            self._attest_state.set_next_ima_ml_entry(self.next_ima_offset) # type: ignore

            # Build embedded TPMState object containing PCR values found in authenticated quote
            self._attest_state.tpm_state = TPMState()
            for num, val in self.tpm_pcrs.items(): # type: ignore
                self._attest_state.tpm_state.init_pcr(num, self.hash_alg)
                self._attest_state.tpm_state.set_pcr(num, val)
        else:
            # If verification of the attestation has not yet completed, or the quote could not be authenticated, use the
            # values from the previous authenticated attestation
            self._attest_state.set_next_ima_ml_entry(self.starting_ima_offset)

            if self.previous_authenticated_attestation:
                self._attest_state.set_tpm_clockinfo(self.previous_authenticated_attestation.tpm_clock_info)
            elif agent.tpm_clockinfo:
                # If agent has a tpm_clockinfo value, this indicates that the verifier has recently changed from pull to
                # push mode, so use this in place of the missing `previous_authenticated_attestation`
                self._attest_state.set_tpm_clockinfo(agent.tpm_clockinfo)

            if self.previous_authenticated_attestation:
                self._attest_state.set_ima_pcrs(self.previous_authenticated_attestation.ima_pcrs(agent))
            elif agent.pcr10:
                # The agent has a pcr10 value, so it recently changed from pull to push mode
                self._attest_state.set_ima_pcrs({"10": agent.pcr10})

        return copy.copy(self._attest_state)
    
    # TODO: make this a property
    def pcr_selection(self, agent):
        pcr_selection = set()
        tpm_policy = json.loads(agent.tpm_policy)

        if "mask" in tpm_policy:
            del tpm_policy["mask"]
        
        lockdown_pcrs = [int(pcr) for pcr in tpm_policy.keys()]

        # TODO: Consider changing to use fields in the agent table, instead of relying on hard-coded PCRs
        pcr_selection.update(lockdown_pcrs)
        pcr_selection.update(config.MEASUREDBOOT_PCRS)
        pcr_selection.add(config.IMA_PCR)

        return sorted(list(pcr_selection))
    
    @property
    def tpm_pcrs(self):
        if not self.tpm_quote:
            return False

        tpm_pcrs_dict = Tpm.get_pcrs_from_quote(self.tpm_quote, False)
        tpm_pcrs_dict = {int(num): val for num, val in tpm_pcrs_dict.items()}
        
        return tpm_pcrs_dict
