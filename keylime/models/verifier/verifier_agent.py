from keylime.models.base import *
import keylime.models.verifier as verifier_models

from keylime.mba import mba
from keylime import config
from keylime.common import states

from keylime.db.verifier_db import JSONPickleType
from keylime.json import JSONPickler

class VerifierAgent(PersistableModel):

    @classmethod
    def _schema(cls):
        cls._persist_as("verifiermain")
        cls._id("agent_id", String(80))

        # Associations
        cls._belongs_to("ima_policy", verifier_models.IMAPolicy)
        cls._belongs_to("mb_policy", verifier_models.MBPolicy)
        cls._has_many("attestations", verifier_models.PushAttestation)

        # The attestation key (AK) used by the TPM to sign attestations
        cls._field("ak_tpm", String(500))
        # Arbitrary metadata about the agent which includes info about the agent's cert if configured to use mTLS
        cls._field("meta_data", String(200))

        # Describes the expected values for the TPM's platform configuration registers (PCRs)
        cls._field("tpm_policy", Dictionary)

        # Fields for runtime integrity monitoring (Linux IMA)
        cls._field("learned_ima_keyrings", Dictionary)

        # Allowable cryptographic algorithms to accept from the TPM
        cls._field("accept_tpm_hash_algs", List)
        cls._field("accept_tpm_encryption_algs", List)
        cls._field("accept_tpm_signing_algs", List)

        # ------------------------------------------------------------------ #
        # PUSH-MODE ONLY FIELDS:

        # Indicates whether attestations will be accepted for this agent
        cls._field("accept_attestations", Boolean)

        # ------------------------------------------------------------------ #
        # PULL-MODE ONLY FIELDS:

        # TODO: replace with SQLAlchemy Enum datatype
        cls._field("operational_state", Integer)
        cls._field("severity_level", Integer, nullable=True)

        cls._field("v", String(45))
        cls._field("public_key", String(500))
        cls._field("mtls_cert", Certificate, nullable=True)
        cls._field("ip", String(15))
        cls._field("port", Integer)
        cls._field("verifier_id", String(80))
        cls._field("verifier_ip", String(15))
        cls._field("verifier_port", Integer)

        # The API version used by the agent
        cls._field("supported_version", String(20))

        # Cryptographic algorithms used to produce quotes
        cls._field("hash_alg", String(10))
        cls._field("enc_alg", String(10))
        cls._field("sign_alg", String(10))

        # Fields for runtime integrity monitoring (Linux IMA)
        cls._field("ima_sign_verification_keys", Text)
        cls._field("ima_pcrs", List)
        cls._field("pcr10", LargeBinary, nullable=True)
        cls._field("next_ima_ml_entry", Integer)

        # Other miscellaneous measures of system state
        cls._field("boottime", Integer)
        cls._field("tpm_clockinfo", Dictionary, nullable=True)

        # Metrics and timestamps
        cls._field("attestation_count", Integer)
        cls._field("last_received_quote", Integer)
        cls._field("last_successful_attestation", Integer)

        # ------------------------------------------------------------------ #
        # QUESTION FOR REVIEWERS:
        # Are these fields for revocation still needed or can we remove them?
        cls._field("revocation_key", String(2800))
        cls._field("last_event_id", String(200), nullable=True)
        # ------------------------------------------------------------------ #
        # TODO: remove above, based on feedback
