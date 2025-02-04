from keylime.models.base import *
import keylime.models.verifier as verifier_models

class IMAPolicy(PersistableModel):
    @classmethod
    def _schema(cls):
        cls._persist_as("allowlists")
        cls._id("id", Integer)

        # Associations
        cls._has_many("agents", verifier_models.VerifierAgent)

        cls._field("name", String(255))
        cls._field("ima_policy", Dictionary)
        cls._field("tpm_policy", Text, nullable=True)
        cls._field("checksum", String(128), nullable=True)
        cls._field("generator", Integer, nullable=True)