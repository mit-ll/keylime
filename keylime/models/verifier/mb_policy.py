from keylime.models.base import *
import keylime.models.verifier as verifier_models

class MBPolicy(PersistableModel):
    @classmethod
    def _schema(cls):
        cls._persist_as("allowlists")
        cls._id("id", Integer)

        # Associations
        cls._has_many("agents", verifier_models.VerifierAgent)

        cls._field("name", String(255))
        cls._field("mb_policy", Text)

