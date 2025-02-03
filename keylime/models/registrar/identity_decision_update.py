from keylime.models.base import *


class AdditionalInfo(BasicModel):
    @classmethod
    def _schema(cls):
        pass


class IdentityOverride(BasicModel):
    @classmethod
    def _schema(cls):
        cls._field("identity", String)
        cls._field("action", OneOf("replace_value", "add_binding", "remove_binding", "change_trust_decision"))

        # Action-specific fields:     # ACTION
        cls._field("value", String)  # "replace_value"
        cls._field("parent", String)  # "add_binding"; "remove_binding"
        cls._field("status", String)  # "change_trust_decision"


class IdentityDecisionUpdate(BasicModel):
    @classmethod
    def _schema(cls):
        cls._embeds_one("additional_info", AdditionalInfo)
        cls._embeds_many("identity_overrides", IdentityOverride)

    @classmethod
    def receive(cls, data):
        decision_update = cls.empty()

        for overrride_data in data.get("identity_overrides"):
            override = IdentityOverride.empty()
            override.cast_changes(overrride_data, ["identity", "action", "value", "parent", "status"])

        return decision_update

    def apply(self, agent):
        pass
