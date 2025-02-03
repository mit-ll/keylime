from keylime.web.base.server import Server
from keylime.web.verifier.agent_controller import AgentController
from keylime.web.verifier.mb_ref_state_controller import MBRefStateController
from keylime.web.verifier.ima_policy_controller import IMAPolicyController
from keylime.web.verifier.push_attestation_controller import PushAttestationController
from keylime.web.verifier.evidence_controller import EvidenceController
from keylime.web.verifier.server_info_controller import ServerInfoController
from keylime.web.verifier.session_contoller import SessionController


class VerifierServer(Server):
    def _setup(self):
        self._use_config("verifier")

    def _routes(self):
        self._top_level_routes()
        self._v2_routes()
        self._v3_routes()

    def _top_level_routes(self):
        self._get("/", ServerInfoController, "show_root")
        self._get("/versions", ServerInfoController, "show_versions")
        self._get("/version", ServerInfoController, "show_versions")

    @Server.version_scope(2)
    def _v2_routes(self):
        self._get("/", ServerInfoController, "show_version_root")

        # Routes for managing agent resources
        self._agent_routes()
        # Agent management routes which are replaced in API v3
        self._v2_agent_routes()
        # Routes for managing measured boot verification in API v2
        self._v2_mb_routes()
        # Routes for managing IMA verification in API v2
        self._v2_ima_routes()
        # Routes for on-demand verification of evidence in API v2
        self._v2_evidence_routes()

        # Note: push-specific endpoints are only available from API v3 onwards

    @Server.version_scope(3)
    def _v3_routes(self):
        self._get("/", ServerInfoController, "show_version_root")

        # Routes for managing agent resources
        self._agent_routes()
        # Agent management routes available from API v3
        self._v3_agent_routes()
        # Routes for managing push attestation resources (API v3+ only)
        self._attestation_routes()
        # Routes for managing measured boot verification in API v3+
        self._v3_mb_routes()
        # Routes for managing IMA verification in API v3+
        self._v3_ima_routes()
        # Routes for on-demand verification of evidence in API v3+
        self._v3_evidence_routes()
        # Routes for agent athentication
        self._v3_authentication_routes()
        

    def _agent_routes(self):
        # Routes used to manage agents enrolled for verification
        self._get("/agents", AgentController, "index")
        self._get("/agents/:agent_id", AgentController, "show")
        self._delete("/agents/:agent_id", AgentController, "delete")

    def _v2_agent_routes(self):
        # Routes used to manage agents enrolled for verification
        self._post("/agents/:agent_id", AgentController, "create")

        # Routes used in pull mode to control polling for attestations from agents
        self._put("/agents/:agent_id/reactivate", AgentController, "reactivate")
        self._put("/agents/:agent_id/stop", AgentController, "stop")
        # Note: in v3+, these actions are performed by mutating agent resources directly

    def _v3_agent_routes(self):
        # Routes used to manage agents enrolled for verification (which adhere to RFC 9110 semantics)
        self._post("/agents", AgentController, "create")
        self._patch("/agents/:agent_id", AgentController, "update")
        # Note: in pull mode, the update action includes turning polling on/off

    @Server.push_only
    def _attestation_routes(self):
        self._get("/agents/:agent_id/attestations", PushAttestationController, "index", allow_insecure=True)
        self._post("/agents/:agent_id/attestations", PushAttestationController, "create", allow_insecure=True)
        self._get("/agents/:agent_id/attestations/latest", PushAttestationController, "show_latest", allow_insecure=True)
        self._patch("/agents/:agent_id/attestations/latest", PushAttestationController, "update_latest", allow_insecure=True)
        self._get("/agents/:agent_id/attestations/:index", PushAttestationController, "show", allow_insecure=True)
        self._patch("/agents/:agent_id/attestations/:index", PushAttestationController, "update", allow_insecure=True)

        # TODO: Remove "allow_insecure" above

    def _v2_mb_routes(self):
        # Routes used to manage reference states for MB/UEFI verification
        self._get("/mbpolicies", MBRefStateController, "index")
        self._post("/mbpolicies/:name", MBRefStateController, "create")
        self._get("/mbpolicies/:name", MBRefStateController, "show")
        self._put("/mbpolicies/:name", MBRefStateController, "overwrite")
        self._delete("/mbpolicies/:name", MBRefStateController, "delete")

    def _v3_mb_routes(self):
        # Routes used to manage reference states for MB/UEFI verification (which adhere to RFC 9110 semantics)
        self._get("/refstates/uefi", MBRefStateController, "index")
        self._post("/refstates/uefi", MBRefStateController, "create")
        self._get("/refstates/uefi/:name", MBRefStateController, "show")
        self._patch("/refstates/uefi/:name", MBRefStateController, "update")
        self._delete("/refstates/uefi/:name", MBRefStateController, "delete")

    def _v2_ima_routes(self):
        # Routes used to manage policies for IMA verification
        self._get("/allowlists", IMAPolicyController, "index")
        self._get("/allowlists/:name", IMAPolicyController, "show")
        self._post("/allowlists/:name", IMAPolicyController, "create")
        self._put("/allowlists/:name", IMAPolicyController, "overwrite")
        self._delete("/allowlists/:name", IMAPolicyController, "delete")

    def _v3_ima_routes(self):
        # Routes used to manage policies for IMA verification (which adhere to RFC 9110 semantics)
        self._get("/policies/ima", IMAPolicyController, "index")
        self._get("/policies/ima/:name", IMAPolicyController, "show")
        self._post("/policies/ima", IMAPolicyController, "create")
        self._patch("/policies/ima/:name", IMAPolicyController, "update")
        self._delete("/policies/ima/:name", IMAPolicyController, "delete")

    def _v2_evidence_routes(self):
        # Routes for on-demand verification of evidence
        self._get("/verify/identity", EvidenceController, "process")

    def _v3_evidence_routes(self):
        # Routes for on-demand verification of evidence (which adhere to RFC 9110 semantics)
        self._post("/evidence", EvidenceController, "process")
    
    def _v3_authentication_routes(self):
        #Routes for agent authentication
        self._get("/agents/:agent_id/session/:token", SessionController, "show", allow_insecure=True)
        self._post("/agents/:agent_id/session", SessionController, "create", allow_insecure=True)
        self._patch("/agents/:agent_id/session/:token", SessionController, "update", allow_insecure=True)

        # TODO: Remove "allow_insecure" above
