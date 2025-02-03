from keylime.web.base import Controller
from keylime import cloud_verifier_tornado as v2


class EvidenceController(Controller):
    """The EvidenceController class performs on-demand, once-off verification of evidence at the will of any API
    consumer. Conversely, continuous verification of a system over time is handled by ``AgentController`` and 
    ``PushAttestationController`` when the verifier is operating in pull and push mode respectively.
    """

    def _new_v2_handler(self):
        tornado_app = self.action_handler.application
        tornado_req = self.action_handler.request
        return v2.VerifyIdentityHandler(tornado_app, tornado_req, override=self.action_handler)
    
    # POST /v3[.x]/evidence
    # GET /v2[.x]/verify/identity
    def process(self, **_params):
        if self.major_version <= 2:
            self._new_v2_handler().get()
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation
