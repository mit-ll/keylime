from keylime.web.base import Controller
from keylime import cloud_verifier_tornado as v2


class AgentController(Controller):
    def _new_v2_handler(self):
        tornado_app = self.action_handler.application
        tornado_req = self.action_handler.request
        return v2.AgentsHandler(tornado_app, tornado_req, override=self.action_handler)

    # GET /vx[.y]/agents/
    def index(self, **_params):
        if self.major_version <= 2:
            self._new_v2_handler().get()
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation

    # GET /vx[.y]/agents/:id/
    def show(self, agent_id, **_params):
        if self.major_version <= 2:
            self._new_v2_handler().get()
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation

    # POST /v3[.x]/agents/
    # POST /v2[.x]/agents/:id
    def create(self, **_params):
        if self.major_version <= 2:
            self._new_v2_handler().post()
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation

    # PATCH /v3[.x]/agents/:id/
    def update(self, agent_id, **_params):
        self.respond(404)
        # TODO: Replace with v3 implementation

    # DELETE /vx[.y]/agents/:id/
    def delete(self, agent_id, **_params):
        if self.major_version <= 2:
            self._new_v2_handler().delete()
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation

    # PUT /v2[.x]/agents/:id/reactivate/
    def reactivate(self, agent_id, **_params):
        self._new_v2_handler().put()

    # PUT /v2[.x]/agents/:id/stop/
    def stop(self, agent_id, **_params):
        self._new_v2_handler().put()
