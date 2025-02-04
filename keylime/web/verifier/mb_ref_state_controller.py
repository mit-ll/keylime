from keylime.web.base import Controller
from keylime import cloud_verifier_tornado as v2


class MBRefStateController(Controller):
    def _new_v2_handler(self):
        tornado_app = self.action_handler.application
        tornado_req = self.action_handler.request
        return v2.MbpolicyHandler(tornado_app, tornado_req, override=self.action_handler)

    # GET /v3[.x]/refstates/uefi/
    # GET /v2[.x]/mbpolicies/
    def index(self, **_params):
        if self.major_version <= 2:
            self._new_v2_handler().get()
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation

    # GET /v3[.x]/refstates/uefi/:name
    # GET /v2[.x]/mbpolicies/:name
    def show(self, name, **_params):
        if self.major_version <= 2:
            self._new_v2_handler().get()
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation

    # POST /v3[.x]/refstates/uefi/
    # POST /v2[.x]/mbpolicies/:name
    def create(self, **_params):
        if self.major_version <= 2:
            self._new_v2_handler().post()
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation

    # PATCH /v3[.x]/refstates/uefi/:name
    def update(self, name, **_params):
        self.respond(404)
        # TODO: Replace with v3 implementation

    # PUT /v2[.x]/mbpolicies/:name
    def overwrite(self, name, **_params):
        self._new_v2_handler().put()

    # DELETE /v3[.x]/refstates/uefi/:name
    # DELETE /v2[.x]/mbpolicies/:name
    def delete(self, name, **_params):
        if self.major_version <= 2:
            self._new_v2_handler().delete()
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation
