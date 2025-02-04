from keylime.web.base import Controller
from keylime import cloud_verifier_tornado as v2
from keylime import config, api_version


class ServerInfoController(Controller):
    def _new_v2_main_handler(self):
        tornado_app = self.action_handler.application
        tornado_req = self.action_handler.request
        return v2.MainHandler(tornado_app, tornado_req, override=self.action_handler)

    def _new_v2_version_handler(self):
        tornado_app = self.action_handler.application
        tornado_req = self.action_handler.request
        return v2.VersionHandler(tornado_app, tornado_req, override=self.action_handler)

    def show_root(self, **_params):
        """The root endpoint may be used by clients which understand API v3+ to determine the current API version of the
        server by way of standard HTTP redirect. As v2 clients do not use this mechanism, it always redirects to a v3
        path, even when the deprecated /versions endpoint indicates an older version is most current.
        """
        version = api_version.current_version()
        major = api_version.major(version)

        if major > 3:
            self.redirect(f"/v{version}/")
        else:
            self.redirect(f"/v{api_version.latest_minor_version(3)}/")

    def show_version_root(self, **_params):
        """A request issued for the top-level path of a given API version results in a 200 response when the server
        supports that version.
        """
        if self.major_version <= 2:
            self._new_v2_main_handler().get()
        else:
            self.respond(200)

    # GET /version[s]
    def show_versions(self, **_params):
        """This endpoint is used by v2 clients (and earlier) to obtain a list of API versions supported by the server.
        Because this endpoint is itself not scoped to a particular API version, it is difficult/impossible to change
        without breaking existing clients. It is therefore deprecated for new clients and not supported in push mode.
        API clients should instead query the top-level path for the latest version supported by the client (e.g.,
        "/v3.0/") to determine whether it is available on the server or not.
        """
        if config.get("verifier", "mode", fallback="pull") == "pull":
            self._new_v2_version_handler().get()
        else:
            self.respond(410, "Gone")
