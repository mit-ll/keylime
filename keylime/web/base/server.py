import asyncio
import multiprocessing
from abc import ABC, abstractmethod
from functools import wraps
from ssl import CERT_OPTIONAL
from typing import TYPE_CHECKING, Any, Callable, Optional

import tornado

from keylime import config, keylime_logging, web_util, api_version
from keylime.web.base.action_handler import ActionHandler
from keylime.web.base.route import Route

if TYPE_CHECKING:
    from ssl import SSLContext

    from keylime.web.base.controller import Controller

logger = keylime_logging.init_logging("web")


class Server(ABC):
    """The Server abstract class provides a domain-specific language (DSL) for defining an HTTP server with a set of
    specific endpoints. This is translated into a list of routes (see the ``Route`` class) which is ordered according to
    priority and can be matched against incoming requests based on their HTTP method and URL path.

    Example
    -------

    To use the Server class, inherit from it and implement the required ``_routes`` method::

        class ExampleServer(Server):
            def _routes(self):
                self._get("/", ExampleController, "example_action")
                # (Any additional routes...)

    Routes are defined by calling the ``self._get(...)``, ``self._post(...)``, ``self._put(...)``, etc. helper methods.
    These calls must happen within the ``_routes`` method or a method which is called by ``_routes``. Each helper method
    takes a path pattern, controller and action. For more details on these parameters, refer to the documentation for
    the ``Route`` class.

    In the event that multiple routes apply to a single request, routes defined earlier will take priority
    over routes defined later.

    Once a server is defined by subclassing Server as above, it can be used by creating a new instance and calling
    the ``start`` instance method::

        server = ExampleServer()
        server.start()

    To spawn multiple worker processes for handling requests, you can call Tornado's ``fork_processes`` function after
    instantiating the server, but before starting it:

        server = ExampleServer()
        tornado.process.fork_processes(0)
        server.start()

    Decorators
    ----------

    The Server class also provides decorators which can be used to modify routes defined using the helper methods,
    or generate additional routes automatically. These decorators can be applied directly to the routes defined
    in the ``_routes`` method or to a subset of routes by extracting them into their own method::

        class ExampleServer(Server):
            def _routes(self):
                self._v2_routes()
                self._get("/", HomeController, "index")

            @Server.version_scope(2)
            def _v2_routes(self):
                self._get("/agents", AgentsController, "index")
                self._get("/agents/:id", AgentsController, "show")

    The above example, in which ``@Server.version_scope(2)`` is applied to the ``_v2_routes`` method, is equivalent
    to defining all routes manually as follows:

        class ExampleServer(Server):
            def _routes(self):
                self._get("/v2/agents", AgentsController, "index")
                self._get("/v2.:minor/agents", AgentsController, "index")
                self._get("/v2/agents/:id", AgentsController, "show")
                self._get("/v2.:minor/agents/:id", AgentsController, "show")
                self._get("/", HomeController, "index")

    Notice that the ``"index"`` and ``"show"`` actions of ``AgentsController`` will now handle requests made to version
    2 of the API, regardless of whether a minor version is specified or not.
    """

    @staticmethod
    def _new_scoped_route(pattern_prefix: str, route: Route) -> Route:
        pattern = pattern_prefix + route.pattern
        return Route(route.method, pattern, route.controller, route.action, route.allow_insecure)

    @staticmethod
    def _make_versioned_routes(major_version: int, route: Route) -> list[Route]:
        versioned_routes = [Server._new_scoped_route(f"/v{major_version}", route)]
        versioned_routes = versioned_routes + [
            Server._new_scoped_route(f"/v{version}", route)
            for version in api_version.all_versions()
            if api_version.major(version) == major_version
        ]
        return versioned_routes

    @staticmethod
    def version_scope(major_version: int) -> Callable[..., Callable[..., Any]]:
        # pylint: disable=protected-access, unused-private-member

        # Create a decorator which will scope routes to major_version
        def version_scope_decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            # Create a wrapper function which will take the place of the decorated function (func)
            @wraps(func)  # preserves the name and module of func when introspected
            def version_scope_wrapper(obj: Server, *args: Any, **kwargs: Any) -> Any:
                if not isinstance(obj, Server):
                    raise TypeError(
                        "The @Server.version_scope(major_version) decorator can only be used on methods of a class "
                        "which inherits from Server"
                    )

                # Get the routes defined at the time that the decorator is called
                initial_routes = obj.routes
                # Create a new list to hold the routes to be added to the Server
                new_routes_list = []
                # Call the decorated function and get the return value (typically None)
                value = func(obj, *args, **kwargs)

                # Iterate over routes created so far
                for route in obj.routes:
                    # Check that the current route is a route newly created by the decorated function
                    if route not in initial_routes:
                        # Define routes scoped to the API version specified by major_version
                        new_routes_list.extend(Server._make_versioned_routes(major_version, route))

                # Replace the Server instance's list of routes with a new list consisting of the routes which were
                # present before func was called and the new routes scoped to major_version
                obj.__routes = initial_routes + new_routes_list

                # Return the return value of the decorated function in case it is something other than None
                return value

            return version_scope_wrapper

        return version_scope_decorator

    @staticmethod
    def push_only(func):
        @wraps(func)  # preserves the name and module of func when introspected
        def push_only_wrapper(obj: Server, *args: Any, **kwargs: Any) -> Any:
            value = func(obj, *args, **kwargs)
            if not isinstance(obj, Server):
                raise TypeError(
                    "The @Server.push_only decorator can only be used on methods of a class which inherits from Server"
                )

            # TODO: Change fallback to "pull" and add config option
            if config.get("verifier", "mode", fallback="push") == "push":
                return value

        return push_only_wrapper

    @staticmethod
    def pull_only(func):
        @wraps(func)  # preserves the name and module of func when introspected
        def pull_only_wrapper(obj: Server, *args: Any, **kwargs: Any) -> Any:
            if not isinstance(obj, Server):
                raise TypeError(
                    "The @Server.pull_only decorator can only be used on methods of a class which inherits from Server"
                )

            # TODO: Change fallback to "pull" and add config option
            if config.get("verifier", "mode", fallback="push") == "pull":
                return func(obj, *args, **kwargs)

        return pull_only_wrapper

    def __init__(self, **options: Any) -> None:
        """Initialise server with provided configuration options or default values and bind to sockets for HTTP and/or
        HTTPS connections. This does not start the server to start accepting requests (this is done by calling the
        ``server.start()`` instance method).

        If you wish to create multiple server processes, first instantiate a new server and then fork the process
        before starting the server with `server.start()`.
        """
        # Set defaults for server options
        self._host: str = "127.0.0.1"
        self._http_port: Optional[int] = 80
        self._https_port: Optional[int] = 443
        self._max_upload_size: Optional[int] = 104857600  # 100MiB
        self._ssl_ctx: Optional["SSLContext"] = None
        self._worker_count: Optional[int] = 0

        # Override defaults with values given by the implementing class
        self._setup()

        # If options are set by the caller, use these to override the defaults and those set by the implementing class
        for opt in ["host", "http_port", "https_port", "max_upload_size", "ssl_ctx"]:
            if opt in options:
                setattr(self, f"_{opt}", options[opt])

        if not self.host:
            raise ValueError(f"server '{self.__class__.__name__}' cannot be initialised without a value for 'host'")

        # TODO fix this logic
        # if not self.http_port or (not self.https_port or not self.ssl_ctx):
        if not self.http_port:
            raise ValueError(
                f"server '{self.__class__.__name__}' cannot be initialised without either 'http_port' or 'https_port'"
                f"and 'ssl_ctx'"
            )

        # Initialise empty list for routes
        self.__routes: list[Route] = []
        # Add routes defined by the implementing class
        self._routes()

        # Create new Tornado app with request handler to process routes
        self.__tornado_app = tornado.web.Application([(r".*", ActionHandler, {"server": self})])
        # Bind socket for HTTP connections
        self.__tornado_http_sockets = tornado.netutil.bind_sockets(int(self.http_port), address=self.host)
        # Bind socket for HTTPS connections
        self.__tornado_https_sockets = tornado.netutil.bind_sockets(int(self.https_port), address=self.host)

        # Tornado servers are instantiated by calling start_single() or start_multi(), so set to None initially
        self.__tornado_http_server: Optional[tornado.httpserver.HTTPServer] = None
        self.__tornado_https_server: Optional[tornado.httpserver.HTTPServer] = None

    async def start_single(self) -> None:
        """Instantiates and starts the server (with one Tornado HTTPServer instance to handle HTTP connections
        and another to handle HTTPS connections).

        This should be done once per process. When new processes are created by forking, this method
        should be called after the fork.
        """
        if self.__tornado_http_sockets:
            http_server = tornado.httpserver.HTTPServer(
                self.__tornado_app, ssl_options=None, max_buffer_size=self.max_upload_size
            )
            http_server.add_sockets(self.__tornado_http_sockets)
            self.__tornado_http_server = http_server

        if self.__tornado_https_sockets and self.ssl_ctx:
            https_server = tornado.httpserver.HTTPServer(
                self.__tornado_app, ssl_options=self.ssl_ctx, max_buffer_size=self.max_upload_size
            )
            https_server.add_sockets(self.__tornado_https_sockets)
            self.__tornado_https_server = https_server

        await asyncio.Event().wait()

    def start_multi(self) -> None:
        ports = ""
        protocols = ""

        if self.__tornado_http_sockets:
            ports = str(self.http_port)
            protocols = "HTTP"

        if self.__tornado_https_sockets and self.ssl_ctx:
            ports = f"{ports}/{self.https_port}" if ports else f"{self.https_port}"
            protocols = f"{protocols}/S" if protocols else "HTTPS"

        logger.info(
            "Listening on %s:%s (%s) with %s worker processes...", self.host, ports, protocols, self.worker_count
        )

        tornado.process.fork_processes(self.worker_count)
        asyncio.run(self.start_single())

    def _setup(self) -> None:
        """Defines values to use in place of the defaults for the various server options. It is suggested that this is
        overriden by the implementing class."""

    @abstractmethod
    def _routes(self) -> None:
        """Defines the routes accepted the server. Must be overridden by the implementing class and include one
        or more calls to the ``_get``, ``_head``, ``_post``, ``_put``, ``_patch``, ``_delete`` and/or ``_options``
        helper methods."""

    def _use_config(self, component: str) -> None:
        """Sets server options to values found in the config."""
        self._host = config.get(component, "ip")
        self._http_port = config.getint(component, "port", fallback=0)
        self._https_port = config.getint(component, "tls_port", fallback=0)
        self._max_upload_size = config.getint(component, "max_upload_size", fallback=104857600)
        self._ssl_ctx = web_util.init_mtls(component)
        self._ssl_ctx.verify_mode = CERT_OPTIONAL

    def _get(self, pattern: str, controller: type["Controller"], action: str, allow_insecure: bool = False) -> None:
        """Creates a new route to handle incoming GET requests issued for paths which match the given
        pattern. Must be called from a Server subclass's ``self._routes`` method.
        """
        self.__routes.append(Route("get", pattern, controller, action, allow_insecure))

    def _head(self, pattern: str, controller: type["Controller"], action: str, allow_insecure: bool = False) -> None:
        """Creates a new route to handle incoming HEAD requests issued for paths which match the given
        pattern. Must be called from a Server subclass's ``self._routes`` method.
        """
        self.__routes.append(Route("head", pattern, controller, action, allow_insecure))

    def _post(self, pattern: str, controller: type["Controller"], action: str, allow_insecure: bool = False) -> None:
        """Creates a new route to handle incoming POST requests issued for paths which match the given
        pattern. Must be called from a Server subclass's ``self._routes`` method.
        """
        self.__routes.append(Route("post", pattern, controller, action, allow_insecure))

    def _put(self, pattern: str, controller: type["Controller"], action: str, allow_insecure: bool = False) -> None:
        """Creates a new route to handle incoming PUT requests issued for paths which match the given
        pattern. Must be called from a Server subclass's ``self._routes`` method.
        """
        self.__routes.append(Route("put", pattern, controller, action, allow_insecure))

    def _patch(self, pattern: str, controller: type["Controller"], action: str, allow_insecure: bool = False) -> None:
        """Creates a new route to handle incoming PATCH requests issued for paths which match the given
        pattern. Must be called from a Server subclass's ``self._routes`` method.
        """
        self.__routes.append(Route("patch", pattern, controller, action, allow_insecure))

    def _delete(self, pattern: str, controller: type["Controller"], action: str, allow_insecure: bool = False) -> None:
        """Creates a new route to handle incoming DELETE requests issued for paths which match the given
        pattern. Must be called from a Server subclass's ``self._routes`` method.
        """
        self.__routes.append(Route("delete", pattern, controller, action, allow_insecure))

    def _options(self, pattern: str, controller: type["Controller"], action: str, allow_insecure: bool = False) -> None:
        """Creates a new route to handle incoming OPTIONS requests issued for paths which match the given
        pattern. Must be called from a Server subclass's ``self._routes`` method.
        """
        self.__routes.append(Route("options", pattern, controller, action, allow_insecure))

    def first_matching_route(self, method: Optional[str], path: str) -> Optional[Route]:
        """Gets the highest-priority route which matches the given ``method`` and ``path``."""
        if method is None:
            matching_routes = (route for route in self.__routes if route.matches_path(path))
        else:
            matching_routes = (route for route in self.__routes if route.matches(method, path))

        try:
            return next(matching_routes)
        except StopIteration:
            return None

    @property
    def http_port(self) -> Optional[int]:
        return self._http_port

    @property
    def https_port(self) -> Optional[int]:
        return self._https_port

    @property
    def host(self) -> str:
        return self._host

    @property
    def max_upload_size(self) -> Optional[int]:
        return self._max_upload_size

    @property
    def ssl_ctx(self) -> Optional["SSLContext"]:
        return self._ssl_ctx

    @property
    def worker_count(self) -> int:
        # pylint: disable=no-else-return

        if self._worker_count == 0 or self._worker_count is None:
            return multiprocessing.cpu_count()
        else:
            return self._worker_count

    @property
    def routes(self) -> list[Route]:
        return self.__routes.copy()

    @property
    def tornado_http_server(self) -> Optional[tornado.httpserver.HTTPServer]:
        return self.__tornado_http_server

    @property
    def tornado_https_server(self) -> Optional[tornado.httpserver.HTTPServer]:
        return self.__tornado_https_server
