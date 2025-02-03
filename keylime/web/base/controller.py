import http.client
import json
import re
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Mapping, Optional, Sequence, TypeAlias, Union

from tornado.escape import parse_qs_bytes
from tornado.httputil import parse_body_arguments

from keylime.web.base.errors import ParamDecodeError

if TYPE_CHECKING:
    from logging import Logger

    from keylime.models.base.basic_model import BasicModel
    from keylime.web.base.action_handler import ActionHandler

PathParams: TypeAlias = Mapping[str, str]
QueryParams: TypeAlias = Mapping[str, str | Sequence[str]]
MultipartParams: TypeAlias = Mapping[str, Union[str, bytes, Sequence[str | bytes]]]
FormParams: TypeAlias = Union[QueryParams, MultipartParams]
JSONConvertible: TypeAlias = Union[str, int, float, bool, None, "JSONObjectConvertible", "JSONArrayConvertible"]
JSONObjectConvertible: TypeAlias = Mapping[str, JSONConvertible]
JSONArrayConvertible: TypeAlias = Sequence[JSONConvertible]  # pyright: ignore[reportInvalidTypeForm]
Params: TypeAlias = Mapping[str, Union[str, bytes, Sequence[str | bytes], JSONObjectConvertible, JSONArrayConvertible]]


class Controller:
    """A controller represents a collection of actions that an API consumer can perform on a resource or set of
    resources. Each action translates a request into method calls made to a model (or multiple models). These calls
    include those needed to query the database and locate the relevant records and also those needed to render these
    records to a representation which can be returned to the API consumer.

    Example
    -------

    A controller is any class which inherits from the ``Controller`` class as follows:

        class AgentsController(Controller):
            async def index(self, **params):
                results = Agent.all()
                self.respond(200, "Success", results)

    The instance methods defined by a controller are referred to as the controller's "actions". These should typically
    be referenced by a route defined by a ``Server`` subclass.

    Each action handles a specify type of request and receives a number of parameters which are extracted from the
    incoming request. These parameters include those present in the URL or in the HTTP request body. Parameters will be
    extracted so long as they are encoded in URL query format, as form data or as JSON. Additionally, the parameters
    will include any indicated by the route's pattern (refer to the documentation for ``Route`` for details).

    All actions should accept any arbitrary keyword argument but may define additional named parameters. Typically, the
    method signature of an action will include all parameters that the action expects to be included in requests made by
    the API consumer::

        async def show(self, id, format=None, **params):
            # (Implementation...)

    In the ``show`` action above, the ``id`` parameter is required and used to locate the record. The result returned
    will depend on ``format`` which is optional and defaults to ``None``.

    If a required parameter is missing from an incoming request, this will be handled by ``ActionHandler`` which will
    respond with a 400 "Bad Request" error.

    Controller vs. Model
    --------------------

    When deciding whether business logic should be implemented as part of a controller or the model itself, the
    general rule is that the controller should only contain the minimum code needed to receive data from the request
    and prepare it to be received in the expected format by methods defined by the model. These should include methods
    for locating records in the database (these are typically those inherited from the ``PersistableModel`` class) as
    well as methods for creating new records, modifying existing records and displaying records (these are all
    typically defined by each individual model).
    """

    # Regex used to extract the API version from a URL, irrespective of how routes are defined
    VERSION_REGEX = re.compile("^\\/v(\\d+)(?:\\.(\\d+))*")

    @staticmethod
    def decode_url_query(query: str | bytes) -> QueryParams:
        """Parses a binary query string (whether from a URL or HTTP body) into a dict of Unicode strings. If multiple
        instances of the same key are present in the string, their values are collected into a list.

        Note that keys and values are interpreted according to the 'latin-1' Python text encoding because of how
        Tornado has chosen to implement query string parsing. This means that each byte (represented in the query string
        as an ASCII character or percent-encoded sequence) is interpreted as a single character from the 'Basic Latin'
        or 'Latin-1 Supplement' Unicode blocks. The implication of this is that no non-latin characters can be
        represented in the query string, even when using percent encoding.

        :raises: :class:`ParamDecodeError`: query string data is malformed
        """
        try:
            query_params = parse_qs_bytes(query)  # type: dict[str, Any]
        except ValueError as err:
            raise ParamDecodeError(f"could not parse data as query string: {str(err)}") from err

        for name, values in query_params.items():
            if len(values) > 1:
                query_params[name] = [bytes.decode(val) for val in values]
            else:
                query_params[name] = bytes.decode(values[0])

        return query_params

    @staticmethod
    def decode_multipart_form(content_type: str, form: bytes) -> MultipartParams:
        """Parses a binary HTTP body encoded with the "multipart/form-data" media type into a dict of Unicode strings.
        Multiple instances of the same key are collected into a list.

        As a multipart/form-data body may contain arbitrary binary data, values not interpretable as Unicode will be
        left as-is and returned as bytes object. Ideally, the media type of each part would be used to determine its
        encoding, but Tornado's implementation does not make use of this feature of RFC 7578.

        :raises: :class:`ParamDecodeError`: form data is malformed
        """
        collated_params: dict[str, list[bytes]] = {}
        decoded_params: dict[str, Union[str, bytes, Sequence[str | bytes]]] = {}

        try:
            parse_body_arguments(content_type, form, collated_params, {})
        except ValueError as err:
            raise ParamDecodeError(f"could not parse body of type 'multipart/form-data': {str(err)}") from err

        for name, values in collated_params.items():
            try:
                if len(values) > 1:
                    decoded_params[name] = [bytes.decode(val) for val in values]
                else:
                    decoded_params[name] = bytes.decode(values[0])

            except UnicodeError:
                decoded_params[name] = values

        return decoded_params

    @staticmethod
    def prepare_http_body(
        body: Union[str, JSONObjectConvertible | JSONArrayConvertible, Any], content_type: Optional[str] = None
    ) -> tuple[Optional[bytes | Any], Optional[str]]:
        """Prepares an object to be included in the body of an HTTP request or response and infers the appropriate
        media type unless provided. ``body`` will be serialised into JSON if it contains a ``dict`` or ``list`` which is
        serialisable unless a ``content_type`` other than ``"application/json"`` is provided.

        :param body: The body of the request/response
        :param content_type: An optional media/MIME type used to interpret the contents of ``body``

        :raises: :class:`TypeError`: tried to convert ``body`` to JSON but contains it objects of a type not convertible
        :raises: :class:`ValueError`: tried to convert ``body`` to JSON but contains values which are not convertible

        :returns: a 2-tuple with the body and content_type the caller should use in their HTTP request/response
        """
        if content_type and not isinstance(content_type, str):
            raise TypeError(f"content_type '{content_type}' is not of type str")

        if content_type:
            content_type = content_type.lower().strip()

        body_out: Optional[bytes | Any]
        content_type_out: Optional[str]

        match (body, content_type):
            case (None, _):
                body_out = None
                content_type_out = content_type
            case ("", _):
                body_out = b""
                content_type_out = "text/plain; charset=utf-8"
            case (_, "text/plain"):
                body_out = str(body).encode("utf-8")
                content_type_out = "text/plain; charset=utf-8"
            case (_, "application/json") if isinstance(body, str):
                body_out = body.encode("utf-8")
                content_type_out = "application/json"
            case (_, "application/json"):
                body_out = json.dumps(body, allow_nan=False, indent=4).encode("utf-8")
                content_type_out = "application/json"
            case (_, None) if isinstance(body, str):
                body_out = body.encode("utf-8")
                content_type_out = "text/plain; charset=utf-8"
            case (_, None) if isinstance(body, (dict, list)):
                body_out = json.dumps(body, allow_nan=False, indent=4).encode("utf-8")
                content_type_out = "application/json"
            case (_, _):
                body_out = body
                content_type_out = content_type

        return (body_out, content_type_out)

    @staticmethod
    def __new__(cls, action_handler: "ActionHandler", *args: Any, **kwargs: Any) -> "Controller":
        if cls is Controller:
            raise TypeError("Only children of the Controller class may be instantiated")
        return super(Controller, cls).__new__(cls, *args, **kwargs)

    def __init__(self, action_handler: "ActionHandler") -> None:
        self._action_handler: "ActionHandler" = action_handler
        self._path_params: Optional[PathParams] = None
        self._query_params: Optional[QueryParams] = None
        self._form_params: Optional[FormParams] = None
        self._json_params: Optional[JSONObjectConvertible] = None
        self._major_version: Optional[int] = None
        self._minor_version: Optional[int] = None

    def send_response(
        self,
        status_code: int = 200,
        status_msg: Optional[str] = None,
        body: Union[JSONObjectConvertible, JSONArrayConvertible, str, Any] = None,
        content_type: Optional[str] = None,
    ) -> None:
        """Sends a response over the active HTTP connection. The caller can choose which parameters to provide and the
        others will be inferred. ``body`` is typically expected to be a ``dict`` or a ``list`` which is convertible to
        JSON, or otherwise a string which will be treated as plain text. This behaviour can be overriden by specifying
        a ``content_type`` other than ``"application/json"``.

        :param status_code: An optional integer representing an HTTP status code (defaults to ``200``)
        :param status_msg: An optional string to be used as the status message (inferred from ``code`` by default)
        :param body: An optional string or JSON-convertible value to use as the response body
        :param content_type: An optional string to use as the MIME type of ``body`` (inferred from ``body`` by default)

        :raises: :class:`TypeError`: A given argument is of an incorrect type
        """

        if not isinstance(status_code, int):
            raise TypeError(f"status code '{status_code}' is not of type int")

        if status_msg and not isinstance(status_msg, str):
            raise TypeError(f"status message '{status_msg}' is not of type str")

        if content_type and not isinstance(content_type, str):
            raise TypeError(f"content_type '{content_type}' is not of type str")

        if not status_msg:
            status_msg = http.client.responses[status_code]

        self.action_handler.set_status(status_code, status_msg)
        body_out, content_type = Controller.prepare_http_body(body, content_type)

        if content_type:
            self.action_handler.set_header("Content-Type", content_type)

        if body_out:
            self.action_handler.write(body_out)

        self.action_handler.finish()

    def respond(
        self,
        code: int = 200,
        status: Optional[str] = None,
        data: Optional[JSONObjectConvertible | JSONArrayConvertible] = None,
    ) -> None:
        """Converts a Python data structure to JSON and wraps it in the following boilerplate JSON object which is
        returned by all v2 endpoints:

        {
            "code": code
            "status": status
            "data": data
        }

        The HTTP status message is inferred from ``code`` and is different from ``status``.

        :param code: An optional integer to use as HTTP status code and include in the JSON response
        :param status: An optional string to include in the JSON response as a status message
        :param data: An optional JSON-convertible value to include in the JSON response as return data

        :raises: :class:`TypeError`: A given argument is of an incorrect type
        """

        if not status:
            status = http.client.responses[code]

        if not data:
            data = {}

        response = {"code": code, "status": status, "results": data}

        self.send_response(status_code=code, body=response)

    def redirect(self, path: str, code: int = 307) -> None:
        """Directs the client to retrieve the requested resource at a different path. Uses a 307 status code by default
        to indicate that the new location may be temporary, but you may wish to override this depending:

            * Use 308 when the condition is permanent and the client should always request the resource at the new path.
            * Use 303 when the client is using a non-GET request method such as POST but should issue the new request
              using GET, such as when redirecting to an endpoint which does not represent the resource acted upon (like
              a confirmation message).
        
        You probably do not want to use a 301 or 302 in most cases, as client behaviour is not reliable and may cause
        security issues in specific edge cases.
        
        :param path: The path or URI to which to redirect
        :param code: An optional integer to use as HTTP status code when performing the redirect (307 by default)

        :raises: :class:`ValueError`: A status code other than 301, 302, 303, 307 or 308 was given
        :raises: :class:`TypeError`: A given argument is of an incorrect type
        """
        if code not in (301, 302, 303, 307, 308):
            raise ValueError(f"{code} is not a valid HTTP status code to indicate a redirect")

        self.action_handler.set_header("Location", path)
        self.send_response(code)

    def log_model_errors(self, model: "BasicModel", logger: "Logger") -> None:
        logger.warning("Data received was not valid because of the following reasons:")

        for field, errors in model.errors.items():
            for msg in errors:
                logger.warning(f"  • {field} {msg}")

    def get_params(self, *param_types: str, ignore_errors: bool = False) -> Params:
        """Fetches all parameters received with the request based on the desired type(s) passed as function arguments.
        For example, ``self.get_params("form", "json")`` will retrieve parameters passed in the body of the request
        whether they are encoded as a form or as a JSON object. If no positional argument is given, all parameters
        (path, query, form and JSON parameters) are returned.

        When two parameters of different types have the same name (e.g., if parameter "id" is given both in the path
        and as a JSON parameter in the request body), then parameters extracted from the path take precedence, then
        parameters given in the request body, and lastly parameters from the URL query string.

        Note that if you wish to retrieve all parameters regardless of type and wish to silently ignore malformed
        parameters, it may be better to use the shorthand ``self.params`` property instead.

        :param *param_types: Any of ``"path"``, ``"query"``, ``"form"``, and/or ``"json"`` (or ``"all"``, the default)
        :param ignore_errors: If ``True``, does not raise when encountering malformed parameters (defaults to ``False``)

        :raises: :class:`ParamDecodeError`: A subset of the requested parameters are malformed

        :returns: A dict containing the request parameters
        """

        # pylint: disable=redefined-outer-name, redefined-builtin

        if "all" in param_types or len(param_types) == 0:
            param_types = ("path", "query", "form", "json")

        params = {}
        failures = []

        for param_type in param_types:
            if param_type not in ("path", "query", "form", "json"):
                raise ValueError(
                    f"Controller.get_params called with '{param_type}' which is not an expected parameter type "
                    f"(only 'path', 'query', 'form', 'json' and 'all' are allowed)"
                )

            try:
                params[param_type] = getattr(self, f"{param_type}_params")
            except ParamDecodeError:
                failures.append(param_type)

        if failures and not ignore_errors:
            list = ", ".join(failures)
            list = " and".join(list.rsplit(",", 1))
            raise ParamDecodeError(f"{list} parameters received in the request were malformed")

        return {**params["query"], **params["form"], **params["json"], **params["path"]}

    @property
    def action_handler(self) -> "ActionHandler":
        return self._action_handler

    @property
    def request_body(self) -> bytes:
        return self.action_handler.request.body

    @property
    def path(self) -> str:
        return self.action_handler.request.path

    @property
    def path_params(self) -> PathParams:
        if not self._path_params:
            if self.action_handler.matching_route:
                path_params = self.action_handler.matching_route.capture_params(self.path)
                # Note: At this point, the parameters defined by the route will have previously been extracted from the
                # path in order to route the request to the controller + action, so if capture_params raises an
                # exception here, this would be an unexpected error which should be processed by the default handler
            else:
                path_params = {}

            # Protect the params dictionary from editing with MappingProxyType before saving in the object and returning
            self._path_params = MappingProxyType(path_params)

        return self._path_params

    @property
    def query_params(self) -> QueryParams:
        """
        :raises: :class:`ParamDecodeError`: URL query string data is malformed
        """
        if not self._query_params:
            query_params = Controller.decode_url_query(self.action_handler.request.query)
            self._query_params = MappingProxyType(query_params)

        return self._query_params

    @property
    def form_params(self) -> FormParams:
        """
        :raises: :class:`ParamDecodeError`: form data is malformed
        """
        if not self._form_params:
            content_type = self.action_handler.request.headers.get("Content-Type")
            form_params: Mapping[str, Union[str, bytes, Sequence[str | bytes]]] = {}

            if content_type and content_type.startswith("application/x-www-form-urlencoded"):
                form_params = Controller.decode_url_query(self.request_body)
            elif content_type and content_type.startswith("multipart/form-data"):
                form_params = Controller.decode_multipart_form(content_type, self.request_body)

            # If the request's Content-Type is neither application/x-www-form-urlencoded nor multipart/form-data,
            # form_params is left blank

            self._form_params = MappingProxyType(form_params)

        return self._form_params

    @property
    def json_params(self) -> JSONObjectConvertible:
        """
        :raises: :class:`ParamDecodeError`: body JSON data is malformed
        """
        if not self._json_params:
            content_type = self.action_handler.request.headers.get("Content-Type")
            json_params = {}

            if content_type and content_type.startswith("application/json"):
                try:
                    json_content = json.loads(self.request_body)
                except json.JSONDecodeError as err:
                    raise ParamDecodeError("request body not interpretable as valid JSON") from err

                if isinstance(json_content, dict):
                    json_params = json_content

            # If the request's Content-Type is neither application/json nor multipart/form-data, or if the request body
            # contains a JSON array instead of a JSON object, json_params is left blank

            self._json_params = MappingProxyType(json_params)

        return self._json_params

    @property
    def params(self) -> Params:
        """Fetches all parameters received with the request regardless of type. In the event that the same parameter is
        defined in multiple parts of the request, parameters extracted from the path take precedence, then parameters
        given in the request body (as a JSON object or a form), and lastly parameters from the URL query string.

        Note that unlike the more flexible ``self.get_params`` method and the specific properties for accessing
        parameters based on type (``self.path_params``, ``self.json_params``, etc.), this property does not raise an
        exception if parameters are malformed and cannot be decoded. In such case, the malformed parameters are simply
        not added to returned dict of parameters.

        :returns: A dict containing the request parameters
        """
        return self.get_params(ignore_errors=True)

    @property
    def major_version(self) -> Optional[int]:
        """Extracts the major API version from the path, if present. E.g., if the path being handled starts with
        "/v2.0", "/v2.5" or "/v2", this method will return ``2``.
        """
        if not self._major_version:
            result = Controller.VERSION_REGEX.match(self.path)

            try:
                major_version = int(result.group(1)) if result else None
            except (TypeError, ValueError):
                major_version = None

            self._major_version = major_version

        return self._major_version

    @property
    def minor_version(self) -> Optional[int]:
        """Extracts the minor API version from the path, if present. E.g., if the path being handled starts with
        "/v2.0", this method will return ``0``. If the path starts with "/v2" instead, the method will return ``None``.
        """
        if not self._major_version:
            result = Controller.VERSION_REGEX.match(self.path)

            try:
                minor_version = int(result.group(2)) if result else None
            except (TypeError, ValueError):
                minor_version = None

            self._minor_version = minor_version

        return self._minor_version
