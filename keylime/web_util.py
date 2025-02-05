import http.client
import os
import re
import ssl
import sys
import tempfile
import urllib.parse
from http.server import BaseHTTPRequestHandler
from logging import Logger
from typing import Any, Dict, List, Optional, Tuple, Union

import tornado.web

from keylime import api_version as keylime_api_version
from keylime import ca_util, config, json
from keylime.api_version import VersionType


def get_tls_dir(component: str) -> str:
    # Get the values from the configuration file
    tls_dir = config.get(component, "tls_dir")

    if not tls_dir:
        raise Exception(f"The 'tls_dir' option is not set for '{component}'")

    if tls_dir == "generate":
        if component == "verifier":
            generatedir = "cv_ca"
        elif component == "registrar":
            generatedir = "reg_ca"
        elif component == "tenant":
            generatedir = "ten_ca"
        else:
            raise Exception(f"The tls_dir=generate option is not supported for " f"'{component}'")

        tls_dir = os.path.abspath(os.path.join(config.WORK_DIR, generatedir))
    elif tls_dir == "default":
        if component in ("verifier", "registrar", "tenant"):
            # Use the keys/certificates generated for the verifier
            tls_dir = os.path.abspath(os.path.join(config.WORK_DIR, "cv_ca"))
    else:
        # if it is relative path, convert to absolute in WORK_DIR
        tls_dir = os.path.abspath(os.path.join(config.WORK_DIR, tls_dir))

    return tls_dir


def init_tls_dir(component: str, logger: Optional[Logger] = None) -> str:
    """
    Init the TLS directory, generating keys and certificates if requested
    """

    # Get the values from the configuration file
    tls_dir = config.get(component, "tls_dir")

    if not tls_dir:
        raise Exception(f"The 'tls_dir' option is not set for '{component}'")
    if tls_dir == "generate":
        if component == "verifier":
            generatedir = "cv_ca"
            # options = [
            #     "server_cert",
            #     "server_key",
            #     "trusted_client_ca",
            #     "client_cert",
            #     "client_key",
            #     "trusted_server_ca",
            # ]
        elif component == "registrar":
            generatedir = "reg_ca"
            # options = ["server_cert", "server_key", "trusted_client_ca"]
        else:
            raise Exception(f"The tls_dir=generate option is not supported for " f"'{component}'")

        tls_dir = os.path.abspath(os.path.join(config.WORK_DIR, generatedir))
        ca_path = os.path.join(tls_dir, "cacert.crt")

        ca_util.read_password(component, None)

        if os.path.exists(ca_path):
            if logger:
                logger.info("Existing CA certificate found in %s, not generating a new one", tls_dir)
        else:
            if logger:
                logger.info("Generating new CA, keys, and certificates in %s", tls_dir)
                logger.info("use keylime_ca -d %s to manage this CA", tls_dir)

            if not os.path.exists(tls_dir):
                os.makedirs(tls_dir, 0o700)

            ca_util.cmd_init(component, tls_dir)

        # Check if all options are set as "default"
        # for option in options:
        #     value = config.get(component, option)
        #     if value != "default":
        #         raise Exception(f"To use tls_dir=generate, the following options must be set to 'default': {options}")

        server_key_path = os.path.join(tls_dir, "server-private.pem")
        server_cert_path = os.path.join(tls_dir, "server-cert.crt")

        # The server key and certificate are already present, do not generate new ones
        if os.path.exists(server_key_path) and os.path.exists(server_cert_path):
            if logger:
                logger.debug("Existing server certificate and key found in %s, not generating a new ones", tls_dir)
        else:
            server_key_pw = config.get(component, "server_key_password")
            if server_key_pw:
                server_key_pw = str(server_key_pw)
            ca_util.cmd_mkcert(component, tls_dir, "server", password=server_key_pw)

        # For the verifier, generate client key and certificate if not present
        if component == "verifier":
            client_key_path = os.path.join(tls_dir, "client-private.pem")
            client_cert_path = os.path.join(tls_dir, "client-cert.crt")

            # The client key and certificate are already present, do not generate new ones
            if os.path.exists(client_key_path) and os.path.exists(client_cert_path):
                if logger:
                    logger.debug("Existing client certificate and key found in %s, not generating a new ones", tls_dir)
            else:
                client_key_pw = config.get(component, "client_key_password")
                if client_key_pw:
                    client_key_pw = str(client_key_pw)
                ca_util.cmd_mkcert(component, tls_dir, "client", password=client_key_pw)

    elif tls_dir == "default":
        # Use the keys/certificates generated for the verifier
        tls_dir = os.path.abspath(os.path.join(config.WORK_DIR, "cv_ca"))
        if not os.path.exists(tls_dir):
            raise Exception(f"It appears that the specified tls_dir does not exist: {tls_dir}")
    else:
        # if it is relative path, convert to absolute in WORK_DIR
        tls_dir = os.path.abspath(os.path.join(config.WORK_DIR, tls_dir))

    return tls_dir


def generate_tls_context(
    certificate: Optional[str],
    private_key: Optional[str],
    trusted_ca: List[str],
    private_key_password: Optional[str] = None,
    verify_peer_cert: bool = True,
    is_client: bool = False,
    ca_cert_string: Optional[str] = None,
    logger: Optional[Logger] = None,
) -> ssl.SSLContext:
    """
    Generate the TLS context

    If 'is_client' is True, a client side context will be generated.  If
    'verify_peer_cert' is True, the peer certificate will be required.
    """

    if not certificate:
        if logger:
            logger.error("Failed to generate TLS context: certificate not provided")
        raise Exception("Failed to generate TLS context: certificate not provided")

    if not private_key:
        if logger:
            logger.error("Failed to generate TLS context: private key not provided")
        raise Exception("Failed to generate TLS context: private key not provided")

    if is_client:
        # The context to be generated is for the client side. Set the purpose of
        # the CA certificates to be SERVER_AUTH
        ssl_purpose = ssl.Purpose.SERVER_AUTH
    else:
        # The context to be generated is for the server side. Set the purpose of
        # the CA certificates to be CLIENT_AUTH
        ssl_purpose = ssl.Purpose.CLIENT_AUTH

    try:
        context = ssl.create_default_context(ssl_purpose)
        context.check_hostname = False  # We do not use hostnames as part of our authentication
        if sys.version_info >= (3, 7):
            context.minimum_version = ssl.TLSVersion.TLSv1_2  # pylint: disable=E1101
        else:
            context.options &= ~ssl.OP_NO_TLSv1_2

        context.load_cert_chain(certfile=certificate, keyfile=private_key, password=private_key_password)

        if verify_peer_cert:
            if not trusted_ca and not ca_cert_string:
                if logger:
                    logger.error("Peer certificate verification is enabled, but no CA certificate was provided")
                    raise Exception("Peer certificate verification is enabled, but no CA certificate was provided")

            # Load CA certificates if the peer certificate verification is
            # requested
            for ca in trusted_ca:
                context.load_verify_locations(cafile=ca)

            # If a CA certificate was provided as a PEM encoded string (which is
            # the case for the agent mTLS self signed certificate), write it
            # temporarily to a file to load into the context
            if ca_cert_string:
                with tempfile.TemporaryDirectory(prefix="keylime_") as temp_dir:
                    temp_file = os.path.join(temp_dir, "agent.crt")
                    with open(temp_file, "w", encoding="utf-8") as f:
                        f.write(ca_cert_string)

                    context.load_verify_locations(cafile=temp_file)

            context.verify_mode = ssl.CERT_REQUIRED

    except ssl.SSLError as exc:
        if exc.reason == "EE_KEY_TOO_SMALL" and logger:
            logger.error(
                "Higher key strength is required for keylime "
                "running on this system. If keylime is responsible "
                "to generate the certificate, please raise the value "
                "of configuration option [ca]cert_bits, remove "
                "generated certificate and re-run keylime service"
            )
        raise exc

    return context


def get_tls_options(
    component: str, is_client: bool = False, logger: Optional[Logger] = None
) -> Tuple[Tuple[Optional[str], Optional[str], List[str], Optional[str]], bool]:
    """
    Get the TLS key and certificates to use for the given component

    Gets the key, certificate, and the list of trusted CA certificates and
    returns as a tuple. Returns also a Boolean indicating if the peer
    certificate should be verified.

    :returns: A tuple in format (certificate, private key, list
    of trusted CA certificates, key password) and a Boolean indicating if the
    peer certificate should be verified
    """

    tls_dir = get_tls_dir(component)

    if is_client:
        role = "client"
        ca_option = "trusted_server_ca"
    else:
        role = "server"
        ca_option = "trusted_client_ca"

    # Peer certificate verification is enabled by default
    verify_peer_certificate = True

    config_trusted_ca = config.get(component, ca_option)
    if not config_trusted_ca:
        if logger:
            logger.warning(f"No value provided in {ca_option} for {component}")
        trusted_ca = []
    elif config_trusted_ca == "default":
        # tls_dir takes into account if the CA certificate was generated or if
        # the CA certificate generated by the verifier should be used
        ca_path = os.path.abspath(os.path.join(tls_dir, "cacert.crt"))
        trusted_ca = [ca_path]
    elif config_trusted_ca == "all":
        # The 'all' keyword disables peer certificate verification
        verify_peer_certificate = False
        trusted_ca = []
    else:
        trusted_ca = config.getlist(component, ca_option)
        trusted_ca = list(os.path.abspath(os.path.join(tls_dir, ca)) for ca in trusted_ca)

    config_cert = config.get(component, f"{role}_cert")
    if not config_cert:
        cert = None
        if logger:
            logger.warning("No value provided in %s_cert option for %s", role, component)
    elif config_cert == "default":
        cert = os.path.abspath(os.path.join(tls_dir, f"{role}-cert.crt"))
        if logger:
            logger.info("Using default %s_cert option for %s", role, component)
    else:
        cert = os.path.abspath(os.path.join(tls_dir, config_cert))

    config_key = config.get(component, f"{role}_key")
    if not config_key:
        if logger:
            logger.warning("No value provided in %s_key option for %s", role, component)
        key = None
    elif config_key == "default":
        key = os.path.abspath(os.path.join(tls_dir, f"{role}-private.pem"))
        if logger:
            logger.info("Using default %s_key option for %s", role, component)
    else:
        key = os.path.join(tls_dir, config_key)

    config_password = config.get(component, f"{role}_key_password")
    if not config_password:
        if logger:
            logger.info(
                "No value provided in %s_key_password option for %s, assuming the key is unencrypted",
                role,
                component,
            )
        password = None
    else:
        password = config_password

    return (cert, key, trusted_ca, password), verify_peer_certificate


def generate_agent_tls_context(
    component: str, cert_blob: str, logger: Optional[Logger] = None
) -> Optional[ssl.SSLContext]:
    """
    Setups a TLS SSLContext object to connect to an agent.

    Get the TLS key and certificates to use for the given component

    :returns: A client TLS SSLContext to access the agent
    """

    # Check if the client certificate verification is enabled
    agent_mtls_enabled = config.getboolean(component, "enable_agent_mtls")
    if not agent_mtls_enabled:
        return None

    (cert, key, trusted_ca, key_password), verify_server = get_tls_options(component, is_client=True, logger=logger)

    context = None

    if not verify_server:
        if logger:
            logger.warning(
                "'enable_agent_mtls' is 'True', but 'trusted_server_ca' is set as 'all', which disables server certificate verification"
            )

    with tempfile.TemporaryDirectory(prefix="keylime_") as tmp_dir:
        agent_cert_file = os.path.abspath(os.path.join(tmp_dir, "agent.crt"))
        with open(agent_cert_file, "wb") as f:
            f.write(cert_blob.encode())

        # Add the self-signed certificate provided by the agent to be trusted
        trusted_ca.append(agent_cert_file)

        context = generate_tls_context(
            cert,
            key,
            trusted_ca,
            private_key_password=key_password,
            verify_peer_cert=verify_server,
            is_client=True,
            logger=logger,
        )

    return context


def init_mtls(component: str, logger: Optional[Logger] = None) -> ssl.SSLContext:
    """
    Initialize the server TLS context following the configuration options.

    Depending on the options set by the configuration files, generates the CA,
    client, and server certificates.

    :return: Returns the TLS contexts for the server
    """

    if logger:
        logger.info("Setting up TLS...")

    # Initialize the TLS directory, generating keys and certificates if
    # requested
    _ = init_tls_dir(component, logger=logger)

    (cert, key, trusted_ca, pw), verify_client = get_tls_options(component, logger=logger)

    # Generate the server TLS context
    return generate_tls_context(
        cert, key, trusted_ca, private_key_password=pw, verify_peer_cert=verify_client, logger=logger
    )


def echo_json_response(
    handler: Any, code: int, status: Optional[str] = None, results: Optional[Dict[str, Any]] = None
) -> bool:
    """Takes a json package and returns it to the user w/ full HTTP headers"""
    if handler is None:
        return False
    if status is None:
        status = http.client.responses[code]
    if results is None:
        results = {}

    json_res = {"code": code, "status": status, "results": results}
    json_response = json.dumps(json_res)
    json_response_bytes = json_response.encode("utf-8")

    if isinstance(handler, BaseHTTPRequestHandler):
        handler.send_response(code)
        handler.send_header("Content-Type", "application/json")
        handler.end_headers()
        handler.wfile.write(json_response_bytes)
        return True
    if isinstance(handler, tornado.web.RequestHandler):
        handler.set_status(code)
        handler.set_header("Content-Type", "application/json")
        handler.write(json_response_bytes)
        handler.finish()
        return True

    return False


def get_restful_params(urlstring: str) -> Dict[str, Union[str, None]]:
    """Returns a dictionary of paired RESTful URI parameters"""
    parsed_path = urllib.parse.urlsplit(urlstring.strip("/"))
    query_params = urllib.parse.parse_qsl(parsed_path.query)
    path_tokens = parsed_path.path.split("/")

    # If first token looks like an API version, validate it and make sure it's supported
    api_version = "0"
    if path_tokens[0] and re.match(r"^v?[0-9]+(\.[0-9]+)?", path_tokens[0]):
        version = keylime_api_version.normalize_version(path_tokens[0])

        if keylime_api_version.is_supported_version(version):
            api_version = version

        path_tokens.pop(0)

    path_params = _list_to_dict(path_tokens)
    path_params["api_version"] = api_version
    path_params.update(query_params)
    return path_params


def validate_api_version(handler: Any, version: VersionType, logger: Logger) -> bool:
    if not version or not keylime_api_version.is_supported_version(version):
        echo_json_response(handler, 400, "API Version not supported")
        return False

    if keylime_api_version.is_deprecated_version(version):
        logger.warning(
            "Client request to API version %s is deprecated and will be removed in future versions.", version
        )
    return True


def _list_to_dict(alist: List[str]) -> Dict[str, Union[str, None]]:
    """Convert list into dictionary via grouping [k0,v0,k1,v1,...]"""
    params = {}
    i = 0
    while i < len(alist):
        params[alist[i]] = alist[i + 1] if (i + 1) < len(alist) else None  # FIXME: Can use "" instead?
        i = i + 2
    return params
