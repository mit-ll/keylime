import http.client
import os
import re
import ssl
import sys
import tempfile
import urllib.parse
from http.server import BaseHTTPRequestHandler

import tornado.web

from keylime import api_version as keylime_api_version
from keylime import ca_util, config, json, secure_mount


def get_tls_dir(component):
    # Get the values from the configuration file
    tls_dir = config.get(component, "tls_dir")

    if not tls_dir:
        raise Exception(f"The 'tls_dir' option is not set for '{component}'")

    if tls_dir == "generate":
        if component == "verifier":
            generatedir = "cv_ca"
        elif component == "registrar":
            generatedir = "reg_ca"
        else:
            raise Exception(f"The tls_dir=generate option is not supported for " f"'{component}'")

        tls_dir = os.path.abspath(os.path.join(config.WORK_DIR, generatedir))
    elif tls_dir == "default":
        if component in ("verifier", "registrar", "tenant"):
            # Use the keys/certificates generated for the verifier
            tls_dir = os.path.abspath(os.path.join(config.WORK_DIR, "cv_ca"))
        elif component == "agent":
            # For the agent, use the secure mount dir as the default directory
            tls_dir = secure_mount.get_secdir()
    else:
        # if it is relative path, convert to absolute in WORK_DIR
        if tls_dir[0] != "/":
            tls_dir = os.path.abspath(os.path.join(config.WORK_DIR, tls_dir))

    return tls_dir


def init_tls_dir(component, logger=None):
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
            options = [
                "server_cert",
                "server_key",
                "trusted_client_ca",
                "client_cert",
                "client_key",
                "trusted_server_ca",
            ]
        elif component == "registrar":
            generatedir = "reg_ca"
            options = ["server_cert", "server_key", "trusted_client_ca"]
        else:
            raise Exception(f"The tls_dir=generate option is not supported for " f"'{component}'")

        tls_dir = os.path.abspath(os.path.join(config.WORK_DIR, generatedir))
        ca_path = os.path.join(tls_dir, "cacert.crt")

        if os.path.exists(ca_path):
            if logger:
                logger.info("Existing CA certificate found in %s, not generating a new one", tls_dir)
            return tls_dir

        for option in options:
            value = config.get(component, option)
            if value != "default":
                raise Exception(f"To use tls_dir=generate, the following options must be set to 'default': {options}")

        if logger:
            logger.info("Generating new CA, keys, and certificates in %s", tls_dir)
            logger.info("use keylime_ca -d %s to manage this CA", tls_dir)

        if not os.path.exists(tls_dir):
            os.makedirs(tls_dir, 0o700)

        ca_util.cmd_init(tls_dir)
        ca_util.cmd_mkcert(tls_dir, "server")

        if component == "verifier":
            # The verifier also needs client key/certificate to access the agent
            ca_util.cmd_mkcert(tls_dir, "client")

    elif tls_dir == "default":
        # Use the keys/certificates generated for the verifier
        tls_dir = os.path.abspath(os.path.join(config.WORK_DIR, "cv_ca"))
        if not os.path.exists(os.path.join(tls_dir, "cacert.crt")):
            raise Exception(
                "It appears that the verifier has not yet created a CA and certificates, please run the verifier first"
            )
    else:
        # if it is relative path, convert to absolute in WORK_DIR
        if tls_dir[0] != "/":
            tls_dir = os.path.abspath(os.path.join(config.WORK_DIR, tls_dir))

    return tls_dir


def generate_tls_context(
    certificate,
    private_key,
    trusted_ca,
    verify_peer_cert=True,
    is_client=False,
    ca_cert_string=None,
    logger=None,
):
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

        context.load_cert_chain(certfile=certificate, keyfile=private_key)

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


def get_tls_options(component, is_client=False, logger=None):
    """
    Get the TLS key and certificates to use for the given component

    Gets the key, certificate, and the list of trusted CA certificates and
    returns as a tuple. Returns also a Boolean indicating if the peer
    certificate should be verified.

    :returns: A tuple in format (certificate, private key, list
    of trusted CA certificates) and a Boolean indicating if the peer certificate
    should be verified
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

    trusted_ca = config.get(component, ca_option)
    if not trusted_ca:
        if logger:
            logger.warning(f"No value provided in {ca_option} for {component}")
        trusted_ca = []
    elif trusted_ca == "default":
        ca_path = os.path.abspath(os.path.join(tls_dir, "cacert.crt"))
        trusted_ca = [ca_path]
    elif trusted_ca == "all":
        # The 'all' keyword disables peer certificate verification
        verify_peer_certificate = False
        trusted_ca = []
    else:
        trusted_ca = config.getlist(component, ca_option)
        absolute_ca = []
        for ca in trusted_ca:
            if not os.path.isabs(ca):
                ca = os.path.join(tls_dir, ca)
            absolute_ca.append(ca)
        trusted_ca = absolute_ca

    cert = config.get(component, f"{role}_cert")
    if not cert:
        cert = None
        if logger:
            logger.warning(f"No value provided in {role}_cert option for {component}")
    elif cert == "default":
        cert = os.path.abspath(os.path.join(tls_dir, f"{role}-cert.crt"))
    else:
        if not os.path.isabs(cert):
            cert = os.path.abspath(os.path.join(tls_dir, cert))

    key = config.get(component, f"{role}_key")
    if not key:
        if logger:
            logger.warning(f"No value provided in {role}_key option for {component}")
        key = None
    elif key == "default":
        key = os.path.abspath(os.path.join(tls_dir, f"{role}-private.pem"))
    else:
        if not os.path.isabs(key):
            key = os.path.join(tls_dir, key)

    return (cert, key, trusted_ca), verify_peer_certificate


def generate_agent_tls_context(component, cert_blob, logger=None):
    """
    Setups a TLS SSLContext object to connect to an agent.

    Get the TLS key and certificates to use for the given component

    :returns: A client TLS SSLContext to access the agent
    """

    # Check if the client certificate verification is enabled
    agent_mtls_enabled = config.getboolean(component, "enable_agent_mtls")
    if not agent_mtls_enabled:
        return None

    (cert, key, trusted_ca), verify_server = get_tls_options(component, is_client=True, logger=logger)

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
            cert, key, trusted_ca, verify_peer_cert=verify_server, is_client=True, logger=logger
        )

    return context


def init_mtls(component, logger=None):
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

    (cert, key, trusted_ca), verify_client = get_tls_options(component, logger=logger)

    # Generate the server TLS context
    return generate_tls_context(cert, key, trusted_ca, verify_peer_cert=verify_client, logger=logger)


def echo_json_response(handler, code, status=None, results=None):
    """Takes a json package and returns it to the user w/ full HTTP headers"""
    if handler is None or code is None:
        return False
    if status is None:
        status = http.client.responses[code]
    if results is None:
        results = {}

    json_res = {"code": code, "status": status, "results": results}
    json_response = json.dumps(json_res)
    json_response = json_response.encode("utf-8")

    if isinstance(handler, BaseHTTPRequestHandler):
        handler.send_response(code)
        handler.send_header("Content-Type", "application/json")
        handler.end_headers()
        handler.wfile.write(json_response)
        return True
    if isinstance(handler, tornado.web.RequestHandler):
        handler.set_status(code)
        handler.set_header("Content-Type", "application/json")
        handler.write(json_response)
        handler.finish()
        return True

    return False


def get_restful_params(urlstring):
    """Returns a dictionary of paired RESTful URI parameters"""
    parsed_path = urllib.parse.urlsplit(urlstring.strip("/"))
    query_params = urllib.parse.parse_qsl(parsed_path.query)
    path_tokens = parsed_path.path.split("/")

    # If first token looks like an API version, validate it and make sure it's supported
    api_version = 0
    if path_tokens[0] and len(path_tokens[0]) >= 0 and re.match(r"^v?[0-9]+(\.[0-9]+)?", path_tokens[0]):
        version = keylime_api_version.normalize_version(path_tokens[0])

        if keylime_api_version.is_supported_version(version):
            api_version = version

        path_tokens.pop(0)

    path_params = _list_to_dict(path_tokens)
    path_params["api_version"] = api_version
    path_params.update(query_params)
    return path_params


def validate_api_version(handler, version, logger):
    if not version or not keylime_api_version.is_supported_version(version):
        echo_json_response(handler, 400, "API Version not supported")
        return False

    if keylime_api_version.is_deprecated_version(version):
        logger.warning(
            "Client request to API version %s is deprecated and will be removed in future versions.", version
        )
    return True


def _list_to_dict(alist):
    """Convert list into dictionary via grouping [k0,v0,k1,v1,...]"""
    params = {}
    i = 0
    while i < len(alist):
        params[alist[i]] = alist[i + 1] if (i + 1) < len(alist) else None
        i = i + 2
    return params
