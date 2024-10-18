import base64
import http.server
import ipaddress
import os
import select
import signal
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import IPv6Address, ip_address
from socketserver import ThreadingMixIn
from typing import Any, Dict, Optional, Tuple, Union, cast

import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm.exc import NoResultFound  # pyright: ignore

from keylime import api_version as keylime_api_version
from keylime import cert_utils, config, crypto, json, keylime_logging, web_util
from keylime.common import validators
from keylime.da import record
from keylime.db.keylime_db import DBEngineManager, SessionManager
from keylime.db.registrar_db import RegistrarMain
from keylime.tpm import tpm2_objects
from keylime.tpm.tpm_main import Tpm

logger = keylime_logging.init_logging("registrar")


try:
    engine = DBEngineManager().make_engine("registrar")
except SQLAlchemyError as err:
    logger.error("Error creating SQL engine: %s", err)
    sys.exit(1)

try:
    rmc = record.get_record_mgt_class(config.get("registrar", "durable_attestation_import", fallback=""))
    if rmc:
        rmc = rmc("registrar")
except record.RecordManagementException as rme:
    logger.error("Error initializing Durable Attestation: %s", rme)
    sys.exit(1)


class BaseHandler(BaseHTTPRequestHandler, SessionManager):
    def _validate_input(
        self, method: str, respond_on_agent_id_none: bool
    ) -> Tuple[Optional[Dict[str, Union[str, None]]], Optional[str]]:
        rest_params = web_util.get_restful_params(self.path)
        if rest_params is None:
            web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface")
            return None, None

        if not web_util.validate_api_version(self, cast(str, rest_params["api_version"]), logger):
            return None, None

        if "agents" not in rest_params:
            web_util.echo_json_response(self, 400, "URI not supported")
            logger.warning("%s agent returning 400 response. uri not supported: %s", method, self.path)
            return None, None

        agent_id = rest_params["agents"]

        if agent_id is None:
            if respond_on_agent_id_none:
                web_util.echo_json_response(self, 400, "agent id not found in uri")
                logger.warning("%s agent returning 400 response. agent id not found in uri %s", method, self.path)
            return rest_params, None

        # If the agent ID is not valid (wrong set of characters), just do nothing.
        if not validators.valid_agent_id(agent_id):
            web_util.echo_json_response(self, 400, "agent_id is not valid")
            logger.error("%s received an invalid agent ID: %s", method, agent_id)
            return None, None

        return rest_params, agent_id


class ProtectedHandler(BaseHandler):
    def handle(self) -> None:
        """Need to perform SSL handshake here, as
        do_handshake_on_connect=False for non-blocking SSL socket"""
        while True:
            try:
                self.request.do_handshake()
                break
            except ssl.SSLWantReadError:
                select.select([self.request], [], [])
            except ssl.SSLWantWriteError:
                select.select([], [self.request], [])
            except ssl.SSLError as e:
                logger.error("SSL connection error: %s", e)
                return
            except Exception as e:
                logger.error("General communication failure: %s", e)
                return
        BaseHTTPRequestHandler.handle(self)

    def do_HEAD(self) -> None:
        """HEAD not supported"""
        web_util.echo_json_response(self, 405, "HEAD not supported")

    def do_PATCH(self) -> None:
        """PATCH not supported"""
        web_util.echo_json_response(self, 405, "PATCH not supported")

    def do_GET(self) -> None:
        """This method handles the GET requests to retrieve status on agents from the Registrar Server.

        Currently, only agents resources are available for GETing, i.e. /agents. All other GET uri's
        will return errors. agents requests require a single agent_id parameter which identifies the
        agent to be returned. If the agent_id is not found, a 404 response is returned.
        """
        session = SessionManager().make_session(engine)

        rest_params, agent_id = self._validate_input("GET", False)
        if not rest_params:
            return

        if agent_id is not None:
            try:
                agent = session.query(RegistrarMain).filter_by(agent_id=agent_id).first()
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                return

            if agent is None:
                web_util.echo_json_response(self, 404, f"agent {agent_id} not found")
                logger.warning("GET returning 404 response. agent %s not found.", agent_id)
                return

            if not bool(agent.active):
                web_util.echo_json_response(self, 404, f"agent {agent_id} not yet active")
                logger.warning("GET returning 404 response. agent %s not yet active.", agent_id)
                return

            response = {
                "aik_tpm": agent.aik_tpm,
                "ek_tpm": agent.ek_tpm,
                "ekcert": agent.ekcert,
                "ek_ca_chain": agent.ek_ca_chain,
                "mtls_cert": agent.mtls_cert,
                "ip": agent.ip,
                "port": agent.port,
                "regcount": agent.regcount,
            }

            if agent.virtual:  # pyright: ignore
                response["provider_keys"] = agent.provider_keys

            web_util.echo_json_response(self, 200, "Success", response)
            logger.info("GET returning 200 response for agent_id: %s", agent_id)
        else:
            # return the available registered uuids from the DB
            json_response = session.query(RegistrarMain.agent_id).all()
            return_response = [item[0] for item in json_response]
            web_util.echo_json_response(self, 200, "Success", {"uuids": return_response})
            logger.info("GET returning 200 response for agent_id list")

        return

    def do_POST(self) -> None:
        """POST not supported"""
        web_util.echo_json_response(self, 405, "POST not supported via TLS interface")

    def do_PUT(self) -> None:
        """PUT not supported"""
        web_util.echo_json_response(self, 405, "PUT not supported via TLS interface")

    def do_DELETE(self) -> None:
        """This method handles the DELETE requests to remove agents from the Registrar Server.

        Currently, only agents resources are available for DELETEing, i.e. /agents. All other DELETE uri's will return errors.
        agents requests require a single agent_id parameter which identifies the agent to be deleted.
        """
        session = SessionManager().make_session(engine)

        rest_params, agent_id = self._validate_input("DELETE", False)
        if not rest_params:
            return

        if agent_id is not None:
            if session.query(RegistrarMain).filter_by(agent_id=agent_id).delete():
                # send response
                try:
                    session.commit()
                except SQLAlchemyError as e:
                    logger.error("SQLAlchemy Error: %s", e)
                web_util.echo_json_response(self, 200, "Success")
                return

            # send response
            web_util.echo_json_response(self, 404)
            return

        web_util.echo_json_response(self, 404)

    # pylint: disable=W0622
    def log_message(self, format: str, *args: Any) -> None:
        return


class UnprotectedHandler(BaseHandler):
    def do_HEAD(self) -> None:
        """HEAD not supported"""
        web_util.echo_json_response(self, 405, "HEAD not supported")

    def do_PATCH(self) -> None:
        """PATCH not supported"""
        web_util.echo_json_response(self, 405, "PATCH not supported")

    def do_GET(self) -> None:
        """This method handles the GET requests to the unprotected side of the Registrar Server

        Currently the only supported path is /versions which shows the supported API versions
        """
        rest_params = web_util.get_restful_params(self.path)
        if rest_params is None:
            web_util.echo_json_response(self, 405, "Not Implemented: Use /version/ interface")
            return

        if "version" not in rest_params:
            web_util.echo_json_response(self, 400, "URI not supported")
            logger.warning("GET agent returning 400 response. URI not supported: %s", self.path)
            return

        version_info = {
            "current_version": keylime_api_version.current_version(),
            "supported_versions": keylime_api_version.all_versions(),
        }

        web_util.echo_json_response(self, 200, "Success", version_info)

    @staticmethod
    def get_network_params(
        json_body: Dict[str, Any], agent_id: str
    ) -> Tuple[Optional[str], Optional[int], Optional[str]]:
        # Validate ip and port
        ip = json_body.get("ip")
        if ip is not None:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                logger.warning("Contact ip for agent %s is not a valid ip got: %s.", agent_id, ip)
                ip = None

        port = json_body.get("port")
        if port is not None:
            try:
                port = int(port)
                if port < 1 or port > 65535:
                    logger.warning(
                        "Contact port for agent %s is not a number between 1 and 65535 got: %s.", agent_id, port
                    )
                    port = None
            except ValueError:
                logger.warning("Contact port for agent %s is not a valid number got: %s.", agent_id, port)
                port = None

        mtls_cert = json_body.get("mtls_cert")
        if mtls_cert is None or mtls_cert == "disabled":
            logger.warning("Agent %s did not send a mTLS certificate. Most operations will not work!", agent_id)

        return ip, port, mtls_cert

    def do_POST(self) -> None:
        """This method handles the POST requests to add agents to the Registrar Server.

        Currently, only agents resources are available for POSTing, i.e. /agents. All other POST uri's
        will return errors. POST requests require an an agent_id identifying the agent to add, and json
        block sent in the body with 2 entries: ek and aik.
        """
        session = SessionManager().make_session(engine)

        _, agent_id = self._validate_input("POST", True)
        if not agent_id:
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                web_util.echo_json_response(self, 400, "Expected non zero content length")
                logger.warning("POST for %s returning 400 response. Expected non zero content length.", agent_id)
                return

            post_body = self.rfile.read(content_length)
            json_body = json.loads(post_body)

            ekcert = json_body["ekcert"]
            ek_ca_chain = json_body.get["ek_ca_chain"]
            aik_tpm = json_body["aik_tpm"]
            iak_tpm = b""
            idevid_tpm = b""
            idevid_cert = ""
            iak_cert = ""
            iak_attest = b""
            iak_sign = b""
            tpm_identity = config.get("registrar", "tpm_identity", fallback="default")
            idevid_required = tpm_identity == "iak_idevid"
            ek_required = tpm_identity == "ek_cert"

            # Check cryptography version before iak and idevid checks
            # If idevid is required in config but version is <38.0.0 then stop
            # If idevid is not required and version is <38.0.0, only the ek will be allowed to be used in registration
            if int(cryptography.__version__.split(".", maxsplit=1)[0]) < 38:
                if idevid_required:
                    logger.warning(
                        "IAK and IDevID required in config (tpm_identity) but cryptography version too early (<38.0.0)"
                    )
                    web_util.echo_json_response(self, 400, "Config not compatible with cryptography version")
                    return
                logger.info("Cryptography version <38.0.0 so only EK will be used to register.")
                ek_required = True

            # If IDevID and IAK are required in the config:
            #  -Check if IDevID and IAK are received along with their certificates
            #  -Check if certificates are trusted
            #  -Make sure the agent has generated the same keys as used in the certificates
            idevid_received = False
            if not ek_required and "iak_tpm" in json_body:
                # These would currently just be overwritten by keys in the certs
                # We will want to use them when the option to send from the agent without including certs is added.
                # iak_tpm_pub = tpm2_objects.pubkey_from_tpm2b_public(base64.b64decode(json_body["iak_tpm"]))
                # idevid_tpm_pub = tpm2_objects.pubkey_from_tpm2b_public(base64.b64decode(json_body["idevid_tpm"]))
                iak_attest = base64.b64decode(json_body["iak_attest"])
                iak_sign = base64.b64decode(json_body["iak_sign"])
                logger.info("IDevID and IAK received")
                idevid_cert = json_body["idevid_cert"]
                iak_cert = json_body["iak_cert"]
                idevid_received = True

                # IDevID and IAK cert checks, this requires crypto>=38.0.0
                # Here we are checking the types of keys in the certificates, checking the certs are valid, and checking they are from a TPM
                error, idevid_tpm_pub, iak_tpm_pub = cert_utils.iak_idevid_cert_checks(
                    base64.b64decode(idevid_cert), base64.b64decode(iak_cert), config.get("tenant", "tpm_cert_store")
                )

                if iak_tpm_pub is None or idevid_tpm_pub is None:
                    logger.warning(
                        "POST for %s returning 400 response. Error in IAK and IDevID certificate checks: %s",
                        agent_id,
                        error,
                    )
                    web_util.echo_json_response(self, 400, error)
                    return

                iak_tpm = base64.b64encode(
                    iak_tpm_pub.public_bytes(
                        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                )
                idevid_tpm = base64.b64encode(
                    idevid_tpm_pub.public_bytes(
                        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                )

                # verify AIK and attestation data with IAK if IAK and IDevID received and required
                aik_verified = False
                if idevid_received:
                    aik_verified = Tpm.verify_aik_with_iak(
                        agent_id, base64.b64decode(aik_tpm), iak_tpm, iak_attest, iak_sign
                    )
                if not aik_verified and idevid_required:
                    logger.warning("Agent %s failed to verify AIK with IAK", agent_id)
                    web_util.echo_json_response(self, 400, "Error: failed verifying AK with IAK")
                    return
            elif idevid_required:
                logger.warning("Agent %s did not provide an IDevID/IAK", agent_id)
                web_util.echo_json_response(self, 400, "Error: no IDevID/IAK received")
                return

            if ekcert is None or ekcert == "emulator":
                logger.warning("Agent %s did not submit an ekcert", agent_id)
                ek_tpm = json_body["ek_tpm"]
            else:
                if "ek_tpm" in json_body:
                    # This would mean the agent submitted both a non-None ekcert, *and*
                    #  an ek_tpm... We can deal with it by just ignoring the ek_tpm they sent
                    logger.warning("Overriding ek_tpm for agent %s from ekcert", agent_id)
                # If there's an EKCert, we just overwrite their ek_tpm
                # Note, we don't validate the EKCert here, other than the implicit
                #  "is it a valid x509 cert" check. So it's still untrusted.
                # This will be validated by the tenant.
                cert = cert_utils.x509_der_cert(base64.b64decode(ekcert))
                pubkey = cert.public_key()
                assert isinstance(pubkey, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey))
                ek_tpm = base64.b64encode(tpm2_objects.ek_low_tpm2b_public_from_pubkey(pubkey)).decode()

            aik_attrs = tpm2_objects.get_tpm2b_public_object_attributes(
                base64.b64decode(aik_tpm),
            )
            if aik_attrs != tpm2_objects.AK_EXPECTED_ATTRS:
                web_util.echo_json_response(self, 400, "Invalid AK attributes")
                logger.warning(
                    "Agent %s submitted AIK with invalid attributes! %s (provided) != %s (expected)",
                    agent_id,
                    tpm2_objects.object_attributes_description(aik_attrs),
                    tpm2_objects.object_attributes_description(tpm2_objects.AK_EXPECTED_ATTRS),
                )
                return

            # try to encrypt the AIK
            aik_enc = Tpm.encrypt_aik_with_ek(agent_id, base64.b64decode(ek_tpm), base64.b64decode(aik_tpm))
            if aik_enc is None:
                logger.warning("Agent %s failed encrypting AIK", agent_id)
                web_util.echo_json_response(self, 400, "Error: failed encrypting AK")
                return

            blob, key = aik_enc

            # special behavior if we've registered this uuid before
            regcount = 1
            try:
                agent = session.query(RegistrarMain).filter_by(agent_id=agent_id).first()
            except NoResultFound:
                agent = None
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                raise

            if agent is not None:
                # keep track of how many ek-ekcerts have registered on this uuid
                assert isinstance(agent.regcount, int)
                regcount = agent.regcount
                if agent.ek_tpm != ek_tpm or agent.ekcert != ekcert:  # pyright: ignore
                    logger.warning("WARNING: Overwriting previous registration for this UUID with new ek-ekcert pair!")
                    regcount += 1

                # force overwrite
                logger.info("Overwriting previous registration for this UUID.")
                try:
                    session.query(RegistrarMain).filter_by(agent_id=agent_id).delete()
                    session.commit()
                except SQLAlchemyError as e:
                    logger.error("SQLAlchemy Error: %s", e)
                    raise

            # Check for ip and port and mTLS cert
            contact_ip, contact_port, mtls_cert = UnprotectedHandler.get_network_params(json_body, agent_id)

            # Add values to database
            d: Dict[str, Any] = {
                "agent_id": agent_id,
                "ek_tpm": ek_tpm,
                "aik_tpm": aik_tpm,
                "ekcert": ekcert,
                "ek_ca_chain": ek_ca_chain,
                "iak_tpm": iak_tpm,
                "idevid_tpm": idevid_tpm,
                "iak_cert": iak_cert,
                "idevid_cert": idevid_cert,
                "ip": contact_ip,
                "mtls_cert": mtls_cert,
                "port": contact_port,
                "virtual": int(ekcert == "virtual"),
                "active": int(False),
                "key": key,
                "provider_keys": {},
                "regcount": regcount,
            }

            try:
                session.add(RegistrarMain(**d))
                session.commit()
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                raise

            if rmc:
                try:
                    rmc.record_create(d, None, None)

                except Exception as e:
                    logger.error("Durable Attestation Error: %s", e)
                    raise

            response = {
                "blob": blob,
            }
            web_util.echo_json_response(self, 200, "Success", response)

            logger.info("POST returning key blob for agent_id: %s", agent_id)
        except Exception as e:
            web_util.echo_json_response(self, 400, f"Error: {str(e)}")
            logger.warning("POST for %s returning 400 response. Error: %s", agent_id, e)
            logger.exception(e)

    def do_PUT(self) -> None:
        """This method handles the PUT requests to add agents to the Registrar Server.

        Currently, only agents resources are available for PUTing, i.e. /agents. All other PUT uri's
        will return errors.
        """
        session = SessionManager().make_session(engine)

        _, agent_id = self._validate_input("PUT", True)
        if not agent_id:
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                web_util.echo_json_response(self, 400, "Expected non zero content length")
                logger.warning("PUT for %s returning 400 response. Expected non zero content length.", agent_id)
                return

            post_body = self.rfile.read(content_length)
            json_body = json.loads(post_body)

            auth_tag = json_body["auth_tag"]
            try:
                agent = session.query(RegistrarMain).filter_by(agent_id=agent_id).first()
            except NoResultFound as e:
                raise Exception("attempting to activate agent before requesting " f"registrar for {agent_id}") from e
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                raise

            assert agent
            assert isinstance(agent.key, str)
            ex_mac = crypto.do_hmac(agent.key.encode(), agent_id)
            if ex_mac == auth_tag:
                try:
                    session.query(RegistrarMain).filter(RegistrarMain.agent_id == agent_id).update(  # type: ignore
                        {"active": int(True)}
                    )
                    session.commit()
                except SQLAlchemyError as e:
                    logger.error("SQLAlchemy Error: %s", e)
                    raise
            else:
                if agent_id and session.query(RegistrarMain).filter_by(agent_id=agent_id).delete():
                    try:
                        session.commit()
                    except SQLAlchemyError as e:
                        logger.error("SQLAlchemy Error: %s", e)
                        raise

                raise Exception(
                    f"Auth tag {auth_tag} for agent {agent_id} does not match expected value. The agent has been deleted from database, and a restart of it will be required"
                )

            web_util.echo_json_response(self, 200, "Success")
            logger.info("PUT activated: %s", agent_id)
        except Exception as e:
            web_util.echo_json_response(self, 400, f"Error: {str(e)}")
            logger.warning("PUT for %s returning 400 response. Error: %s", agent_id, e)
            logger.exception(e)
            return

    def do_DELETE(self) -> None:
        """DELETE not supported"""
        web_util.echo_json_response(self, 405, "DELETE not supported")

    # pylint: disable=W0622
    def log_message(self, format: str, *args: Any) -> None:
        return


# consider using PooledProcessMixIn
# https://github.com/muayyad-alsadi/python-PooledProcessMixIn


class RegistrarServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

    def __init__(self, server_address: Tuple[str, int], RequestHandlerClass: Any) -> None:
        """Constructor overridden to provide ability to read file"""
        bindaddr = server_address[0].strip()
        if len(bindaddr) > 0 and isinstance(ip_address(bindaddr), IPv6Address):
            self.address_family = socket.AF_INET6
        http.server.HTTPServer.__init__(self, server_address, RequestHandlerClass)

    def shutdown(self) -> None:
        http.server.HTTPServer.shutdown(self)


def start(host: str, tlsport: int, port: int) -> None:
    """Main method of the Registrar Server.  This method is encapsulated in a function for packaging to allow it to be
    called as a function by an external program."""

    # set a conservative general umask
    os.umask(0o077)

    RegistrarMain.metadata.create_all(engine, checkfirst=True)  # type: ignore
    session = SessionManager().make_session(engine)
    try:
        count = session.query(RegistrarMain.agent_id).count()
        if count > 0:
            logger.info("Loaded %d public keys from database", count)
    except SQLAlchemyError as e:
        logger.error("SQLAlchemy Error: %s", e)

    # Set up the protected registrar server
    protected_server = RegistrarServer((host, tlsport), ProtectedHandler)
    context = web_util.init_mtls("registrar", logger=logger)
    if context is not None:
        protected_server.socket = context.wrap_socket(
            protected_server.socket, server_side=True, do_handshake_on_connect=False
        )
    thread_protected_server = threading.Thread(target=protected_server.serve_forever)

    # Set up the unprotected registrar server
    unprotected_server = RegistrarServer((host, port), UnprotectedHandler)
    thread_unprotected_server = threading.Thread(target=unprotected_server.serve_forever)

    logger.info("Starting Cloud Registrar Server on ports %s and %s (TLS) use <Ctrl-C> to stop", port, tlsport)
    keylime_api_version.log_api_versions(logger)
    thread_protected_server.start()
    thread_unprotected_server.start()

    def signal_handler(signum: int, frame: Any) -> None:
        del signum, frame
        logger.info("Shutting down Registrar Server...")
        protected_server.shutdown()
        unprotected_server.shutdown()
        sys.exit(0)

    # Catch these signals.  Note that a SIGKILL cannot be caught, so
    # killing this process with "kill -9" may result in improper shutdown
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    thread_protected_server.join()
    thread_unprotected_server.join()
