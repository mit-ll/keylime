import asyncio
import base64
import functools
import os
import signal
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Process
from typing import Any, Dict, List, Optional, Tuple, Union, cast

import tornado.httpserver
import tornado.ioloop
import tornado.netutil
import tornado.process
import tornado.web
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.orm.exc import NoResultFound  # pyright: ignore

from keylime import api_version as keylime_api_version
from keylime import (
    cloud_verifier_common,
    config,
    json,
    keylime_logging,
    revocation_notifier,
    signing,
    tornado_requests,
    web_util,
)
from keylime.agentstates import AgentAttestState, AgentAttestStates
from keylime.common import retry, states, validators
from keylime.common.version import str_to_version
from keylime.da import record
from keylime.db.keylime_db import DBEngineManager, SessionManager
from keylime.db.verifier_db import VerfierMain, VerifierAllowlist, VerifierMbpolicy
from keylime.failure import MAX_SEVERITY_LABEL, Component, Event, Failure, set_severity_config
from keylime.ima import ima
from keylime.mba import mba

logger = keylime_logging.init_logging("verifier")

GLOBAL_POLICY_CACHE: Dict[str, Dict[str, str]] = {}

set_severity_config(config.getlist("verifier", "severity_labels"), config.getlist("verifier", "severity_policy"))

try:
    engine = DBEngineManager().make_engine("cloud_verifier")
except SQLAlchemyError as err:
    logger.error("Error creating SQL engine or session: %s", err)
    sys.exit(1)

try:
    rmc = record.get_record_mgt_class(config.get("verifier", "durable_attestation_import", fallback=""))
    if rmc:
        rmc = rmc("verifier")
except record.RecordManagementException as rme:
    logger.error("Error initializing Durable Attestation: %s", rme)
    sys.exit(1)


def get_session() -> Session:
    return SessionManager().make_session(engine)


def get_AgentAttestStates() -> AgentAttestStates:
    return AgentAttestStates.get_instance()


# The "exclude_db" dict values are removed from the response before adding the dict to the DB
# This is because we want these values to remain ephemeral and not stored in the database.
exclude_db: Dict[str, Any] = {
    "registrar_data": "",
    "nonce": "",
    "b64_encrypted_V": "",
    "provide_V": True,
    "num_retries": 0,
    "pending_event": None,
    # the following 3 items are updated to VerifierDB only when the AgentState is stored
    "boottime": "",
    "ima_pcrs": [],
    "pcr10": "",
    "next_ima_ml_entry": 0,
    "learned_ima_keyrings": {},
    "ssl_context": None,
}


def _from_db_obj(agent_db_obj: VerfierMain) -> Dict[str, Any]:
    fields = [
        "agent_id",
        "v",
        "ip",
        "port",
        "operational_state",
        "public_key",
        "tpm_policy",
        "meta_data",
        "ima_sign_verification_keys",
        "revocation_key",
        "accept_tpm_hash_algs",
        "accept_tpm_encryption_algs",
        "accept_tpm_signing_algs",
        "hash_alg",
        "enc_alg",
        "sign_alg",
        "boottime",
        "ima_pcrs",
        "pcr10",
        "next_ima_ml_entry",
        "learned_ima_keyrings",
        "supported_version",
        "mtls_cert",
        "ak_tpm",
        "attestation_count",
        "last_received_quote",
        "last_successful_attestation",
        "tpm_clockinfo",
    ]
    agent_dict = {}
    for field in fields:
        agent_dict[field] = getattr(agent_db_obj, field, None)

    # add default fields that are ephemeral
    for key, val in exclude_db.items():
        agent_dict[key] = val

    return agent_dict


def verifier_read_policy_from_cache(stored_agent: VerfierMain) -> str:
    checksum = ""
    name = "empty"
    agent_id = str(stored_agent.agent_id)

    if agent_id not in GLOBAL_POLICY_CACHE:
        GLOBAL_POLICY_CACHE[agent_id] = {}
        GLOBAL_POLICY_CACHE[agent_id][""] = ""

    if stored_agent.ima_policy:
        checksum = str(stored_agent.ima_policy.checksum)
        name = stored_agent.ima_policy.name

    if checksum not in GLOBAL_POLICY_CACHE[agent_id]:
        if len(GLOBAL_POLICY_CACHE[agent_id]) > 1:
            # Perform a cleanup of the contents, IMA policy checksum changed
            logger.debug(
                "Cleaning up policy cache for policy named %s, with checksum %s, used by agent %s",
                name,
                checksum,
                agent_id,
            )

            GLOBAL_POLICY_CACHE[agent_id] = {}
            GLOBAL_POLICY_CACHE[agent_id][""] = ""

        logger.debug(
            "IMA policy named %s, with checksum %s, used by agent %s is not present on policy cache on this verifier, performing SQLAlchemy load",
            name,
            checksum,
            agent_id,
        )
        # Actually contacts the database and load the (large) ima_policy column for "allowlists" table
        ima_policy = stored_agent.ima_policy.ima_policy
        assert isinstance(ima_policy, str)
        GLOBAL_POLICY_CACHE[agent_id][checksum] = ima_policy

    return GLOBAL_POLICY_CACHE[agent_id][checksum]


def verifier_db_delete_agent(session: Session, agent_id: str) -> None:
    get_AgentAttestStates().delete_by_agent_id(agent_id)
    session.query(VerfierMain).filter_by(agent_id=agent_id).delete()
    session.query(VerifierAllowlist).filter_by(name=agent_id).delete()
    session.query(VerifierMbpolicy).filter_by(name=agent_id).delete()
    session.commit()


def store_attestation_state(agentAttestState: AgentAttestState) -> None:
    # Only store if IMA log was evaluated
    if agentAttestState.get_ima_pcrs():
        agent_id = agentAttestState.agent_id
        session = get_session()
        try:
            update_agent = session.query(VerfierMain).get(agentAttestState.get_agent_id())
            assert update_agent
            update_agent.boottime = agentAttestState.get_boottime()
            update_agent.next_ima_ml_entry = agentAttestState.get_next_ima_ml_entry()
            ima_pcrs_dict = agentAttestState.get_ima_pcrs()
            update_agent.ima_pcrs = list(ima_pcrs_dict.keys())
            for pcr_num, value in ima_pcrs_dict.items():
                setattr(update_agent, f"pcr{pcr_num}", value)
            update_agent.learned_ima_keyrings = agentAttestState.get_ima_keyrings().to_json()
            try:
                session.add(update_agent)
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error on storing attestation state for agent %s: %s", agent_id, e)
            session.commit()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error on storing attestation state for agent %s: %s", agent_id, e)


class BaseHandler(tornado.web.RequestHandler):
    def prepare(self) -> None:  # pylint: disable=W0235
        super().prepare()

    def write_error(self, status_code: int, **kwargs: Any) -> None:
        self.set_header("Content-Type", "text/json")
        if self.settings.get("serve_traceback") and "exc_info" in kwargs:
            # in debug mode, try to send a traceback
            lines = []
            for line in traceback.format_exception(*kwargs["exc_info"]):
                lines.append(line)
            self.finish(
                json.dumps(
                    {
                        "code": status_code,
                        "status": self._reason,
                        "traceback": lines,
                        "results": {},
                    }
                )
            )
        else:
            self.finish(
                json.dumps(
                    {
                        "code": status_code,
                        "status": self._reason,
                        "results": {},
                    }
                )
            )

    def data_received(self, chunk: Any) -> None:
        raise NotImplementedError()


class MainHandler(tornado.web.RequestHandler):
    def head(self) -> None:
        web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface instead")

    def get(self) -> None:
        web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface instead")

    def delete(self) -> None:
        web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface instead")

    def post(self) -> None:
        web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface instead")

    def put(self) -> None:
        web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface instead")

    def data_received(self, chunk: Any) -> None:
        raise NotImplementedError()


class VersionHandler(BaseHandler):
    def head(self) -> None:
        web_util.echo_json_response(self, 405, "Not Implemented: Use GET interface instead")

    def get(self) -> None:
        if self.request.uri is None:
            web_util.echo_json_response(self, 400, "URI not specified")
            return

        rest_params = web_util.get_restful_params(self.request.uri)
        if rest_params is None:
            web_util.echo_json_response(self, 405, "Not Implemented")
            return

        if "version" not in rest_params:
            web_util.echo_json_response(self, 400, "URI not supported")
            logger.warning("GET returning 400 response. URI not supported: %s", self.request.path)
            return

        version_info = {
            "current_version": keylime_api_version.current_version(),
            "supported_versions": keylime_api_version.all_versions(),
        }

        web_util.echo_json_response(self, 200, "Success", version_info)

    def delete(self) -> None:
        web_util.echo_json_response(self, 405, "Not Implemented: Use GET interface instead")

    def post(self) -> None:
        web_util.echo_json_response(self, 405, "Not Implemented: Use GET interface instead")

    def put(self) -> None:
        web_util.echo_json_response(self, 405, "Not Implemented: Use GET interface instead")

    def data_received(self, chunk: Any) -> None:
        raise NotImplementedError()


class AgentsHandler(BaseHandler):
    def __validate_input(self, method: str) -> Tuple[Optional[Dict[str, Union[str, None]]], Optional[str]]:
        if self.request.uri is None:
            web_util.echo_json_response(self, 400, "URI not specified")
            return None, None

        rest_params = web_util.get_restful_params(self.request.uri)
        if rest_params is None:
            web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface")
            return None, None

        if not web_util.validate_api_version(self, cast(str, rest_params["api_version"]), logger):
            return None, None

        if "agents" not in rest_params:
            web_util.echo_json_response(self, 400, "uri not supported")
            if method != "DELETE":
                logger.warning("%s returning 400 response. uri not supported: %s", method, self.request.path)
            return None, None

        agent_id = rest_params["agents"]

        validate_agent_id = False
        if method == "GET":
            validate_agent_id = (agent_id is not None) and (agent_id != "")
        elif method in ["PUT", "DELETE"]:
            if agent_id is None:
                web_util.echo_json_response(self, 400, "uri not supported")
                logger.warning("%s returning 400 response. uri not supported", method)
                if method == "DELETE":
                    return None, None

            validate_agent_id = True
        else:
            validate_agent_id = agent_id is not None

        # If the agent ID is not valid (wrong set of characters), just do nothing.
        if validate_agent_id and not validators.valid_agent_id(agent_id):
            web_util.echo_json_response(self, 400, "agent_id not not valid")
            logger.error("%s received an invalid agent ID: %s", method, agent_id)
            return None, None

        return rest_params, agent_id

    def head(self) -> None:
        """HEAD not supported"""
        web_util.echo_json_response(self, 405, "HEAD not supported")

    def get(self) -> None:
        """This method handles the GET requests to retrieve status on agents from the Cloud Verifier.

        Currently, only agents resources are available for GETing, i.e. /agents. All other GET uri's
        will return errors. Agents requests require a single agent_id parameter which identifies the
        agent to be returned. If the agent_id is not found, a 404 response is returned.  If the agent_id
        was not found, it either completed successfully, or failed.  If found, the agent_id is still polling
        to contact the Cloud Agent.
        """
        session = get_session()

        rest_params, agent_id = self.__validate_input("GET")
        if not rest_params:
            return

        if (agent_id is not None) and (agent_id != ""):
            # If the agent ID is not valid (wrong set of characters),
            # just do nothing.
            agent = None
            try:
                agent = (
                    session.query(VerfierMain)
                    .options(  # type: ignore
                        joinedload(VerfierMain.ima_policy).load_only(
                            VerifierAllowlist.checksum, VerifierAllowlist.generator  # pyright: ignore
                        )
                    )
                    .options(  # type: ignore
                        joinedload(VerfierMain.mb_policy).load_only(VerifierMbpolicy.mb_policy)  # pyright: ignore
                    )
                    .filter_by(agent_id=agent_id)
                    .one_or_none()
                )
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)

            if agent is not None:
                response = cloud_verifier_common.process_get_status(agent)
                web_util.echo_json_response(self, 200, "Success", response)
            else:
                web_util.echo_json_response(self, 404, "agent id not found")
        else:
            json_response = None
            if "bulk" in rest_params:
                agent_list = None

                if ("verifier" in rest_params) and (rest_params["verifier"] != ""):
                    agent_list = (
                        session.query(VerfierMain)
                        .options(  # type: ignore
                            joinedload(VerfierMain.ima_policy).load_only(
                                VerifierAllowlist.checksum, VerifierAllowlist.generator  # pyright: ignore
                            )
                        )
                        .options(  # type: ignore
                            joinedload(VerfierMain.mb_policy).load_only(VerifierMbpolicy.mb_policy)  # pyright: ignore
                        )
                        .filter_by(verifier_id=rest_params["verifier"])
                        .all()
                    )
                else:
                    agent_list = (
                        session.query(VerfierMain)
                        .options(  # type: ignore
                            joinedload(VerfierMain.ima_policy).load_only(
                                VerifierAllowlist.checksum, VerifierAllowlist.generator  # pyright: ignore
                            )
                        )
                        .options(  # type: ignore
                            joinedload(VerfierMain.mb_policy).load_only(VerifierMbpolicy.mb_policy)  # pyright: ignore
                        )
                        .all()
                    )

                json_response = {}
                for agent in agent_list:
                    json_response[agent.agent_id] = cloud_verifier_common.process_get_status(agent)

                web_util.echo_json_response(self, 200, "Success", json_response)
            else:
                if ("verifier" in rest_params) and (rest_params["verifier"] != ""):
                    json_response_list = (
                        session.query(VerfierMain.agent_id).filter_by(verifier_id=rest_params["verifier"]).all()
                    )
                else:
                    json_response_list = session.query(VerfierMain.agent_id).all()

                web_util.echo_json_response(self, 200, "Success", {"uuids": json_response_list})

            logger.info("GET returning 200 response for agent_id list")

    def delete(self) -> None:
        """This method handles the DELETE requests to remove agents from the Cloud Verifier.

        Currently, only agents resources are available for DELETEing, i.e. /agents. All other DELETE uri's will return errors.
        agents requests require a single agent_id parameter which identifies the agent to be deleted.
        """
        session = get_session()

        rest_params, agent_id = self.__validate_input("DELETE")
        if not rest_params or not agent_id:
            return

        agent = None
        try:
            agent = session.query(VerfierMain).filter_by(agent_id=agent_id).first()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)

        if agent is None:
            web_util.echo_json_response(self, 404, "agent id not found")
            logger.info("DELETE returning 404 response. agent id: %s not found.", agent_id)
            return

        verifier_id = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)
        if verifier_id != agent.verifier_id:
            web_util.echo_json_response(self, 404, "agent id associated to this verifier")
            logger.info("DELETE returning 404 response. agent id: %s not associated to this verifer.", agent_id)
            return

        # Cleanup the cache when the agent is deleted. Do it early.
        if agent_id in GLOBAL_POLICY_CACHE:
            del GLOBAL_POLICY_CACHE[agent_id]
            logger.debug(
                "Cleaned up policy cache from all entries used by agent %s",
                agent_id,
            )

        op_state = agent.operational_state
        if op_state in (states.SAVED, states.FAILED, states.TERMINATED, states.TENANT_FAILED, states.INVALID_QUOTE):
            try:
                verifier_db_delete_agent(session, agent_id)
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
            web_util.echo_json_response(self, 200, "Success")
            logger.info("DELETE returning 200 response for agent id: %s", agent_id)
        else:
            try:
                update_agent = session.query(VerfierMain).get(agent_id)
                assert update_agent
                update_agent.operational_state = states.TERMINATED
                try:
                    session.add(update_agent)
                except SQLAlchemyError as e:
                    logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                session.commit()
                web_util.echo_json_response(self, 202, "Accepted")
                logger.info("DELETE returning 202 response for agent id: %s", agent_id)
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)

    def post(self) -> None:
        """This method handles the POST requests to add agents to the Cloud Verifier.

        Currently, only agents resources are available for POSTing, i.e. /agents. All other POST uri's will return errors.
        agents requests require a json block sent in the body
        """
        session = get_session()
        # TODO: exception handling needs fixing
        # Maybe handle exceptions with if/else if/else blocks ... simple and avoids nesting
        try:  # pylint: disable=too-many-nested-blocks
            rest_params, agent_id = self.__validate_input("POST")
            if not rest_params:
                return

            if agent_id is not None:
                content_length = len(self.request.body)
                if content_length == 0:
                    web_util.echo_json_response(self, 400, "Expected non zero content length")
                    logger.warning("POST returning 400 response. Expected non zero content length.")
                else:
                    json_body = json.loads(self.request.body)
                    agent_data = {
                        "v": json_body.get("v", None),
                        "ip": json_body["cloudagent_ip"],
                        "port": int(json_body["cloudagent_port"]),
                        "operational_state": states.START,
                        "public_key": "",
                        "tpm_policy": json_body["tpm_policy"],
                        "meta_data": json_body["metadata"],
                        "ima_sign_verification_keys": json_body["ima_sign_verification_keys"],
                        "revocation_key": json_body["revocation_key"],
                        "accept_tpm_hash_algs": json_body["accept_tpm_hash_algs"],
                        "accept_tpm_encryption_algs": json_body["accept_tpm_encryption_algs"],
                        "accept_tpm_signing_algs": json_body["accept_tpm_signing_algs"],
                        "supported_version": json_body["supported_version"],
                        "ak_tpm": json_body["ak_tpm"],
                        "mtls_cert": json_body.get("mtls_cert", None),
                        "hash_alg": "",
                        "enc_alg": "",
                        "sign_alg": "",
                        "agent_id": agent_id,
                        "boottime": 0,
                        "ima_pcrs": [],
                        "pcr10": None,
                        "next_ima_ml_entry": 0,
                        "learned_ima_keyrings": {},
                        "verifier_id": config.get(
                            "verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID
                        ),
                        "attestation_count": 0,
                        "last_received_quote": 0,
                        "last_successful_attestation": 0,
                    }

                    if "verifier_ip" in json_body:
                        agent_data["verifier_ip"] = json_body["verifier_ip"]
                    else:
                        agent_data["verifier_ip"] = config.get("verifier", "ip")

                    if "verifier_port" in json_body:
                        agent_data["verifier_port"] = json_body["verifier_port"]
                    else:
                        agent_data["verifier_port"] = config.get("verifier", "port")

                    agent_mtls_cert_enabled = config.getboolean("verifier", "enable_agent_mtls", fallback=False)

                    # TODO: Always error for v1.0 version after initial upgrade
                    if all(
                        [
                            agent_data["supported_version"] != "1.0",
                            agent_mtls_cert_enabled,
                            (agent_data["mtls_cert"] is None or agent_data["mtls_cert"] == "disabled"),
                        ]
                    ):
                        web_util.echo_json_response(self, 400, "mTLS certificate for agent is required!")
                        return

                    # Handle runtime policies

                    # How each pair of inputs should be handled:
                    # - No name, no policy: use default empty policy using agent UUID as name
                    # - Name, no policy: fetch existing policy from DB
                    # - No name, policy: store policy using agent UUID as name
                    # - Name, policy: store policy using name

                    runtime_policy_name = json_body.get("runtime_policy_name")
                    runtime_policy = base64.b64decode(json_body.get("runtime_policy")).decode()
                    runtime_policy_stored = None

                    if runtime_policy_name:
                        try:
                            runtime_policy_stored = (
                                session.query(VerifierAllowlist).filter_by(name=runtime_policy_name).one_or_none()
                            )
                        except SQLAlchemyError as e:
                            logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                            raise

                        # Prevent overwriting existing IMA policies with name provided in request
                        if runtime_policy and runtime_policy_stored:
                            web_util.echo_json_response(
                                self,
                                409,
                                f"IMA policy with name {runtime_policy_name} already exists. Please use a different name or delete the allowlist from the verifier.",
                            )
                            logger.warning("IMA policy with name %s already exists", runtime_policy_name)
                            return

                        # Return an error code if the named allowlist does not exist in the database
                        if not runtime_policy and not runtime_policy_stored:
                            web_util.echo_json_response(
                                self, 404, f"Could not find IMA policy with name {runtime_policy_name}!"
                            )
                            logger.warning("Could not find IMA policy with name %s", runtime_policy_name)
                            return

                    # Prevent overwriting existing agents with UUID provided in request
                    try:
                        new_agent_count = session.query(VerfierMain).filter_by(agent_id=agent_id).count()
                    except SQLAlchemyError as e:
                        logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                        raise e

                    if new_agent_count > 0:
                        web_util.echo_json_response(
                            self,
                            409,
                            f"Agent of uuid {agent_id} already exists. Please use delete or update.",
                        )
                        logger.warning("Agent of uuid %s already exists", agent_id)
                        return

                    # Write IMA policy to database if needed
                    if not runtime_policy_name and not runtime_policy:
                        logger.info("IMA policy data not provided with request! Using default empty IMA policy.")
                        runtime_policy = json.dumps(cast(Dict[str, Any], ima.EMPTY_RUNTIME_POLICY))

                    if runtime_policy:
                        runtime_policy_key_bytes = signing.get_runtime_policy_keys(
                            runtime_policy.encode(),
                            json_body.get("runtime_policy_key"),
                        )

                        try:
                            ima.verify_runtime_policy(
                                runtime_policy.encode(),
                                runtime_policy_key_bytes,
                                verify_sig=config.getboolean(
                                    "verifier", "require_allow_list_signatures", fallback=False
                                ),
                            )
                        except ima.ImaValidationError as e:
                            web_util.echo_json_response(self, e.code, e.message)
                            logger.warning(e.message)
                            return

                        if not runtime_policy_name:
                            runtime_policy_name = agent_id

                        try:
                            runtime_policy_db_format = ima.runtime_policy_db_contents(
                                runtime_policy_name, runtime_policy
                            )
                        except ima.ImaValidationError as e:
                            message = f"Runtime policy is malformatted: {e.message}"
                            web_util.echo_json_response(self, e.code, message)
                            logger.warning(message)
                            return

                        try:
                            runtime_policy_stored = (
                                session.query(VerifierAllowlist).filter_by(name=runtime_policy_name).one_or_none()
                            )
                        except SQLAlchemyError as e:
                            logger.error(
                                "SQLAlchemy Error while retrieving stored ima policy for agent ID %s: %s", agent_id, e
                            )
                            raise
                        try:
                            if runtime_policy_stored is None:
                                runtime_policy_stored = VerifierAllowlist(**runtime_policy_db_format)
                                session.add(runtime_policy_stored)
                                session.commit()
                        except SQLAlchemyError as e:
                            logger.error("SQLAlchemy Error while updating ima policy for agent ID %s: %s", agent_id, e)
                            raise

                    # Handle measured boot policy
                    # - No name, mb_policy   : store mb_policy using agent UUID as name
                    # - Name, no mb_policy   : fetch existing mb_policy from DB
                    # - Name, mb_policy      : store mb_policy using name

                    mb_policy_name = json_body["mb_policy_name"]
                    mb_policy = json_body["mb_policy"]
                    mb_policy_stored = None

                    if mb_policy_name:
                        try:
                            mb_policy_stored = (
                                session.query(VerifierMbpolicy).filter_by(name=mb_policy_name).one_or_none()
                            )
                        except SQLAlchemyError as e:
                            logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                            raise

                        # Prevent overwriting existing mb_policy with name provided in request
                        if mb_policy and mb_policy_stored:
                            web_util.echo_json_response(
                                self,
                                409,
                                f"mb_policy with name {mb_policy_name} already exists. Please use a different name or delete the mb_policy from the verifier.",
                            )
                            logger.warning("mb_policy with name %s already exists", mb_policy_name)
                            return

                        # Return error if the mb_policy is neither provided nor stored.
                        if not mb_policy and not mb_policy_stored:
                            web_util.echo_json_response(
                                self, 404, f"Could not find mb_policy with name {mb_policy_name}!"
                            )
                            logger.warning("Could not find mb_policy with name %s", mb_policy_name)
                            return

                    else:
                        # Use the UUID of the agent
                        mb_policy_name = agent_id
                        try:
                            mb_policy_stored = (
                                session.query(VerifierMbpolicy).filter_by(name=mb_policy_name).one_or_none()
                            )
                        except SQLAlchemyError as e:
                            logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                            raise

                        # Prevent overwriting existing mb_policy
                        if mb_policy and mb_policy_stored:
                            web_util.echo_json_response(
                                self,
                                409,
                                f"mb_policy with name {mb_policy_name} already exists. You can delete the mb_policy from the verifier.",
                            )
                            logger.warning("mb_policy with name %s already exists", mb_policy_name)
                            return

                    # Store the policy into database if not stored
                    if mb_policy_stored is None:
                        try:
                            mb_policy_db_format = mba.mb_policy_db_contents(mb_policy_name, mb_policy)
                            mb_policy_stored = VerifierMbpolicy(**mb_policy_db_format)
                            session.add(mb_policy_stored)
                            session.commit()
                        except SQLAlchemyError as e:
                            logger.error("SQLAlchemy Error while updating mb_policy for agent ID %s: %s", agent_id, e)
                            raise

                    # Write the agent to the database, attaching associated stored ima_policy and mb_policy
                    try:
                        assert runtime_policy_stored
                        assert mb_policy_stored
                        session.add(
                            VerfierMain(**agent_data, ima_policy=runtime_policy_stored, mb_policy=mb_policy_stored)
                        )
                        session.commit()
                    except SQLAlchemyError as e:
                        logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                        raise e

                    # add default fields that are ephemeral
                    for key, val in exclude_db.items():
                        agent_data[key] = val

                    # Prepare SSLContext for mTLS connections
                    agent_data["ssl_context"] = None
                    if agent_mtls_cert_enabled:
                        agent_data["ssl_context"] = web_util.generate_agent_tls_context(
                            "verifier", agent_data["mtls_cert"], logger=logger
                        )

                    if agent_data["ssl_context"] is None:
                        logger.warning("Connecting to agent without mTLS: %s", agent_id)

                    asyncio.ensure_future(process_agent(agent_data, states.GET_QUOTE))
                    web_util.echo_json_response(self, 200, "Success")
                    logger.info("POST returning 200 response for adding agent id: %s", agent_id)
            else:
                web_util.echo_json_response(self, 400, "uri not supported")
                logger.warning("POST returning 400 response. uri not supported")
        except Exception as e:
            web_util.echo_json_response(self, 400, f"Exception error: {str(e)}")
            logger.exception("POST returning 400 response.")

    def put(self) -> None:
        """This method handles the PUT requests to add agents to the Cloud Verifier.

        Currently, only agents resources are available for PUTing, i.e. /agents. All other PUT uri's will return errors.
        agents requests require a json block sent in the body
        """
        session = get_session()
        try:
            rest_params, agent_id = self.__validate_input("PUT")
            if not rest_params:
                return

            try:
                verifier_id = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)
                db_agent = session.query(VerfierMain).filter_by(agent_id=agent_id, verifier_id=verifier_id).one()
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                raise e

            if db_agent is None:
                web_util.echo_json_response(self, 404, "agent id not found")
                logger.info("PUT returning 404 response. agent id: %s not found.", agent_id)
                return

            if "reactivate" in rest_params:
                agent = _from_db_obj(db_agent)

                if agent["mtls_cert"] and agent["mtls_cert"] != "disabled":
                    agent["ssl_context"] = web_util.generate_agent_tls_context(
                        "verifier", agent["mtls_cert"], logger=logger
                    )
                if agent["ssl_context"] is None:
                    logger.warning("Connecting to agent without mTLS: %s", agent_id)

                agent["operational_state"] = states.START
                asyncio.ensure_future(process_agent(agent, states.GET_QUOTE))
                web_util.echo_json_response(self, 200, "Success")
                logger.info("PUT returning 200 response for agent id: %s", agent_id)
            elif "stop" in rest_params:
                # do stuff for terminate
                logger.debug("Stopping polling on %s", agent_id)
                try:
                    session.query(VerfierMain).filter(VerfierMain.agent_id == agent_id).update(  # pyright: ignore
                        {"operational_state": states.TENANT_FAILED}
                    )
                    session.commit()
                except SQLAlchemyError as e:
                    logger.error("SQLAlchemy Error: %s", e)

                web_util.echo_json_response(self, 200, "Success")
                logger.info("PUT returning 200 response for agent id: %s", agent_id)
            else:
                web_util.echo_json_response(self, 400, "uri not supported")
                logger.warning("PUT returning 400 response. uri not supported")

        except Exception as e:
            web_util.echo_json_response(self, 400, f"Exception error: {str(e)}")
            logger.exception("PUT returning 400 response.")

    def data_received(self, chunk: Any) -> None:
        raise NotImplementedError()


class AllowlistHandler(BaseHandler):
    def head(self) -> None:
        web_util.echo_json_response(self, 400, "Allowlist handler: HEAD Not Implemented")

    def __validate_input(self, method: str) -> Tuple[bool, Optional[str]]:
        """Validate the input"""
        if self.request.uri is None:
            web_util.echo_json_response(self, 400, "Invalid URL")
            return False, None
        rest_params = web_util.get_restful_params(self.request.uri)
        if rest_params is None or "allowlists" not in rest_params:
            web_util.echo_json_response(self, 400, "Invalid URL")
            return False, None

        if not web_util.validate_api_version(self, cast(str, rest_params["api_version"]), logger):
            return False, None

        runtime_policy_name = rest_params["allowlists"]
        if runtime_policy_name is None and method != "GET":
            web_util.echo_json_response(self, 400, "Invalid URL")
            logger.warning("%s returning 400 response: %s", method, self.request.path)
            return False, None

        return True, runtime_policy_name

    def get(self) -> None:
        """Get an allowlist or names of allowlists

        GET /allowlists/[name]
        name is required to get an allowlist but not for getting the names of the allowlists.
        """
        params_valid, allowlist_name = self.__validate_input("GET")
        if not params_valid:
            return

        session = get_session()
        if allowlist_name is None:
            try:
                names_allowlists = session.query(VerifierAllowlist.name).all()
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                web_util.echo_json_response(self, 500, "Failed to get names of allowlists")
                raise

            names_response = []
            for name in names_allowlists:
                names_response.append(name[0])
            web_util.echo_json_response(self, 200, "Success", {"runtimepolicy names": names_response})

        else:
            try:
                allowlist = session.query(VerifierAllowlist).filter_by(name=allowlist_name).one()
            except NoResultFound:
                web_util.echo_json_response(self, 404, f"Runtime policy {allowlist_name} not found")
                return
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                web_util.echo_json_response(self, 500, "Failed to get allowlist")
                raise

            response = {}
            for field in ("name", "tpm_policy"):
                response[field] = getattr(allowlist, field, None)
            response["runtime_policy"] = getattr(allowlist, "ima_policy", None)
            web_util.echo_json_response(self, 200, "Success", response)

    def delete(self) -> None:
        """Delete an allowlist

        DELETE /allowlists/{name}
        """

        params_valid, allowlist_name = self.__validate_input("DELETE")
        if not params_valid or allowlist_name is None:
            return

        session = get_session()
        try:
            runtime_policy = session.query(VerifierAllowlist).filter_by(name=allowlist_name).one()
        except NoResultFound:
            web_util.echo_json_response(self, 404, f"Runtime policy {allowlist_name} not found")
            return
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            web_util.echo_json_response(self, 500, "Failed to get allowlist")
            raise

        try:
            agent = session.query(VerfierMain).filter_by(ima_policy_id=runtime_policy.id).one_or_none()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            raise
        if agent is not None:
            web_util.echo_json_response(
                self,
                409,
                f"Can't delete allowlist as it's currently in use by agent {agent.agent_id}",
            )
            return

        try:
            session.query(VerifierAllowlist).filter_by(name=allowlist_name).delete()
            session.commit()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            session.close()
            web_util.echo_json_response(self, 500, f"Database error: {e}")
            raise

        # NOTE(kaifeng) 204 Can not have response body, but current helper
        # doesn't support this case.
        self.set_status(204)
        self.set_header("Content-Type", "application/json")
        self.finish()
        logger.info("DELETE returning 204 response for allowlist: %s", allowlist_name)

    def __get_runtime_policy_db_format(self, runtime_policy_name: str) -> Dict[str, Any]:
        """Get the IMA policy from the request and return it in Db format"""
        content_length = len(self.request.body)
        if content_length == 0:
            web_util.echo_json_response(self, 400, "Expected non zero content length")
            logger.warning("POST returning 400 response. Expected non zero content length.")
            return {}

        json_body = json.loads(self.request.body)

        runtime_policy = base64.b64decode(json_body.get("runtime_policy")).decode()
        runtime_policy_key_bytes = signing.get_runtime_policy_keys(
            runtime_policy.encode(),
            json_body.get("runtime_policy_key"),
        )

        try:
            ima.verify_runtime_policy(
                runtime_policy.encode(),
                runtime_policy_key_bytes,
                verify_sig=config.getboolean("verifier", "require_allow_list_signatures", fallback=False),
            )
        except ima.ImaValidationError as e:
            web_util.echo_json_response(self, e.code, e.message)
            logger.warning(e.message)
            return {}

        tpm_policy = json_body.get("tpm_policy")

        try:
            runtime_policy_db_format = ima.runtime_policy_db_contents(runtime_policy_name, runtime_policy, tpm_policy)
        except ima.ImaValidationError as e:
            message = f"Runtime policy is malformatted: {e.message}"
            web_util.echo_json_response(self, e.code, message)
            logger.warning(message)
            return {}

        return runtime_policy_db_format

    def post(self) -> None:
        """Create an allowlist

        POST /allowlists/{name}
        body: {"tpm_policy": {..} ...
        """

        params_valid, runtime_policy_name = self.__validate_input("POST")
        if not params_valid or runtime_policy_name is None:
            return

        runtime_policy_db_format = self.__get_runtime_policy_db_format(runtime_policy_name)
        if not runtime_policy_db_format:
            return

        session = get_session()
        # don't allow overwritting
        try:
            runtime_policy_count = session.query(VerifierAllowlist).filter_by(name=runtime_policy_name).count()
            if runtime_policy_count > 0:
                web_util.echo_json_response(self, 409, f"Runtime policy with name {runtime_policy_name} already exists")
                logger.warning("Runtime policy with name %s already exists", runtime_policy_name)
                return
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            raise

        try:
            # Add the agent and data
            session.add(VerifierAllowlist(**runtime_policy_db_format))
            session.commit()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            raise

        web_util.echo_json_response(self, 201)
        logger.info("POST returning 201")

    def put(self) -> None:
        """Update an allowlist

        PUT /allowlists/{name}
        body: {"tpm_policy": {..} ...
        """

        params_valid, runtime_policy_name = self.__validate_input("PUT")
        if not params_valid or runtime_policy_name is None:
            return

        runtime_policy_db_format = self.__get_runtime_policy_db_format(runtime_policy_name)
        if not runtime_policy_db_format:
            return

        session = get_session()
        # don't allow creating a new policy
        try:
            runtime_policy_count = session.query(VerifierAllowlist).filter_by(name=runtime_policy_name).count()
            if runtime_policy_count != 1:
                web_util.echo_json_response(
                    self, 409, f"Runtime policy with name {runtime_policy_name} does not already exist"
                )
                logger.warning("Runtime policy with name %s does not already exist", runtime_policy_name)
                return
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            raise

        try:
            # Update the named runtime policy
            session.query(VerifierAllowlist).filter_by(name=runtime_policy_name).update(
                runtime_policy_db_format  # pyright: ignore
            )
            session.commit()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            raise

        web_util.echo_json_response(self, 201)
        logger.info("PUT returning 201")

    def data_received(self, chunk: Any) -> None:
        raise NotImplementedError()


class VerifyIdentityHandler(BaseHandler):
    def head(self) -> None:
        """HEAD not supported"""
        web_util.echo_json_response(self, 405, "HEAD not supported")

    def delete(self) -> None:
        """DELETE not supported"""
        web_util.echo_json_response(self, 405, "DELETE not supported")

    def post(self) -> None:
        """POST not supported"""
        web_util.echo_json_response(self, 405, "POST not supported")

    def put(self) -> None:
        """PUT not supported"""
        web_util.echo_json_response(self, 405, "PUT not supported")

    def get(self) -> None:
        """This method handles the GET requests to verify an identity quote from an agent.

        This is useful for 3rd party tools and integrations to independently verify the state of an agent.
        """
        session = get_session()

        # validate the parameters of our request
        if self.request.uri is None:
            web_util.echo_json_response(self, 400, "URI not specified")
            return

        rest_params = web_util.get_restful_params(self.request.uri)
        if rest_params is None:
            web_util.echo_json_response(self, 405, "Not Implemented: Use /verify/identity interface")
            return

        if not web_util.validate_api_version(self, cast(str, rest_params["api_version"]), logger):
            return

        if "verify" not in rest_params and rest_params["verify"] != "identity":
            web_util.echo_json_response(self, 400, "uri not supported")
            logger.warning("GET returning 400 response. uri not supported: %s", self.request.path)
            return

        # make sure we have all of the necessary parameters: agent_uuid, quote and nonce
        agent_id = rest_params.get("agent_uuid")
        if agent_id is None or agent_id == "":
            web_util.echo_json_response(self, 400, "missing query parameter 'agent_uuid'")
            logger.warning("GET returning 400 response. missing query parameter 'agent_uuid'")
            return

        quote = rest_params.get("quote")
        if quote is None or quote == "":
            web_util.echo_json_response(self, 400, "missing query parameter 'quote'")
            logger.warning("GET returning 400 response. missing query parameter 'quote'")
            return

        nonce = rest_params.get("nonce")
        if nonce is None or nonce == "":
            web_util.echo_json_response(self, 400, "missing query parameter 'nonce'")
            logger.warning("GET returning 400 response. missing query parameter 'nonce'")
            return

        hash_alg = rest_params.get("hash_alg")
        if hash_alg is None or hash_alg == "":
            web_util.echo_json_response(self, 400, "missing query parameter 'hash_alg'")
            logger.warning("GET returning 400 response. missing query parameter 'hash_alg'")
            return

        # get the agent information from the DB
        agent = None
        try:
            agent = (
                session.query(VerfierMain)
                .options(  # type: ignore
                    joinedload(VerfierMain.ima_policy).load_only(
                        VerifierAllowlist.checksum, VerifierAllowlist.generator  # pyright: ignore
                    )
                )
                .filter_by(agent_id=agent_id)
                .one_or_none()
            )
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)

        if agent is not None:
            agentAttestState = get_AgentAttestStates().get_by_agent_id(agent_id)
            failure = cloud_verifier_common.process_verify_identity_quote(
                agent, quote, nonce, hash_alg, agentAttestState
            )
            if failure:
                failure_contexts = "; ".join(x.context for x in failure.events)
                web_util.echo_json_response(self, 200, "Success", {"valid": 0, "reason": failure_contexts})
                logger.info("GET returning 200, but validation failed")
            else:
                web_util.echo_json_response(self, 200, "Success", {"valid": 1})
                logger.info("GET returning 200, validation successful")
        else:
            web_util.echo_json_response(self, 404, "agent id not found")
            logger.info("GET returning 404, agaent not found")

    def data_received(self, chunk: Any) -> None:
        raise NotImplementedError()


class MbpolicyHandler(BaseHandler):
    def head(self) -> None:
        web_util.echo_json_response(self, 400, "Mbpolicy handler: HEAD Not Implemented")

    def __validate_input(self, method: str) -> Tuple[bool, Optional[str]]:
        """Validate the input"""

        if self.request.uri is None:
            web_util.echo_json_response(self, 400, "Invalid URL")
            return False, None
        rest_params = web_util.get_restful_params(self.request.uri)
        if rest_params is None or "mbpolicies" not in rest_params:
            web_util.echo_json_response(self, 400, "Invalid URL")
            return False, None

        if not web_util.validate_api_version(self, cast(str, rest_params["api_version"]), logger):
            return False, None

        mb_policy_name = rest_params["mbpolicies"]
        if mb_policy_name is None and method != "GET":
            web_util.echo_json_response(self, 400, "Invalid URL")
            logger.warning("%s returning 400 response: %s", method, self.request.path)
            return False, None

        return True, mb_policy_name

    def get(self) -> None:
        """Get a mb_policy or list of names of mbpolicies

        GET /mbpolicies/[name]
        name is required to get a mb_policy but not for getting the names of the mbpolicies.
        """

        params_valid, mb_policy_name = self.__validate_input("GET")
        if not params_valid:
            return

        session = get_session()
        if mb_policy_name is None:
            try:
                names_mbpolicies = session.query(VerifierMbpolicy.name).all()
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                web_util.echo_json_response(self, 500, "Failed to get names of mbpolicies")
                raise

            names_response = []
            for name in names_mbpolicies:
                names_response.append(name[0])
            web_util.echo_json_response(self, 200, "Success", {"mbpolicy names": names_response})

        else:
            try:
                mbpolicy = session.query(VerifierMbpolicy).filter_by(name=mb_policy_name).one()
            except NoResultFound:
                web_util.echo_json_response(self, 404, f"Measured boot policy {mb_policy_name} not found")
                return
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                web_util.echo_json_response(self, 500, "Failed to get mb_policy")
                raise

            response = {}
            response["name"] = getattr(mbpolicy, "name", None)
            response["mb_policy"] = getattr(mbpolicy, "mb_policy", None)
            web_util.echo_json_response(self, 200, "Success", response)

    def delete(self) -> None:
        """Delete a mb_policy

        DELETE /mbpolicies/{name}
        """

        params_valid, mb_policy_name = self.__validate_input("DELETE")
        if not params_valid or mb_policy_name is None:
            return

        session = get_session()
        try:
            mbpolicy = session.query(VerifierMbpolicy).filter_by(name=mb_policy_name).one()
        except NoResultFound:
            web_util.echo_json_response(self, 404, f"Measured boot policy {mb_policy_name} not found")
            return
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            web_util.echo_json_response(self, 500, "Failed to get mb_policy")
            raise

        try:
            agent = session.query(VerfierMain).filter_by(mb_policy_id=mbpolicy.id).one_or_none()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            raise
        if agent is not None:
            web_util.echo_json_response(
                self,
                409,
                f"Can't delete mb_policy as it's currently in use by agent {agent.agent_id}",
            )
            return

        try:
            session.query(VerifierMbpolicy).filter_by(name=mb_policy_name).delete()
            session.commit()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            session.close()
            web_util.echo_json_response(self, 500, f"Database error: {e}")
            raise

        # NOTE(kaifeng) 204 Can not have response body, but current helper
        # doesn't support this case.
        self.set_status(204)
        self.set_header("Content-Type", "application/json")
        self.finish()
        logger.info("DELETE returning 204 response for mb_policy: %s", mb_policy_name)

    def __get_mb_policy_db_format(self, mb_policy_name: str) -> Dict[str, Any]:
        """Get the measured boot policy from the request and return it in Db format"""

        content_length = len(self.request.body)
        if content_length == 0:
            web_util.echo_json_response(self, 400, "Expected non zero content length")
            logger.warning("POST returning 400 response. Expected non zero content length.")
            return {}

        json_body = json.loads(self.request.body)
        mb_policy = json_body.get("mb_policy")
        mb_policy_db_format = mba.mb_policy_db_contents(mb_policy_name, mb_policy)

        return mb_policy_db_format

    def post(self) -> None:
        """Create a mb_policy

        POST /mbpolicies/{name}
        body: ...
        """

        params_valid, mb_policy_name = self.__validate_input("POST")
        if not params_valid or mb_policy_name is None:
            return

        mb_policy_db_format = self.__get_mb_policy_db_format(mb_policy_name)
        if not mb_policy_db_format:
            return

        session = get_session()
        # don't allow overwritting
        try:
            mbpolicy_count = session.query(VerifierMbpolicy).filter_by(name=mb_policy_name).count()
            if mbpolicy_count > 0:
                web_util.echo_json_response(
                    self, 409, f"Measured boot policy with name {mb_policy_name} already exists"
                )
                logger.warning("Measured boot policy with name %s already exists", mb_policy_name)
                return
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            raise

        try:
            # Add the data
            session.add(VerifierMbpolicy(**mb_policy_db_format))
            session.commit()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            raise

        web_util.echo_json_response(self, 201)
        logger.info("POST returning 201")

    def put(self) -> None:
        """Update an mb_policy

        PUT /mbpolicies/{name}
        body: ...
        """

        params_valid, mb_policy_name = self.__validate_input("PUT")
        if not params_valid or mb_policy_name is None:
            return

        mb_policy_db_format = self.__get_mb_policy_db_format(mb_policy_name)
        if not mb_policy_db_format:
            return

        session = get_session()
        # don't allow creating a new policy
        try:
            mbpolicy_count = session.query(VerifierMbpolicy).filter_by(name=mb_policy_name).count()
            if mbpolicy_count != 1:
                web_util.echo_json_response(
                    self, 409, f"Measured boot policy with name {mb_policy_name} does not already exist"
                )
                logger.warning("Measured boot policy with name %s does not already exist", mb_policy_name)
                return
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            raise

        try:
            # Update the named mb_policy
            session.query(VerifierMbpolicy).filter_by(name=mb_policy_name).update(
                mb_policy_db_format  # pyright: ignore
            )
            session.commit()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            raise

        web_util.echo_json_response(self, 201)
        logger.info("PUT returning 201")

    def data_received(self, chunk: Any) -> None:
        raise NotImplementedError()


async def update_agent_api_version(agent: Dict[str, Any], timeout: float = 60.0) -> Union[Dict[str, Any], None]:
    agent_id = agent["agent_id"]

    logger.info("Agent %s API version bump detected, trying to update stored API version", agent_id)
    kwargs = {}
    if agent["ssl_context"]:
        kwargs["context"] = agent["ssl_context"]

    res = tornado_requests.request(
        "GET",
        f"http://{agent['ip']}:{agent['port']}/version",
        **kwargs,
        timeout=timeout,
    )
    response = await res

    if response.status_code != 200:
        logger.warning(
            "Could not get agent %s supported API version, Error: %s",
            agent["agent_id"],
            response.status_code,
        )
        return None

    try:
        json_response = json.loads(response.body)
        new_version = json_response["results"]["supported_version"]
        old_version = agent["supported_version"]

        # Only update the API version to use if it is supported by the verifier
        if new_version in keylime_api_version.all_versions():
            new_version_tuple = str_to_version(new_version)
            old_version_tuple = str_to_version(old_version)

            assert new_version_tuple, f"Agent {agent_id} version {new_version} is invalid"
            assert old_version_tuple, f"Agent {agent_id} version {old_version} is invalid"

            # Check that the new version is greater than current version
            if new_version_tuple <= old_version_tuple:
                logger.warning(
                    "Agent %s API version %s is lower or equal to previous version %s",
                    agent_id,
                    new_version,
                    old_version,
                )
                return None

            logger.info("Agent %s new API version %s is supported", agent_id, new_version)
            session = get_session()
            agent["supported_version"] = new_version

            # Remove keys that should not go to the DB
            agent_db = dict(agent)
            for key in exclude_db:
                if key in agent_db:
                    del agent_db[key]

            session.query(VerfierMain).filter_by(agent_id=agent_id).update(agent_db)  # pyright: ignore
            session.commit()
        else:
            logger.warning("Agent %s new API version %s is not supported", agent_id, new_version)
            return None

    except SQLAlchemyError as e:
        logger.error("SQLAlchemy Error updating API version for agent %s: %s", agent_id, e)
        return None
    except Exception as e:
        logger.exception(e)
        return None

    logger.info("Agent %s API version updated to %s", agent["agent_id"], agent["supported_version"])
    return agent


async def invoke_get_quote(
    agent: Dict[str, Any], mb_policy: Optional[str], runtime_policy: str, need_pubkey: bool, timeout: float = 60.0
) -> None:
    failure = Failure(Component.INTERNAL, ["verifier"])

    params = cloud_verifier_common.prepare_get_quote(agent)

    partial_req = "1"
    if need_pubkey:
        partial_req = "0"

    # TODO: remove special handling after initial upgrade
    kwargs = {}
    if agent["ssl_context"]:
        kwargs["context"] = agent["ssl_context"]

    res = tornado_requests.request(
        "GET",
        f"http://{agent['ip']}:{agent['port']}/v{agent['supported_version']}/quotes/integrity"
        f"?nonce={params['nonce']}&mask={params['mask']}"
        f"&partial={partial_req}&ima_ml_entry={params['ima_ml_entry']}",
        **kwargs,
        timeout=timeout,
    )
    response = await res

    if response.status_code != 200:
        # this is a connection error, retry get quote
        if response.status_code in [408, 500, 599]:
            asyncio.ensure_future(process_agent(agent, states.GET_QUOTE_RETRY))
            return

        if response.status_code == 400:
            try:
                json_response = json.loads(response.body)
                if "API version not supported" in json_response["status"]:
                    update = update_agent_api_version(agent)
                    updated = await update

                    if updated:
                        asyncio.ensure_future(process_agent(updated, states.GET_QUOTE_RETRY))
                    else:
                        logger.warning("Could not update stored agent %s API version", agent["agent_id"])
                        failure.add_event(
                            "version_not_supported",
                            {"context": "Agent API version not supported", "data": json_response},
                            False,
                        )
                        asyncio.ensure_future(process_agent(agent, states.FAILED, failure))
                    return

            except Exception as e:
                logger.exception(e)
                failure.add_event(
                    "exception", {"context": "Agent caused the verifier to throw an exception", "data": str(e)}, False
                )
                asyncio.ensure_future(process_agent(agent, states.FAILED, failure))
                return

        # catastrophic error, do not continue
        logger.critical(
            "Unexpected Get Quote response error for cloud agent %s, Error: %s",
            agent["agent_id"],
            response.status_code,
        )
        failure.add_event("no_quote", "Unexpected Get Quote reponse from agent", False)
        asyncio.ensure_future(process_agent(agent, states.FAILED, failure))
    else:
        try:
            json_response = json.loads(response.body)

            # validate the cloud agent response
            if "provide_V" not in agent:
                agent["provide_V"] = True
            agentAttestState = get_AgentAttestStates().get_by_agent_id(agent["agent_id"])

            if rmc:
                rmc.record_create(agent, json_response, mb_policy, runtime_policy)

            failure = cloud_verifier_common.process_quote_response(
                agent,
                mb_policy,
                ima.deserialize_runtime_policy(runtime_policy),
                json_response["results"],
                agentAttestState,
            )
            if not failure:
                if agent["provide_V"]:
                    asyncio.ensure_future(process_agent(agent, states.PROVIDE_V))
                else:
                    asyncio.ensure_future(process_agent(agent, states.GET_QUOTE))
            else:
                asyncio.ensure_future(process_agent(agent, states.INVALID_QUOTE, failure))

            # store the attestation state
            store_attestation_state(agentAttestState)

        except Exception as e:
            logger.exception(e)
            failure.add_event(
                "exception", {"context": "Agent caused the verifier to throw an exception", "data": str(e)}, False
            )
            asyncio.ensure_future(process_agent(agent, states.FAILED, failure))


async def invoke_provide_v(agent: Dict[str, Any], timeout: float = 60.0) -> None:
    failure = Failure(Component.INTERNAL, ["verifier"])

    if agent.get("pending_event") is not None:
        agent["pending_event"] = None

    v_json_message = cloud_verifier_common.prepare_v(agent)

    # TODO: remove special handling after initial upgrade
    kwargs = {}
    if agent["ssl_context"]:
        kwargs["context"] = agent["ssl_context"]

    res = tornado_requests.request(
        "POST",
        f"http://{agent['ip']}:{agent['port']}/v{agent['supported_version']}/keys/vkey",
        data=v_json_message,
        **kwargs,
        timeout=timeout,
    )

    response = await res

    if response.status_code != 200:
        if response.status_code in [408, 500, 599]:
            asyncio.ensure_future(process_agent(agent, states.PROVIDE_V_RETRY))
            return

        if response.status_code == 400:
            try:
                json_response = json.loads(response.body)
                if "API version not supported" in json_response["status"]:
                    update = update_agent_api_version(agent)
                    updated = await update

                    if updated:
                        asyncio.ensure_future(process_agent(updated, states.PROVIDE_V_RETRY))
                    else:
                        logger.warning("Could not update stored agent %s API version", agent["agent_id"])
                        failure.add_event(
                            "version_not_supported",
                            {"context": "Agent API version not supported", "data": json_response},
                            False,
                        )
                        asyncio.ensure_future(process_agent(agent, states.FAILED, failure))
                    return

            except Exception as e:
                logger.exception(e)
                failure.add_event(
                    "exception", {"context": "Agent caused the verifier to throw an exception", "data": str(e)}, False
                )
                asyncio.ensure_future(process_agent(agent, states.FAILED, failure))
                return

        # catastrophic error, do not continue
        logger.critical(
            "Unexpected Provide V response error for cloud agent %s, Error: %s",
            agent["agent_id"],
            response.status_code,
        )
        failure.add_event("no_v", {"message": "Unexpected provide V response", "data": response.status_code}, False)
        asyncio.ensure_future(process_agent(agent, states.FAILED, failure))
    else:
        asyncio.ensure_future(process_agent(agent, states.GET_QUOTE))


async def invoke_notify_error(agent: Dict[str, Any], tosend: Dict[str, Any], timeout: float = 60.0) -> None:
    kwargs = {
        "data": tosend,
    }
    if agent["ssl_context"]:
        kwargs["context"] = agent["ssl_context"]

    res = tornado_requests.request(
        "POST",
        f"http://{agent['ip']}:{agent['port']}/v{agent['supported_version']}/notifications/revocation",
        **kwargs,  # type: ignore
        timeout=timeout,
    )
    response = await res

    if response is None:
        logger.warning(
            "Empty Notify Revocation response from cloud agent %s",
            agent["agent_id"],
        )
    elif response.status_code != 200:
        if response.status_code == 400:
            try:
                json_response = json.loads(response.body)
                if "API version not supported" in json_response["status"]:
                    update = update_agent_api_version(agent)
                    updated = await update

                    if updated:
                        asyncio.ensure_future(invoke_notify_error(updated, tosend))
                    else:
                        logger.warning("Could not update stored agent %s API version", agent["agent_id"])

                    return

            except Exception as e:
                logger.exception(e)
                return

        logger.warning(
            "Unexpected Notify Revocation response error for cloud agent %s, Error: %s",
            agent["agent_id"],
            response.status_code,
        )


async def notify_error(
    agent: Dict[str, Any], msgtype: str = "revocation", event: Optional[Event] = None, timeout: float = 60.0
) -> None:
    notifiers = revocation_notifier.get_notifiers()
    if len(notifiers) == 0:
        return

    tosend = cloud_verifier_common.prepare_error(agent, msgtype, event)
    if "webhook" in notifiers:
        revocation_notifier.notify_webhook(tosend)
    if "zeromq" in notifiers:
        revocation_notifier.notify(tosend)
    if "agent" in notifiers:
        verifier_id = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)
        session = get_session()
        agents = session.query(VerfierMain).filter_by(verifier_id=verifier_id).all()
        futures = []
        loop = asyncio.get_event_loop()
        # Notify all agents asynchronously through a thread pool
        with ThreadPoolExecutor() as pool:
            for agent_db_obj in agents:
                if agent_db_obj.agent_id != agent["agent_id"]:
                    agent = _from_db_obj(agent_db_obj)
                    if agent["mtls_cert"] and agent["mtls_cert"] != "disabled":
                        agent["ssl_context"] = web_util.generate_agent_tls_context(
                            "verifier", agent["mtls_cert"], logger=logger
                        )
                func = functools.partial(invoke_notify_error, agent, tosend, timeout=timeout)
                futures.append(await loop.run_in_executor(pool, func))
            # Wait for all tasks complete in 60 seconds
            try:
                for f in asyncio.as_completed(futures, timeout=60):
                    await f
            except asyncio.TimeoutError as e:
                logger.error("Timeout during notifying error to agents: %s", e)


async def process_agent(
    agent: Dict[str, Any], new_operational_state: int, failure: Failure = Failure(Component.INTERNAL, ["verifier"])
) -> None:
    session = get_session()
    try:  # pylint: disable=R1702
        main_agent_operational_state = agent["operational_state"]
        stored_agent = None
        try:
            stored_agent = (
                session.query(VerfierMain)
                .options(  # type: ignore
                    joinedload(VerfierMain.ima_policy).load_only(VerifierAllowlist.checksum)  # pyright: ignore
                )
                .options(  # type: ignore
                    joinedload(VerfierMain.mb_policy).load_only(VerifierMbpolicy.mb_policy)  # pyright: ignore
                )
                .filter_by(agent_id=str(agent["agent_id"]))
                .first()
            )
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error for agent ID %s: %s", agent["agent_id"], e)

        # if the stored agent could not be recovered from the database, stop polling
        if not stored_agent:
            logger.warning("Unable to retrieve agent %s from database. Stopping polling", agent["agent_id"])
            if agent["pending_event"] is not None:
                tornado.ioloop.IOLoop.current().remove_timeout(agent["pending_event"])
            return

        # if the user did terminated this agent
        if stored_agent.operational_state == states.TERMINATED:  # pyright: ignore
            logger.warning("Agent %s terminated by user.", agent["agent_id"])
            if agent["pending_event"] is not None:
                tornado.ioloop.IOLoop.current().remove_timeout(agent["pending_event"])
            verifier_db_delete_agent(session, agent["agent_id"])
            return

        # if the user tells us to stop polling because the tenant quote check failed
        if stored_agent.operational_state == states.TENANT_FAILED:  # pyright: ignore
            logger.warning("Agent %s has failed tenant quote. Stopping polling", agent["agent_id"])
            if agent["pending_event"] is not None:
                tornado.ioloop.IOLoop.current().remove_timeout(agent["pending_event"])
            return

        # Get request timeout from configuration file
        timeout = config.getfloat("verifier", "request_timeout", fallback=60.0)

        # If failed during processing, log regardless and drop it on the floor
        # The administration application (tenant) can GET the status and act accordingly (delete/retry/etc).
        if new_operational_state in (states.FAILED, states.INVALID_QUOTE):
            assert failure, "States FAILED and INVALID QUOTE should only be reached with a failure message"
            assert failure.highest_severity

            if agent.get("severity_level") is None or agent["severity_level"] < failure.highest_severity.severity:
                assert failure.highest_severity_event
                agent["severity_level"] = failure.highest_severity.severity
                agent["last_event_id"] = failure.highest_severity_event.event_id
                agent["operational_state"] = new_operational_state

                # issue notification for invalid quotes
                if new_operational_state == states.INVALID_QUOTE:
                    await notify_error(agent, event=failure.highest_severity_event, timeout=timeout)

                # When the failure is irrecoverable we stop polling the agent
                if not failure.recoverable or failure.highest_severity == MAX_SEVERITY_LABEL:
                    if agent["pending_event"] is not None:
                        tornado.ioloop.IOLoop.current().remove_timeout(agent["pending_event"])
                    for key in exclude_db:
                        if key in agent:
                            del agent[key]
                    session.query(VerfierMain).filter_by(agent_id=agent["agent_id"]).update(agent)  # pyright: ignore
                    session.commit()

        # propagate all state, but remove none DB keys first (using exclude_db)
        try:
            agent_db = dict(agent)
            for key in exclude_db:
                if key in agent_db:
                    del agent_db[key]

            session.query(VerfierMain).filter_by(agent_id=agent_db["agent_id"]).update(agent_db)  # pyright: ignore
            session.commit()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error for agent ID %s: %s", agent["agent_id"], e)

        # Load agent's IMA policy
        runtime_policy = verifier_read_policy_from_cache(stored_agent)

        # Get agent's measured boot policy
        mb_policy = None
        if stored_agent.mb_policy is not None:
            mb_policy = stored_agent.mb_policy.mb_policy

        # If agent was in a failed state we check if we either stop polling
        # or just add it again to the event loop
        if new_operational_state in [states.FAILED, states.INVALID_QUOTE]:
            if not failure.recoverable or failure.highest_severity == MAX_SEVERITY_LABEL:
                logger.warning("Agent %s failed, stopping polling", agent["agent_id"])
                return

            await invoke_get_quote(agent, mb_policy, runtime_policy, False, timeout=timeout)
            return

        # if new, get a quote
        if main_agent_operational_state == states.START and new_operational_state == states.GET_QUOTE:
            agent["num_retries"] = 0
            agent["operational_state"] = states.GET_QUOTE
            await invoke_get_quote(agent, mb_policy, runtime_policy, True, timeout=timeout)
            return

        if main_agent_operational_state == states.GET_QUOTE and new_operational_state == states.PROVIDE_V:
            agent["num_retries"] = 0
            agent["operational_state"] = states.PROVIDE_V
            # Only deploy V key if actually set
            if agent.get("v"):
                await invoke_provide_v(agent)
            else:
                await process_agent(agent, states.GET_QUOTE)
            return

        if (
            main_agent_operational_state in (states.PROVIDE_V, states.GET_QUOTE)
            and new_operational_state == states.GET_QUOTE
        ):
            agent["num_retries"] = 0
            interval = config.getfloat("verifier", "quote_interval")
            agent["operational_state"] = states.GET_QUOTE
            if interval == 0:
                await invoke_get_quote(agent, mb_policy, runtime_policy, False, timeout=timeout)
            else:
                logger.debug(
                    "Setting up callback to check agent ID %s again in %f seconds", agent["agent_id"], interval
                )

                pending = tornado.ioloop.IOLoop.current().call_later(
                    interval, invoke_get_quote, agent, mb_policy, runtime_policy, False, timeout=timeout  # type: ignore  # due to python <3.9
                )
                agent["pending_event"] = pending
            return

        maxr = config.getint("verifier", "max_retries")
        interval = config.getfloat("verifier", "retry_interval")
        exponential_backoff = config.getboolean("verifier", "exponential_backoff")

        if main_agent_operational_state == states.GET_QUOTE and new_operational_state == states.GET_QUOTE_RETRY:
            if agent["num_retries"] >= maxr:
                logger.warning(
                    "Agent %s was not reachable for quote in %d tries, setting state to FAILED", agent["agent_id"], maxr
                )
                failure.add_event("not_reachable", "agent was not reachable from verifier", False)
                if agent["attestation_count"] > 0:  # only notify on previously good agents
                    await notify_error(
                        agent, msgtype="comm_error", event=failure.highest_severity_event, timeout=timeout
                    )
                else:
                    logger.debug("Communication error for new agent. No notification will be sent")
                await process_agent(agent, states.FAILED, failure)
            else:
                agent["operational_state"] = states.GET_QUOTE

                agent["num_retries"] += 1
                next_retry = retry.retry_time(exponential_backoff, interval, agent["num_retries"], logger)
                logger.info(
                    "Connection to %s refused after %d/%d tries, trying again in %f seconds",
                    agent["ip"],
                    agent["num_retries"],
                    maxr,
                    next_retry,
                )
                tornado.ioloop.IOLoop.current().call_later(
                    next_retry, invoke_get_quote, agent, mb_policy, runtime_policy, True, timeout=timeout  # type: ignore  # due to python <3.9
                )
            return

        if main_agent_operational_state == states.PROVIDE_V and new_operational_state == states.PROVIDE_V_RETRY:
            if agent["num_retries"] >= maxr:
                logger.warning(
                    "Agent %s was not reachable to provide v in %d tries, setting state to FAILED",
                    agent["agent_id"],
                    maxr,
                )
                failure.add_event("not_reachable_v", "agent was not reachable to provide V", False)
                await notify_error(agent, msgtype="comm_error", event=failure.highest_severity_event, timeout=timeout)
                await process_agent(agent, states.FAILED, failure)
            else:
                agent["operational_state"] = states.PROVIDE_V

                agent["num_retries"] += 1
                next_retry = retry.retry_time(exponential_backoff, interval, agent["num_retries"], logger)
                logger.info(
                    "Connection to %s refused after %d/%d tries, trying again in %f seconds",
                    agent["ip"],
                    agent["num_retries"],
                    maxr,
                    next_retry,
                )
                tornado.ioloop.IOLoop.current().call_later(
                    next_retry, invoke_provide_v, agent  # type: ignore  # due to python <3.9
                )
            return
        raise Exception("nothing should ever fall out of this!")

    except Exception as e:
        logger.exception("Polling thread error for agent ID %s", agent["agent_id"])
        failure.add_event(
            "exception", {"context": "Agent caused the verifier to throw an exception", "data": str(e)}, False
        )
        await process_agent(agent, states.FAILED, failure)


async def activate_agents(agents: List[VerfierMain], verifier_ip: str, verifier_port: int) -> None:
    aas = get_AgentAttestStates()
    for agent in agents:
        agent.verifier_ip = verifier_ip  # pyright: ignore
        agent.verifier_port = verifier_port  # pyright: ignore
        agent_run = _from_db_obj(agent)
        if agent_run["mtls_cert"] and agent_run["mtls_cert"] != "disabled":
            agent_run["ssl_context"] = web_util.generate_agent_tls_context(
                "verifier", agent_run["mtls_cert"], logger=logger
            )

        if agent.operational_state == states.START:  # pyright: ignore
            asyncio.ensure_future(process_agent(agent_run, states.GET_QUOTE))
        if agent.boottime:  # pyright: ignore
            ima_pcrs_dict = {}
            assert isinstance(agent.ima_pcrs, list)
            for pcr_num in agent.ima_pcrs:
                ima_pcrs_dict[pcr_num] = getattr(agent, f"pcr{pcr_num}")
            aas.add(
                str(agent.agent_id),
                int(agent.boottime),  # pyright: ignore
                ima_pcrs_dict,
                int(agent.next_ima_ml_entry),  # type: ignore
                dict(agent.learned_ima_keyrings),  # type: ignore
            )


def get_agents_by_verifier_id(verifier_id: str) -> List[VerfierMain]:
    session = get_session()
    try:
        return session.query(VerfierMain).filter_by(verifier_id=verifier_id).all()
    except SQLAlchemyError as e:
        logger.error("SQLAlchemy Error: %s", e)
    return []


def main() -> None:
    """Main method of the Cloud Verifier Server.  This method is encapsulated in a function for packaging to allow it to be
    called as a function by an external program."""

    config.check_version("verifier", logger=logger)

    verifier_port = config.get("verifier", "port")
    verifier_host = config.get("verifier", "ip")
    verifier_id = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)

    # allow tornado's max upload size to be configurable
    max_upload_size = None
    if config.has_option("verifier", "max_upload_size"):
        max_upload_size = int(config.get("verifier", "max_upload_size"))

    # set a conservative general umask
    os.umask(0o077)

    VerfierMain.metadata.create_all(engine, checkfirst=True)  # pyright: ignore
    session = get_session()
    try:
        query_all = session.query(VerfierMain).all()
        for row in query_all:
            if row.operational_state in states.APPROVED_REACTIVATE_STATES:
                row.operational_state = states.START  # pyright: ignore
        session.commit()
    except SQLAlchemyError as e:
        logger.error("SQLAlchemy Error: %s", e)

    num = session.query(VerfierMain.agent_id).count()
    if num > 0:
        agent_ids = session.query(VerfierMain.agent_id).all()
        logger.info("Agent ids in db loaded from file: %s", agent_ids)

    logger.info("Starting Cloud Verifier (tornado) on port %s, use <Ctrl-C> to stop", verifier_port)

    # print out API versions we support
    keylime_api_version.log_api_versions(logger)

    # Get the server TLS context
    ssl_ctx = web_util.init_mtls("verifier", logger=logger)

    app = tornado.web.Application(
        [
            (r"/v?[0-9]+(?:\.[0-9]+)?/verify/identity", VerifyIdentityHandler),
            (r"/v?[0-9]+(?:\.[0-9]+)?/agents/.*", AgentsHandler),
            (r"/v?[0-9]+(?:\.[0-9]+)?/allowlists/.*", AllowlistHandler),
            (r"/v?[0-9]+(?:\.[0-9]+)?/mbpolicies/.*", MbpolicyHandler),
            (r"/versions?", VersionHandler),
            (r".*", MainHandler),
        ]
    )

    sockets = tornado.netutil.bind_sockets(int(verifier_port), address=verifier_host)

    def server_process(task_id: int, agents: List[VerfierMain]) -> None:
        logger.info("Starting server of process %s", task_id)
        assert isinstance(engine, Engine)
        engine.dispose()
        server = tornado.httpserver.HTTPServer(app, ssl_options=ssl_ctx, max_buffer_size=max_upload_size)
        server.add_sockets(sockets)

        def server_sig_handler(*_: Any) -> None:
            logger.info("Shutting down server %s..", task_id)
            # Stop server to not accept new incoming connections
            server.stop()

            # Wait for all connections to be closed and then stop ioloop
            async def stop() -> None:
                await server.close_all_connections()
                tornado.ioloop.IOLoop.current().stop()

            asyncio.ensure_future(stop())

        # Attach signal handler to ioloop.
        # Do not use signal.signal(..) for that because it does not work!
        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGINT, server_sig_handler)
        loop.add_signal_handler(signal.SIGTERM, server_sig_handler)

        server.start()
        # Reactivate agents
        asyncio.ensure_future(activate_agents(agents, verifier_host, int(verifier_port)))
        tornado.ioloop.IOLoop.current().start()
        logger.debug("Server %s stopped.", task_id)
        sys.exit(0)

    processes: List[Process] = []

    run_revocation_notifier = "zeromq" in revocation_notifier.get_notifiers()

    def sig_handler(*_: Any) -> None:
        if run_revocation_notifier:
            revocation_notifier.stop_broker()
        for p in processes:
            p.join()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)
    if run_revocation_notifier:
        logger.info(
            "Starting service for revocation notifications on port %s",
            config.getint("verifier", "zmq_port", section="revocations"),
        )
        revocation_notifier.start_broker()

    num_workers = config.getint("verifier", "num_workers")
    if num_workers <= 0:
        num_workers = tornado.process.cpu_count()

    agents = get_agents_by_verifier_id(verifier_id)
    for task_id in range(0, num_workers):
        active_agents = [agents[i] for i in range(task_id, len(agents), num_workers)]
        process = Process(target=server_process, args=(task_id, active_agents))
        process.start()
        processes.append(process)
