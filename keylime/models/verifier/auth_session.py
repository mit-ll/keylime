import base64
from datetime import timedelta
import random
import string

from keylime import config
from keylime.models.base import *
from keylime.tpm.tpm_main import Tpm
from keylime.db.verifier_db import VerfierMain

from keylime.db.keylime_db import DBEngineManager, SessionManager
from keylime.tpm.errors import IncorrectSignature, QualifyingDataMismatch, ObjectNameMismatch, HashAlgorithmMismatch, SignatureAlgorithmMismatch
from sqlalchemy.orm import Session

engine = DBEngineManager().make_engine("cloud_verifier")

def get_session() -> Session:
    return SessionManager().make_session(engine)


class AuthSession(PersistableModel):
    @classmethod
    def _schema(cls):
        # TODO: Uncomment
        # cls._belongs_to("agent", VerifierAgent, inverse_of="sessions", preload = False)

        cls._persist_as("sessions")
        cls._id("token", String(22))
        cls._field("active", Boolean)
        cls._field("agent_id", String(80))
        cls._field("nonce", Nonce)
        cls._field("nonce_created_at", Timestamp)
        cls._field("nonce_expires_at", Timestamp)
        cls._virtual("supported_hash_algorithms", List)
        cls._virtual("supported_signing_schemes", List)
        cls._field("hash_algorithm", String(10))
        cls._field("signing_scheme", String(10))
        cls._field("ak_attest", Binary)
        cls._field("ak_sign", Binary)
        cls._field("pop_received_at", Timestamp)
        cls._field("token_expires_at", Timestamp)

    @classmethod
    def authenticate_agent(cls, token):
        auth_session = cls.get(token)

        if not auth_session or not auth_session.active:
            return False

        session = get_session()
        agent = session.query(VerfierMain).filter(VerfierMain.agent_id == auth_session.agent_id).one_or_none()

        return agent

    @classmethod
    def create(cls, agent, data):
        session = AuthSession.empty()
        session.initialise(agent.agent_id)
        session.receive_capabilities(data, agent)
        return session
    
    @classmethod
    def delete_stale(cls, agent_id):
        agent_sessions = AuthSession.all(agent_id=agent_id)

        for session in agent_sessions:
            if session.nonce_expires_at >= Timestamp.now() or session.token_expires_at >= Timestamp.now():
                session.delete()
    
    def initialise(self, agent_id):
        if "agent_id" not in self.values:
            self.agent_id = agent_id
        
        if "token" not in self.values:
            charset = string.ascii_uppercase + string.ascii_lowercase + string.digits
            self.token = "".join(random.SystemRandom().choice(charset) for _ in range(22))

        if "active" not in self.values:
            self.active = False

    def receive_capabilities(self, data, agent):
        if self.nonce:
            raise ValueError("AuthSession object cannot be updated as it has already received agent capabilities")

        # Set fields from capabilities reported by the agent
        self.cast_changes(data, ["supported_hash_algorithms", "supported_signing_schemes"])
        self.validate_required(["supported_hash_algorithms", "supported_signing_schemes"])

        # Generate the nonce the agent should use in the call to TPM2_Certify
        self._set_nonce()
        # Select algorithms from the list given by the agent
        self._set_algs(data, agent)

        self._set_timestamps()

    def receive_pop(self, agent, data):
        if not agent or not agent.agent_id == self.agent_id:
            return

        ak_tpm = base64.b64decode(agent.ak_tpm)
        self.cast_changes(data, ["ak_attest", "ak_sign"])

        try:
            Tpm.verify_tpm_object(ak_tpm, ak_tpm, self.ak_attest, self.ak_sign, qual=self.nonce, hash_alg=self.hash_algorithm, sign_alg=self.signing_scheme)
        except QualifyingDataMismatch:
            self._add_error("ak_attest", "must include the nonce as qualifying data")
        except ObjectNameMismatch:
            self._add_error("ak_attest", "must include the AK of the agent as the certified object")
        except HashAlgorithmMismatch:
            self._add_error("ak_attest", f"must specify {self.hash_algorithm} as the hash algorithm")
        except SignatureAlgorithmMismatch:
            self._add_error("ak_attest", f"must specify {self.signing_scheme} as the signature scheme")
        except IncorrectSignature:
            self._add_error("ak_sign", "must verify against ak_attest using the agent's AK")

        session_lifetime = config.getint("verifier", "session_lifetime")
        self.token_expires_at = Timestamp.now() + timedelta(session_lifetime)
        self.active = True

    def _set_nonce(self):
        if "nonce" not in self.values:
            self.nonce = Nonce.generate(128)

    def _set_algs(self, data, agent):
        # pylint: disable=no-else-break

        supported_hash_algorithms = data.get("supported_hash_algorithms")
        supported_signing_schemes = data.get("supported_signing_schemes")

        # Set hashing algorithm that is first match from the list of hashing supported by the agent tpm
        # and the list of accpeted hashing algorithm
        for hash_alg in agent.accept_tpm_hash_algs:
            if hash_alg in supported_hash_algorithms:
                self.hash_algorithm = hash_alg
                break
        
        if not self.hash_algorithm:
            self._add_error(
                "supported_hash_algorithms",
                f"does not contain any accepted hashing algorithm for agent '{agent.agent_id}'",
            )

        # Set signing algorithm that is first match from the list of signing supported by the agent tpm
        # and the list of accpeted signing algorithm
        for signing_scheme in agent.accept_tpm_signing_algs:
            if signing_scheme in supported_signing_schemes:
                self.signing_scheme = signing_scheme
                break

        if not self.signing_scheme:
            self._add_error(
                "supported_signing_schemes",
                f"does not contain any accepeted signing scheme for agent '{agent.agent_id}'",
            )

    def _set_timestamps(self):
        nonce_lifetime = config.getint("verifier", "nonce_lifetime")

        if self.changes.get("nonce"):
            self.nonce_created_at = Timestamp.now()
            self.nonce_expires_at = self.nonce_created_at + timedelta(nonce_lifetime)

        if self.changes.get("ak_attest", "ak_sign"):
            self.pop_received_at = Timestamp.now()
    
    def render(self, agent, only=None):
        if not only:
            only = ["token", "active", "nonce", "agent_id", "token_expires_at"]

        output = super().render(only)
        return output
