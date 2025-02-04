from sqlalchemy import Boolean, Column, ForeignKey, Integer, LargeBinary, PickleType, String, Text, schema
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

from keylime.json import JSONPickler

Base = declarative_base()


class JSONPickleType(PickleType):  # pylint: disable=abstract-method,too-many-ancestors
    impl = Text
    cache_ok = True


class VerfierMain(Base):
    __tablename__ = "verifiermain"
    agent_id = Column(String(80), primary_key=True)
    v = Column(String(45), nullable=True)
    ip = Column(String(15))
    verifier_id = Column(String(80))
    verifier_ip = Column(String(15))
    verifier_port = Column(Integer)
    port = Column(Integer)
    operational_state = Column(Integer)
    public_key = Column(String(500))
    tpm_policy = Column(JSONPickleType(pickler=JSONPickler))
    meta_data = Column(String(200))
    ima_policy = relationship("VerifierAllowlist", back_populates="agent", uselist=False)
    ima_policy_id = Column(Integer, ForeignKey("allowlists.id"))
    ima_sign_verification_keys = Column(Text().with_variant(Text(429400000), "mysql"))
    mb_policy = relationship("VerifierMbpolicy", back_populates="agent", uselist=False)
    mb_policy_id = Column(Integer, ForeignKey("mbpolicies.id"))
    revocation_key = Column(String(2800))
    accept_tpm_hash_algs = Column(JSONPickleType(pickler=JSONPickler))
    accept_tpm_encryption_algs = Column(JSONPickleType(pickler=JSONPickler))
    accept_tpm_signing_algs = Column(JSONPickleType(pickler=JSONPickler))
    hash_alg = Column(String(10))
    enc_alg = Column(String(10))
    sign_alg = Column(String(10))
    boottime = Column(Integer)
    ima_pcrs = Column(JSONPickleType(pickler=JSONPickler))
    pcr10 = Column(LargeBinary)
    next_ima_ml_entry = Column(Integer)
    severity_level = Column(Integer, nullable=True)
    last_event_id = Column(String(200), nullable=True)
    learned_ima_keyrings = Column(JSONPickleType(pickler=JSONPickler))
    supported_version = Column(String(20))
    ak_tpm = Column(String(500))
    mtls_cert = Column(String(2048), nullable=True)
    attestation_count = Column(Integer)
    last_received_quote = Column(Integer)
    last_successful_attestation = Column(Integer)
    tpm_clockinfo = Column(JSONPickleType(pickler=JSONPickler))
    accept_attestations = Column(Boolean)


class VerifierAllowlist(Base):
    __tablename__ = "allowlists"
    __table_args__ = (schema.UniqueConstraint("name", name="uniq_allowlists0name"),)
    id = Column(Integer, primary_key=True)
    agent = relationship("VerfierMain", back_populates="ima_policy")
    name = Column(String(255), nullable=False)
    checksum = Column(String(128))
    generator = Column(Integer)
    tpm_policy = Column(Text())
    ima_policy = Column(Text().with_variant(Text(429400000), "mysql"))


class VerifierMbpolicy(Base):
    __tablename__ = "mbpolicies"
    __table_args__ = (schema.UniqueConstraint("name", name="uniq_mbpolicies_name"),)
    id = Column(Integer, primary_key=True)
    agent = relationship("VerfierMain", back_populates="mb_policy")
    name = Column(String(255), nullable=False)
    mb_policy = Column(Text().with_variant(Text(429400000), "mysql"))
