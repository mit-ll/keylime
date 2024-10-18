from sqlalchemy import Column, Integer, PickleType, String, Text
from sqlalchemy.ext.declarative import declarative_base

from keylime.json import JSONPickler

Base = declarative_base()


class JSONPickleType(PickleType):  # pylint: disable=abstract-method,too-many-ancestors
    impl = Text
    cache_ok = True


class RegistrarMain(Base):
    __tablename__ = "registrarmain"
    agent_id = Column(String(80), primary_key=True)
    key = Column(String(45))
    aik_tpm = Column(String(500))
    ekcert = Column(String(2048))
    ek_ca_chain = Column(String(8192))
    ek_tpm = Column(String(2048))
    iak_tpm = Column(String(500))
    idevid_tpm = Column(String(500))
    iak_cert = Column(String(2048))
    idevid_cert = Column(String(2048))
    mtls_cert = Column(String(2048), nullable=True)
    virtual = Column(Integer)
    ip = Column(String(15), nullable=True)
    port = Column(Integer, nullable=True)
    active = Column(Integer)
    provider_keys = Column(JSONPickleType(pickler=JSONPickler))
    regcount = Column(Integer)
