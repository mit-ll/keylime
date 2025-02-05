import os
from configparser import NoOptionError
from sqlite3 import Connection as SQLite3Connection
from typing import Any, Dict, Optional, cast

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, scoped_session, sessionmaker

from keylime import config, keylime_logging

logger = keylime_logging.init_logging("keylime_db")


# make sure referential integrity is working for SQLite
@event.listens_for(Engine, "connect")  # type: ignore
def _set_sqlite_pragma(dbapi_connection: SQLite3Connection, _: Any) -> None:
    if isinstance(dbapi_connection, SQLite3Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


class DBEngineManager:
    service: Optional[str]

    def __init__(self) -> None:
        self.service = None

    def make_engine(self, service: str) -> Engine:
        """
        To use: engine = self.make_engine('cloud_verifier')
        """

        # Keep DB related stuff as it is, but read configuration from new
        # configs
        if service == "cloud_verifier":
            config_service = "verifier"
        else:
            config_service = service

        self.service = service

        try:
            p_sz_m_ovfl = config.get(config_service, "database_pool_sz_ovfl")
            p_sz, m_ovfl = p_sz_m_ovfl.split(",")
        except NoOptionError:
            p_sz = "5"
            m_ovfl = "10"

        engine_args: Dict[str, Any] = {}

        url = config.get(config_service, "database_url")
        if url:
            logger.info("database_url is set, using it to establish database connection")

            # If the keyword sqlite is provided as the database url, use the
            # cv_data.sqlite for the verifier or the file reg_data.sqlite for
            # the registrar, located at the config.WORK_DIR directory
            if url == "sqlite":
                logger.info(
                    "database_url is set as 'sqlite' keyword, using default values to establish database connection"
                )
                if service == "cloud_verifier":
                    database = "cv_data.sqlite"
                elif service == "registrar":
                    database = "reg_data.sqlite"
                else:
                    logger.error("Tried to setup database access for unknown service '%s'", service)
                    raise Exception(f"Unknown service '{service}' for database setup")

                database_file = os.path.abspath(os.path.join(config.WORK_DIR, database))
                url = f"sqlite:///{database_file}"

                kl_dir = os.path.dirname(os.path.abspath(database_file))
                if not os.path.exists(kl_dir):
                    os.makedirs(kl_dir, 0o700)

                engine_args["connect_args"] = {"check_same_thread": False}

            if not url.count("sqlite:"):
                engine_args["pool_size"] = int(p_sz)
                engine_args["max_overflow"] = int(m_ovfl)
                engine_args["pool_pre_ping"] = True

        # Enable DB debugging
        if config.DEBUG_DB and config.INSECURE_DEBUG:
            engine_args["echo"] = True

        engine = create_engine(url, **engine_args)
        return engine


class SessionManager:
    engine: Optional[Engine]

    def __init__(self) -> None:
        self.engine = None

    def make_session(self, engine: Engine) -> Session:
        """
        To use: session = self.make_session(engine)
        """
        self.engine = engine
        my_session = scoped_session(sessionmaker())
        try:
            my_session.configure(bind=self.engine)  # type: ignore
        except SQLAlchemyError as err:
            logger.error("Error creating SQL session manager %s", err)
        return cast(Session, my_session())
