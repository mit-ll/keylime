import os
from configparser import NoOptionError
from contextlib import contextmanager
from sqlite3 import Connection as SQLite3Connection
from typing import Any, Dict, Iterator, Optional, cast

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, registry, scoped_session, sessionmaker  # type: ignore[attr-defined]

from keylime import config, keylime_logging
from keylime.models.base.errors import BackendMissing

logger = keylime_logging.init_logging("keylime_db")


# make sure referential integrity is working for SQLite
@event.listens_for(Engine, "connect")  # type: ignore
def _set_sqlite_pragma(dbapi_connection: SQLite3Connection, _: Any) -> None:
    if isinstance(dbapi_connection, SQLite3Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


class DBManager:
    def __init__(self) -> None:
        self._service: Optional[str] = None
        self._engine: Optional[Engine] = None
        self._registry = None
        self._scoped_session = None

    def make_engine(self, service: str) -> Engine:
        # Keep DB related stuff as it is, but read configuration from new
        # configs
        if service == "cloud_verifier":
            config_service = "verifier"
        else:
            config_service = service

        self._service = service

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

        self._engine = create_engine(url, **engine_args)  # type: ignore
        self._registry = registry()
        return self._engine  # type: ignore

    @property
    def service(self) -> Optional[str]:
        if not self._service:
            raise BackendMissing("cannot access the service for a DBManager before a call to db_manager.make_engine()")

        return self._service

    @property
    def engine(self) -> Engine:
        if not self._engine:
            raise BackendMissing("cannot access the engine for a DBManager before a call to db_manager.make_engine()")

        return self._engine

    @property
    def registry(self) -> registry:
        if not self._registry:
            raise BackendMissing("cannot access the registry for a DBManager before a call to db_manager.make_engine()")

        return self._registry

    def session(self) -> Session:
        """
        To use: session = self.session()
        """
        if not self._registry:
            raise BackendMissing("cannot access the session for a DBManager before a call to db_manager.make_engine()")

        if not self._scoped_session:
            self._scoped_session = scoped_session(sessionmaker())

            try:
                self._scoped_session.configure(bind=self.engine)
                self._scoped_session.configure(expire_on_commit=False)
            except SQLAlchemyError as err:
                logger.error("Error creating SQL session manager %s", err)

        return cast(Session, self._scoped_session())

    @contextmanager
    def session_context(self) -> Iterator[Session]:
        session = self.session()

        try:
            yield session
            session.commit()
        except:
            session.rollback()
            raise


# Create a global DBManager which can be referenced from any module
db_manager = DBManager()
