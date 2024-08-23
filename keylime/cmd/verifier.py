from keylime import cloud_verifier_tornado, config, keylime_logging
from keylime.common.migrations import apply
from keylime.mba import mba
import asyncio
import tornado.process

from keylime.web import VerifierServer
from keylime.models import da_manager, db_manager


logger = keylime_logging.init_logging("verifier")


def main() -> None:
    # if we are configured to auto-migrate the DB, check if there are any migrations to perform
    if config.has_option("verifier", "auto_migrate_db") and config.getboolean("verifier", "auto_migrate_db"):
        apply("cloud_verifier")

    # Explicitly load and initialize measured boot components
    mba.load_imports()

    # TODO: Remove
    # cloud_verifier_tornado.main()

    """ db_manager.make_engine("cloud_verifier")
    server = VerifierServer(http_port=8881)
    tornado.process.fork_processes(0)
    asyncio.run(server.start()) """

    # Prepare to use the cloud_verifier database
    db_manager.make_engine("cloud_verifier")
    # Prepare backend for durable attestation, if configured
    #da_manager.make_backend("cloud_verifier")

    # Start HTTP server
    server = VerifierServer(http_port=8881)
    server.start_multi()

    # db_manager.make_engine("cloud_verifier")

    # server = VerifierServer()
    # tornado.process.fork_processes(0)
    # asyncio.run(server.start())


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
