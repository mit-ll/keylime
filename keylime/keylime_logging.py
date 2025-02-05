import contextvars
import logging
import sys
from configparser import RawConfigParser
from contextlib import contextmanager
from logging import Logger
from logging import config as logging_config
from typing import TYPE_CHECKING, Any, Callable, Dict, Generator, Optional, Tuple, cast

from keylime import config

if TYPE_CHECKING:
    from logging import LogRecord

# Default logging configuration
DEFAULT_LOGGING_CONFIG = {
    "version": 1,
    "root": {"level": "INFO", "handlers": ["consoleHandler"]},
    "loggers": {
        "keylime": {  # Keylime logger
            "level": "INFO",
        },
    },
    "handlers": {
        "consoleHandler": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "formatter_formatter",
            "stream": "ext://sys.stdout",  # Outputs to console
        }
    },
    "formatters": {
        "formatter_formatter": {
            "format": "%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
}

try:
    logging_config.dictConfig(DEFAULT_LOGGING_CONFIG)
except KeyError:
    logging.basicConfig(format="%(asctime)s %(name)-12s %(levelname)-8s %(message)s", level=logging.DEBUG)


request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id")


def set_log_func(loglevel: int, logger: Logger) -> Callable[..., None]:
    """
    Returns the appropriate logging function (e.g., info, debug) based on the provided log level.

    Args:
        loglevel (int): The desired log level (e.g., logging.INFO).
        logger (Logger): The logger instance to use.

    Returns:
        Callable[..., None]: The logger function corresponding to the log level.
    """
    log_func = logger.info

    if loglevel == logging.CRITICAL:
        log_func = logger.critical
    elif loglevel == logging.ERROR:
        log_func = logger.error
    elif loglevel == logging.WARNING:
        log_func = logger.warning
    elif loglevel == logging.INFO:
        log_func = logger.info
    elif loglevel == logging.DEBUG:
        log_func = logger.debug

    return log_func


def log_http_response(logger: Logger, loglevel: int, response_body: Dict[str, Any]) -> bool:
    """
    Logs the HTTP response details based on the log level and response body structure.

    Args:
        logger (Logger): The logger instance to use for logging.
        loglevel (int): The log level to use for the response.
        response_body (Dict[str, Any]): The HTTP response body as a dictionary.

    Returns:
        bool: True if the response was successfully logged, False otherwise.
    """
    if None in [response_body, logger]:
        return False

    log_func = set_log_func(loglevel, logger)

    matches = ["results", "code", "status"]
    if all(x in response_body for x in matches):
        log_func(f"Response code {response_body['code']}: {response_body['status']}")
    else:
        logger.error("Error: unexpected or malformed http response payload")
        return False

    return True


def annotate_logger(logger: Logger) -> None:
    """
    Adds a request ID filter to all handlers of the specified logger.

    Args:
        logger (Logger): The logger instance to annotate.
    """
    request_id_filter = RequestIDFilter()

    for handler in logger.handlers:
        handler.addFilter(request_id_filter)


def _configure_logging_from_raw(raw_config: RawConfigParser) -> None:
    """
    Dynamically configures logging based on a RawConfigParser object.

    Args:
        raw_config (RawConfigParser): The source configuration containing logging sections.
    """
    # Step 1: Configure formatters
    formatters = {}
    for section in raw_config.sections():
        if section.startswith("formatter_"):
            formatter_name = section.split("_", 1)[1]
            formatter_options = dict(raw_config.items(section))
            format_str = formatter_options.get("format", "%(message)s")
            datefmt = formatter_options.get("datefmt", None)
            formatters[formatter_name] = logging.Formatter(format_str, datefmt)

    # Step 2: Configure handlers
    handlers = {}
    for section in raw_config.sections():
        if section.startswith("handler_"):
            handler_name = section.split("_", 1)[1]
            handler_options = dict(raw_config.items(section))
            handler_class = handler_options.get("class", "logging.StreamHandler")
            level = handler_options.get("level", "NOTSET").upper()
            formatter_name = handler_options.get("formatter", "NOTSET")

            # Parse args safely
            args = _parse_args(handler_options.get("args", "()"))
            handler: logging.Handler
            try:
                if "StreamHandler" in handler_class:
                    handler = logging.StreamHandler(stream=sys.stdout if not args else args[0])
                elif "FileHandler" in handler_class:
                    filename = args[0]
                    handler = logging.FileHandler(filename=filename)
                else:
                    raise ValueError(f"Unsupported handler class: {handler_class}")

                handler.setLevel(getattr(logging, level, logging.NOTSET))
                if formatter_name in formatters:
                    handler.setFormatter(formatters[formatter_name])

                handlers[handler_name] = handler
            except Exception as e:
                print(f"Error configuring handler {handler_name}: {e}", file=sys.stderr)

    # Step 3: Configure root logger
    if "logger_root" in raw_config.sections():
        root_logger = logging.getLogger()
        root_options = dict(raw_config.items("logger_root"))
        level = root_options.get("level", "NOTSET").upper()
        handler_names = [name.strip() for name in root_options.get("handlers", "").split(",") if name]

        # Set root logger level
        root_logger.setLevel(level)

        # Clear existing handlers
        root_logger.handlers = []

        # Attach new handlers
        for handler_name in handler_names:
            if handler_name in handlers:
                root_logger.addHandler(handlers[handler_name])

    # Step 4: Configure other loggers
    for section in raw_config.sections():
        if section.startswith("logger_") and section != "logger_root":
            logger_name = section.split("_", 1)[1]
            logger_options = dict(raw_config.items(section))
            level = logger_options.get("level", "NOTSET").upper()
            propagate = logger_options.get("propagate", "1") == "1"
            handler_names = [name.strip() for name in logger_options.get("handlers", "").split(",") if name]

            logger = logging.getLogger(logger_name)
            logger.setLevel(level)
            logger.propagate = propagate

            # Attach handlers
            logger.handlers = []
            for handler_name in handler_names:
                if handler_name in handlers:
                    logger.addHandler(handlers[handler_name])


def _parse_args(args_str: str) -> Tuple[Any, ...]:
    """
    Safely parse the `args` string from the configuration.

    Args:
        args_str (str): The string representation of arguments (e.g., "(sys.stdout,)").

    Returns:
        tuple: A parsed tuple of arguments.
    """
    if args_str == "()":
        return ()

    if args_str == "(sys.stdout,)":
        return (sys.stdout,)

    if args_str.startswith("(") and args_str.endswith(")"):
        args_list = args_str[1:-1].split(",")  # Remove parentheses and split
        args_list = [arg.strip() for arg in args_list if arg.strip()]
        # Handle basic parsing (extend this for your specific cases)
        parsed_args = []
        for arg in args_list:
            if arg == "sys.stdout":
                parsed_args.append(sys.stdout)
            elif arg == "sys.stderr":
                parsed_args.append(sys.stderr)
            else:
                # Handle as string or other basic types
                parsed_args.append(arg)
        return tuple(parsed_args)

    raise ValueError(f"Invalid args format: {args_str}")


@contextmanager
def _safe_logging_configuration() -> Generator[None, None, None]:
    """
    Context manager to safely apply logging configuration. If an error occurs,
    all loggers (root and named) are restored to their original state, including handlers and formatters.
    """
    # Backup all existing loggers and their handlers
    existing_loggers: dict[str, dict[str, list[logging.Handler] | int | bool]] = {
        name: {
            "handlers": list(logger.handlers),
            "level": logger.level,
            "propagate": logger.propagate,
        }
        for name, logger in logging.Logger.manager.loggerDict.items()
        if isinstance(logger, logging.Logger)  # Ensure it's a valid logger
    }
    # Backup root logger
    root_logger: Logger = logging.getLogger()
    root_backup: dict[str, list[logging.Handler] | int] = {
        "handlers": list(root_logger.handlers),
        "level": root_logger.level,
    }

    try:
        yield  # Run the logging configuration
    except Exception:
        # Restore potentially affected loggers
        for name, logger in logging.Logger.manager.loggerDict.items():
            if name in existing_loggers and isinstance(logger, logging.Logger):
                logger.handlers = cast(list[logging.Handler], existing_loggers[name]["handlers"])
                logger.level = cast(int, existing_loggers[name]["level"])
                logger.propagate = cast(bool, existing_loggers[name]["propagate"])
        # Restore root logger
        root_logger.handlers = cast(list[logging.Handler], root_backup["handlers"])
        root_logger.setLevel(cast(int, root_backup["level"]))
        raise


def _safe_get_config(loggername: str) -> Optional[RawConfigParser]:
    try:
        return config.get_config(loggername)
    except Exception:
        return None


def init_logging(loggername: str) -> Logger:
    """
    Initializes the logging system for a specific logger.

    This function applies the logger's configuration dynamically, disables unnecessary logs,
    and ensures the logging system is properly annotated with metadata.

    Args:
        loggername (str): The name of the logger to initialize.

    Returns:
        Logger: The initialized logger instance.
    """
    logger = logging.getLogger(f"keylime.{loggername}")

    component_config = _safe_get_config(loggername)

    # Apply the component logging configuration (if available)
    if component_config:
        try:
            with _safe_logging_configuration():
                _configure_logging_from_raw(component_config)
        except Exception as e:
            logger.error("Logging configuration error: %s", e)

    logging.getLogger("requests").setLevel(logging.WARNING)

    # Disable default Tornado logs, as we are outputting more detail to the 'keylime.web' logger
    logging.getLogger("tornado.general").disabled = True
    logging.getLogger("tornado.access").disabled = True
    logging.getLogger("tornado.application").disabled = True

    # Add metadata to root logger, so that it is inherited by all
    annotate_logger(logging.getLogger())

    return logger


class RequestIDFilter(logging.Filter):
    """
    A logging filter that adds a request ID to log records.

    This filter retrieves the request ID from the `request_id_var` context variable
    and attaches it to each log record as `reqid` and `reqidf`.

    Attributes:
        reqid (str): The raw request ID.
        reqidf (str): The formatted request ID for inclusion in log messages.
    """

    def filter(self, record: "LogRecord") -> bool:
        reqid = request_id_var.get("")

        record.reqid = reqid
        record.reqidf = f"(reqid={reqid})" if reqid else ""

        return True
