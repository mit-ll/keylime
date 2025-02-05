import logging
import unittest
from configparser import RawConfigParser
from unittest.mock import patch

from keylime.keylime_logging import (
    RequestIDFilter,
    _configure_logging_from_raw,
    _safe_logging_configuration,
    annotate_logger,
    init_logging,
    log_http_response,
    set_log_func,
)


class TestKeylimeLogging(unittest.TestCase):
    def setUp(self):
        """
        Set up test environment with a sample RawConfigParser.
        """
        self.raw_config = RawConfigParser()
        self.raw_config.read_string(
            """
        [formatter_simple]
        format = %(asctime)s - %(name)s - %(levelname)s - %(message)s
        datefmt = %Y-%m-%d %H:%M:%S

        [handler_console]
        class = logging.StreamHandler
        level = DEBUG
        formatter = simple
        args = (sys.stdout,)

        [logger_root]
        level = DEBUG
        handlers = console

        [logger_keylime.custom]
        level = INFO
        handlers = console
        propagate = 0
        """
        )

    def tearDown(self):
        """
        Reset logging configuration after each test to ensure isolation.
        """
        logging.shutdown()

    def test_set_log_func(self):
        """
        Test that set_log_func returns the correct logging function based on log level.
        """
        logger = logging.getLogger("test")
        self.assertEqual(set_log_func(logging.INFO, logger), logger.info)
        self.assertEqual(set_log_func(logging.DEBUG, logger), logger.debug)
        self.assertEqual(set_log_func(logging.ERROR, logger), logger.error)

    def test_log_http_response(self):
        """
        Test that log_http_response logs correctly based on response payload.
        """
        logger = logging.getLogger("test")
        logger.setLevel(logging.INFO)
        with self.assertLogs(logger, level="INFO") as log:
            response_body = {"results": [], "code": 200, "status": "OK"}
            success = log_http_response(logger, logging.INFO, response_body)
            self.assertTrue(success)
            self.assertIn("Response code 200: OK", log.output[0])

        with self.assertLogs(logger, level="ERROR") as log:
            response_body = {"results": []}  # Malformed response
            success = log_http_response(logger, logging.INFO, response_body)
            self.assertFalse(success)
            self.assertIn("Error: unexpected or malformed http response payload", log.output[0])

    def test_annotate_logger(self):
        """
        Test that annotate_logger adds RequestIDFilter to all handlers.
        """
        logger = logging.getLogger("test")
        handler = logging.StreamHandler()
        logger.addHandler(handler)

        annotate_logger(logger)
        self.assertTrue(any(isinstance(f, RequestIDFilter) for f in handler.filters))

    def test_configure_logging_from_raw(self):
        """
        Test that _configure_logging_from_raw correctly configures loggers and handlers.
        """
        _configure_logging_from_raw(self.raw_config)

        root_logger = logging.getLogger()
        self.assertEqual(root_logger.level, logging.DEBUG)
        self.assertEqual(len(root_logger.handlers), 1)
        self.assertIsInstance(root_logger.handlers[0], logging.StreamHandler)

        custom_logger = logging.getLogger("keylime.custom")
        self.assertEqual(custom_logger.level, logging.INFO)
        self.assertEqual(len(custom_logger.handlers), 1)
        self.assertFalse(custom_logger.propagate)

    def test_safe_logging_configuration(self):
        """
        Test that _safe_logging_configuration restores logging state after an error.
        """
        root_logger = logging.getLogger()
        original_level = root_logger.level

        try:
            with _safe_logging_configuration():
                root_logger.setLevel(logging.CRITICAL)
                self.assertEqual(root_logger.level, logging.CRITICAL)
                raise RuntimeError("Simulated error")
        except RuntimeError:
            pass

        self.assertEqual(root_logger.level, original_level)

    @patch("keylime.keylime_logging._safe_get_config")
    def test_init_logging(self, mock_safe_get_config):
        """
        Test that init_logging initializes the logger correctly.
        """
        mock_safe_get_config.return_value = self.raw_config

        logger = init_logging("custom")

        self.assertEqual(logger.name, "keylime.custom")
        self.assertEqual(logger.level, logging.INFO)
        self.assertEqual(len(logger.handlers), 1)
        self.assertIsInstance(logger.handlers[0], logging.StreamHandler)


if __name__ == "__main__":
    unittest.main()
