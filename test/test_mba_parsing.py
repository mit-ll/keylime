import os
import tempfile
import unittest
from configparser import RawConfigParser

from keylime import config
from keylime.cmd import convert_config
from keylime.common.algorithms import Hash
from keylime.mba import mba

TEMPLATES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "templates"))


class TestMBAParsing(unittest.TestCase):
    def test_parse_bootlog(self):
        """Test parsing binary measured boot event log"""
        # This test requires the verifier configuration file, so let's create
        # one with the default values to use, so that we do not depend on the
        # configuration files existing in the test system.
        with tempfile.TemporaryDirectory() as config_dir:
            # Let's write the config file for the verifier.
            verifier_config = convert_config.process_versions(["verifier"], TEMPLATES_DIR, RawConfigParser(), True)
            convert_config.output(["verifier"], verifier_config, TEMPLATES_DIR, config_dir)

            # As we want to use a config file from a different location, the
            # proper way would be to define an environment variable for the
            # module of interest, e.g. in our case it would be the
            # KEYLIME_VERIFIER_CONFIG variable. However, the config module
            # reads such env vars at first load, and there is no clean way
            # to have it re-read them, so for this test we will override it
            # manually.
            config.CONFIG_ENV["verifier"] = os.path.abspath(os.path.join(config_dir, "verifier.conf"))

            mba.load_imports()
            # Use the file that triggered https://github.com/keylime/keylime/issues/1153
            mb_log_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "data/mb_log.b64"))
            with open(mb_log_path, encoding="utf-8") as f:
                # Read the base64 input and remove the newlines
                b64 = "".join(f.read().splitlines())
                pcr_hashes, boot_aggregates, measurement_data, failure = mba.bootlog_parse(b64, Hash.SHA256)

                self.assertFalse(
                    failure,
                    f"Parsing of measured boot log failed with: {list(map(lambda x: x.context, failure.events))}",
                )
                self.assertTrue(isinstance(pcr_hashes, dict))
                self.assertTrue(isinstance(boot_aggregates, dict))
                self.assertTrue(isinstance(measurement_data, dict))


if __name__ == "__main__":
    unittest.main()
