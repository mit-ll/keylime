#!/usr/bin/env python3

"""
 This script parses the content of a configuration file and use the data to
 replace the values in templates to generate new configuration files.  The
 process is controlled by the "mapping" dictionary, provided through a JSON
 file.

 ## Full mapping

 The full mapping dictionary has the "type" field set as "full".  Mappings
 without a "type" field are processed as if they were full mappings to support
 older versions of the mapping were the "type" field is missing.

 This dictionary maps the name of the new option to a dictionary with the info
 from the old configuration file format.

 The dictionary has the following fields:
 * "version": The mapping version. Should match the target configuration version
 number
 * "type": The mapping type. For the full mapping, this should be set as "full".
 If this field is missing, the mapping will be treated as a full mapping for
 compatibility
 * "components": A dictionary which keys are the components for which the
 configuration files should be generated. The keys in the "components"
 dictionary should match the template file names without the extension (e.g.
 for the agent component, the key should be "agent" and the template file name
 should be "agent.j2").
 * "subcomponents": A dictionary which maps sections names without a version
 number to the main section name which has the version number. The idea is that
 only the main section contains the version number for the entire file (e.g. the
 "verifier" section in the "verifier.conf" file) which will be inherited by the
 subcomponents.

 For each component in the "components" dictionary, the value is a dictionary
 which keys are the option names in the new configuration files and the value is
 a dictionary with the information used to find the data in the old
 configuration file. For each option name the value is a dictionary with the
 following fields:

 * "section": The section from the old configuration file
 * "option": The name of the option in the old configuration file
 * "default" The default value to use in case the option is missing in the
 old configuration file

 All values are treated as strings.

 An example could be:

 {
     "version": "1.0",
     "type": "full",
     "components": {
         "a_component": {
             "some_option": {
                 "section": "some_section",
                 "option" : "some_old_option_name",
                 "default": "default",
             },
             another_option: {
                 "section": "another_section",
                 "option" : "another_old_option_name",
                 "default": "default_value",
             }
         },
         "another_component": {
             "an_option": {
                 "section": "some_section",
                 "option" : "some_old_option_name",
                 "default": "default",
             },
             "another_option": {
                 "section": "another_section",
                 "option" : "another_old_option_name",
                 "default": "default_value",
             }
         }
     },
     "subcomponents" {
        "another_section": "some_section"
     }
 }

 Check "templates/2.0/mapping.json" file for an example.

 ## Update mapping

 This mapping dictionary is used to modify a configuration without listing all
 the options. Changes can be donemade through operations, specified as
 dictionaries.

 The dictionary has the following fields:

 * "version": The mapping version. Should match the target configuration version
 number
 * "type": The mapping type. For the update mapping, this should be set as
 "update". If this field is missing, the mapping will be treated as a full
 mapping for compatibility
 * "components": A dictionary which keys are the components for which the
 operations are performed. For each component, a dictionary with operations as
 keys and operands as values should be provided. For each operation the operands
 should be provided using the correct dictionary format.

 The supported operations are:

 * Add a new option

 To add optios, the component to be modified in the mapping should contain the
 "add" field set with a dictionary mapping the option name to be added to the
 default value to set. Example:

 {
     "version": "3.1",
     "type": "update",
     "components": {
         "comp_a": {
             "add": {
                 "new_option": "value",
                 "new_option2": "value2"
             }
         }
     }
 }

 * Remove an option

 To remove options, the component to be modified in the mapping should contain
 the "remove" field set with a list of options names to be removed. Example:

 {
     "version": "3.1",
     "type": "update",
     "components": {
         "comp_a": {
             "remove": ["unused_option", "another_unused_option"]
         }
     }
 }

 * Replace an option

 To replace options, the component to be modified in the mapping should contain
 the "replace" field set with a dictionary mapping names to be replaced to a
 dictionary specifying the section to receive the replacement, the new option
 name, and the default value. Example:

 {
     "version": "3.1",
     "type": "update",
     "components": {
         "comp_a": {
             "replace": {
                 "old_option_to_replace": {
                     "section": "new_section",
                     "option": "new_option",
                     "default": "value"
                 },
                 "old_value": {
                     "section": "other_section",
                     "option": "other_new_option",
                     "default": "value"
                 }
             }
         }
     }
 }

 Multiple operations can be performed through the same update mapping.

 The idea is to provide new templates, mapping, and adjust script for new
 versions of the configuration, allowing the user to easily convert from a
 version of the configuration file to the next.
"""

import argparse
import configparser
import importlib.util
import itertools
import json
import logging
import os
import re
import shutil
from configparser import RawConfigParser
from logging import Logger
from typing import Any, Dict, List, Optional, Tuple, Union

from jinja2 import Template

COMPONENTS = ["agent", "verifier", "tenant", "registrar", "ca", "logging"]

CONFIG_DIRS = ["/usr/etc/keylime", "/etc/keylime"]

# Old configuration files (before versioning was introduced)
OLD_CONFIG_FILES = ["/usr/etc/keylime.conf", "/etc/keylime.conf"]

# Configuration files
CONFIG_FILES = [os.path.join(d, f"{c}.conf") for d, c in itertools.product(CONFIG_DIRS, COMPONENTS)]

if "KEYLIME_CONFIG" in os.environ:
    CONFIG_FILES.insert(0, os.environ["KEYLIME_CONFIG"])

if "KEYLIME_AGENT_CONFIG" in os.environ:
    CONFIG_FILES.insert(0, os.environ["KEYLIME_AGENT_CONFIG"])

if "KEYLIME_VERIFIER_CONFIG" in os.environ:
    CONFIG_FILES.insert(0, os.environ["KEYLIME_VERIFIER_CONFIG"])

if "KEYLIME_REGISTRAR_CONFIG" in os.environ:
    CONFIG_FILES.insert(0, os.environ["KEYLIME_REGISTRAR_CONFIG"])

if "KEYLIME_TENANT_CONFIG" in os.environ:
    CONFIG_FILES.insert(0, os.environ["KEYLIME_TENANT_CONFIG"])

if "KEYLIME_CA_CONFIG" in os.environ:
    CONFIG_FILES.insert(0, os.environ["KEYLIME_CA_CONFIG"])

if "KEYLIME_LOGGING_CONFIG" in os.environ:
    CONFIG_FILES.insert(0, os.environ["KEYLIME_LOGGING_CONFIG"])


def str_to_version(v_str: str) -> Union[Tuple[int, int], None]:
    """
    Validates the string format and converts the provided string to a tuple of
    ints which can be sorted and compared.

    :returns: Tuple with version number parts converted to int. In case of
    invalid version string, returns None
    """

    # Strip to remove eventual quotes and spaces
    v_str = v_str.strip('" ')

    m = re.match(r"^(\d+)\.(\d+)$", v_str)

    if not m:
        return None

    return (int(m.group(1)), int(m.group(2)))


def get_config(config_files: List[List[str]], logger: Logger = logging.getLogger(__name__)) -> RawConfigParser:
    """
    Read configuration files and merge them together
    """

    flat = [s for ss in config_files for s in ss]
    if not flat:
        logger.debug("No input provided: using %s as input", CONFIG_FILES)
        files = list(x for x in CONFIG_FILES if os.path.exists(x))
    else:
        files = list(x for x in set(flat) if os.path.exists(x))
        if not files:
            raise Exception(f"None of the provided files in {set(flat)} exist")

    if not files:
        # The configuration files doesn't exist, try old file
        logger.debug("Could not find configuration files, trying to find old configuration")
        files = list(x for x in OLD_CONFIG_FILES if os.path.exists(x))

    config = configparser.RawConfigParser()
    if not files:
        logger.info("Could not find configuration files in default locations. Using default values for all options")
    else:
        # Validate that at least one config file was successfully read
        read_files = config.read(files)
        if read_files:
            logger.info("Successfully read configuration from %s", read_files)
        else:
            raise Exception(
                f"Could not parse any configuration from {files}, please check the files syntax and permissions"
            )

    return config


def output_component(
    component: str,
    config: RawConfigParser,
    template: str,
    outfile: str,
    logger: Logger = logging.getLogger(__name__),
) -> None:
    """
    Output the configuration file for a component
    """

    if os.path.exists(outfile):
        try:
            shutil.copyfile(outfile, outfile + ".bkp")
        except Exception as e:
            logger.error("Could not create backup file %s, aborting: %s", outfile + ".bkp", e)
            return

    logger.info("Writing %s configuration to %s", component, outfile)

    with open(template, "r", encoding="utf-8") as tf:
        t = tf.read()

        j2 = Template(t)

        r = j2.render(config)

        with open(outfile, "w", encoding="utf-8") as o:
            print(r, file=o)


def output(
    components: List[str],
    config: RawConfigParser,
    templates: str,
    outdir: str,
    logger: Logger = logging.getLogger(__name__),
) -> None:
    """
    Output the requested files using a template
    """

    # Check that there are templates for all components
    for component in components:
        version = config[component]["version"].strip('" ')
        version_dir = os.path.join(templates, version)
        if not os.path.isdir(version_dir):
            raise Exception(f"Could not find directory {version_dir}")

        t = os.path.join(version_dir, f"{component}.j2")
        if not os.path.exists(t):
            raise Exception(f"Template file {t} not found")

        # Set output path
        o = os.path.join(outdir, f"{component}.conf")

        output_component(component, config, t, o, logger=logger)


def needs_update(component: str, old_config: RawConfigParser, new_version: Tuple[int, int]) -> bool:
    """
    Returns whether an update is necessary for a given component and version
    """

    if component in old_config and "version" in old_config[component]:
        old_version = str_to_version(old_config[component]["version"])
        if old_version and old_version >= new_version:
            return False
    return True


def strip_quotes(config: RawConfigParser) -> None:
    """
    Remove surrounding spaces and quotes from all options
    """
    for k in config:
        for o in config[k]:
            config[k][o] = config[k][o].strip('" ')


def process_full_mapping(
    mapping: Dict[str, Any],
    old_config: RawConfigParser,
    use_defaults: bool,
    target: Optional[Tuple[int, int]] = None,
    logger: Logger = logging.getLogger(__name__),
) -> RawConfigParser:
    """
    Process full mapping
    """

    new_version = str_to_version(mapping["version"])
    if not new_version:
        raise Exception(f"Invalid version number in mapping: {mapping['version']}")

    new = configparser.RawConfigParser()

    for component in mapping["components"]:
        if component in old_config:
            if component in mapping["subcomponents"]:
                # If the component is a subcomponent, use the version from the
                # component
                version_component = mapping["subcomponents"][component]
            else:
                version_component = component

            # If the configuration file does not contain a version number, assume it is
            # in the old format and use the minimum possible version
            try:
                found_version = old_config.get(version_component, "version")
                old_version = str_to_version(found_version)

                if not old_version:
                    raise Exception("Invalid version number found in old configuration")

            except (configparser.NoOptionError, configparser.NoSectionError):
                logger.debug("No version found in old configuration for %s, using '1.0'", component)
                old_version = (1, 0)
        else:
            # If the old_version does not contain the component from the
            # mapping, use the minimum version to use defaults
            old_version = (1, 0)

        # Skip versions lower than the current version
        if old_version >= new_version:
            new[component] = old_config[component]
            continue

        # Stop if the version reached the target
        if target:
            if old_version >= target:
                new[component] = old_config[component]
                continue

        # Create a new dictionary for each component
        new.add_section(component)
        m = mapping["components"][component]

        for option in m:
            # For each option, get the dictionary with the info to search:
            # {
            #     "section": section to search
            #     "option": option name
            #     "default": value to use in case the option is missing
            info = m[option]
            try:
                if use_defaults:
                    new[component][option] = info["default"]
                else:
                    # Preserve the old value
                    new[component][option] = old_config.get(info["section"], info["option"])
            except Exception as e:
                logger.debug(
                    '[%s] %s not found: Using default value "%s" for "%s"', component, e, info["default"], option
                )
                new[component][option] = info["default"]

        # Set the resulting version for the component
        new[component]["version"] = mapping["version"]

    return new


def update_options(
    new: RawConfigParser,
    mapping: Dict[str, Any],
    component: str,
    use_defaults: bool,
    logger: Logger = logging.getLogger(__name__),
) -> None:
    """
    Process updates to a single component
    """

    operations = mapping[component]

    if "add" in operations:
        to_add = operations["add"]
        for option in to_add:
            if option in new[component]:
                logger.debug('[%s]: Skipped adding already existing option "%s"', component, option)
                continue
            new[component][option] = to_add[option]
            logger.debug('[%s]: Added new option "%s" = "%s"', component, option, to_add[option])
    if "remove" in operations:
        to_remove = operations["remove"]
        for option in to_remove:
            if option not in new[component]:
                logger.debug('[%s]: Skipped removing unexisting option "%s"', component, option)
                continue
            new[component].pop(option)
            logger.debug('[%s]: Removed option "%s"', component, option)
    if "replace" in operations:
        to_replace = operations["replace"]
        for old_option in to_replace:
            new_option = to_replace[old_option]
            # Check if the new option name is present and get the value from the
            # mapping
            if "section" not in new_option:
                raise Exception(f'[{component}] Malformed mapping: missing "section" in {old_option} replacement')

            # Check if the new option name is present and get the value from the
            # mapping
            if "option" not in new_option:
                raise Exception(f'[{component}] Malformed mapping: missing "option" in {old_option} replacement')

            # Check if the new option dafault value is present and get from the
            # mapping
            if "default" not in new_option:
                raise Exception(f'[{component}] Malformed mapping: missing "default" in {old_option} replacement')

            new_section = new_option["section"]
            new_name = new_option["option"]
            default = new_option["default"]

            # If the option to be replace is not present, do not try to remove
            # and use the default value for the newly added option
            if old_option not in new[component]:
                logger.debug('[%s]: Skipped removing unexisting option "%s"', component, old_option)
                value = default
            else:
                if use_defaults:
                    value = default
                else:
                    # Get the old value to preserve
                    value = new[component].pop(old_option)

            # If the section was not present in old config, add the new
            # section
            if new_section not in new:
                new.add_section(new_section)
                logger.info("Added new section [%s]", new_section)

            # Add the new option
            new[new_section][new_name] = value
            logger.debug('[%s]: Set option "%s" = "%s"', new_section, new_name, value)


def process_update_mapping(
    mapping: Dict[str, Any],
    old_config: RawConfigParser,
    use_defaults: bool,
    target: Optional[Tuple[int, int]] = None,
    logger: Logger = logging.getLogger(__name__),
) -> RawConfigParser:
    """
    Process update mapping
    """
    new_version = str_to_version(mapping["version"])
    if not new_version:
        raise Exception(f"Invalid version number in mapping: {mapping['version']}")

    new = configparser.RawConfigParser()

    for component in old_config:
        # Copy the component from the old config
        new[component] = dict(old_config[component])

        # Only components in the mapping are modified
        if component in mapping["components"]:
            if "subcomponents" in mapping and component in mapping["subcomponents"]:
                # If the component is a subcomponent, use the version from the
                # component
                version_component = mapping["subcomponents"][component]
            else:
                version_component = component

            try:
                found_version = old_config.get(version_component, "version")
                old_version = str_to_version(found_version)

                if not old_version:
                    raise Exception("Invalid version number found in old configuration")

            except (configparser.NoOptionError, configparser.NoSectionError):
                logger.debug("No version found in old configuration for %s, using '1.0'", component)
                old_version = (1, 0)

            # Skip versions lower than the current version
            if old_version >= new_version:
                continue

            # Stop if the version reached the target
            if target:
                if old_version >= target:
                    continue

            # Apply operations for each found option
            update_options(new, mapping["components"], component, use_defaults, logger=logger)

        # Set the resulting version for the component
        new[component]["version"] = mapping["version"]

    # Process sections added via update mapping
    for component in (x for x in mapping["components"] if x not in old_config):
        operations = mapping["components"][component]
        if "add" not in operations:
            logger.warning('Missing "add" operation in new section "[%s]"', component)

        for i in (x for x in operations if x != "add"):
            logger.warning('Bogus "%s" operation in new section "[%s]"', i, component)

        new.add_section(component)
        logger.info('Added new section "[%s]"', component)
        update_options(new, mapping["components"], component, use_defaults, logger=logger)

    return new


def process_mapping(
    components: List[str],
    old_config: RawConfigParser,
    templates: str,
    mapping_file: str,
    use_defaults: bool,
    target: Optional[Tuple[int, int]] = None,
    logger: Logger = logging.getLogger(__name__),
) -> RawConfigParser:
    """
    Apply the transformations from the provided mapping file to the
    configuration dictionary
    """

    with open(mapping_file, "r", encoding="utf-8") as f:
        try:
            mapping = json.loads(f.read())
        except Exception as e:
            raise Exception(f"Could not load mapping file {mapping_file}: {e}") from e

    if not mapping["version"]:
        raise Exception('Malformed mapping: no "version" set')

    if not mapping["components"]:
        raise Exception('Malformed mapping: no "components" set')

    new_version = str_to_version(mapping["version"])
    if not new_version:
        raise Exception(f"Invalid version number in mapping: {mapping['version']}")

    if not any(map(lambda c: needs_update(c, old_config, new_version), components)):
        logger.info("Skipping version %s", mapping["version"])
        # Strip quotes in case the old config was a TOML file
        strip_quotes(old_config)
        return old_config

    # Search for the directory containing the templates for the version set in
    # the mapping
    version_dir = os.path.join(templates, mapping["version"])

    if not os.path.isdir(version_dir):
        raise Exception(
            f"Could not find directory {version_dir} for version " f"{mapping['version']} set in {mapping_file}"
        )

    logger.debug("Applying mapping from file %s version %s ", mapping_file, mapping["version"])

    if "type" in mapping:
        t = mapping["type"]
        if t == "full":
            new = process_full_mapping(mapping, old_config, use_defaults, target, logger=logger)
        elif t == "update":
            new = process_update_mapping(mapping, old_config, use_defaults, target, logger=logger)
        else:
            raise Exception("Invalid mapping type")
    else:
        # When the mapping type is not defined, treat as full mapping to handle
        # older mapping versions
        new = process_full_mapping(mapping, old_config, use_defaults, target, logger)

    # Strip quotes from all options
    strip_quotes(new)

    # If there is an adjust script, load and run it
    adjust_script = os.path.abspath(os.path.join(version_dir, "adjust.py"))
    if os.path.isfile(adjust_script):
        try:
            logger.debug("Applying adjustment from %s", adjust_script)

            # Dynamically load adjust script
            spec = importlib.util.spec_from_file_location("adjust", adjust_script)
            if not spec or not spec.loader:
                raise Exception(f"Could not create spec to load {adjust_script}")

            module = importlib.util.module_from_spec(spec)
            if not module:
                raise Exception(f"Could not load script from {adjust_script}")

            spec.loader.exec_module(module)

            logging.getLogger("adjust").setLevel(logger.getEffectiveLevel())

            # Run adjust function from adjust script
            execute = getattr(module, "adjust")
            execute(new, mapping)
        except Exception as e:
            logger.warning("Failed while running adjustment from %s: %s", adjust_script, e)

    return new


def process_versions(
    components: List[str],
    templates: str,
    old_config: RawConfigParser,
    use_defaults: bool,
    target_version: Optional[str] = None,
    logger: Logger = logging.getLogger(__name__),
) -> RawConfigParser:
    """
    Apply the transformations from the mappings for each version found in the
    templates folder to the configuration.

    If a target version is provided, the process will stop if the target version
    is reached, otherwise all transformations to the latest version are applied
    """

    dirs = os.listdir(templates)

    if not dirs:
        raise Exception(f"No directories found in {templates} for versions")

    # Get a sorted list of the available versions as tuples
    versions = sorted(x for x in set(map(str_to_version, dirs)) if x is not None)

    target = None
    if target_version:
        target = str_to_version(target_version)
        if not target:
            raise Exception(f"Invalid target version number provided: " f"{target_version}")

        if not target in versions:
            raise Exception(f"Directory for target version {target_version} not " f"found in {templates}")

    new = configparser.RawConfigParser()

    for version in versions:
        # Find the mapping file for the version and apply
        p = os.path.join(templates, f"{version[0]}.{version[1]}")
        if os.path.isdir(p):
            m = os.path.join(p, "mapping.json")
            if os.path.isfile(m):
                # Apply transformation for the mapping
                new = process_mapping(components, old_config, templates, m, use_defaults, target=target, logger=logger)
                old_config = new
            else:
                raise Exception(f"Could not find mapping {m}")
        else:
            raise Exception(f"Could not find directory {p}")

        if target:
            if version >= target:
                break

    return new


def main() -> None:
    logging.basicConfig(
        datefmt="%Y-%m-%d %H:%M:%S",
        format="%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )

    logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(description="Split keylime configuration" "file into individual files")

    parser.add_argument(
        "--component",
        help="Select the components for which "
        "configuration files should be generated. If not "
        "provided, generate configuration files for all "
        "components. Can be provided multiple times. "
        "If provided, files will be generated even when up-to-date",
        default=[],
        action="append",
        nargs="+",
    )

    parser.add_argument(
        "--debug",
        help="Raise log level to DEBUG",
        default=False,
        action="store_true",
    )

    parser.add_argument(
        "--input",
        help="Input keylime configuration file to "
        "process. If not provided, it tries to use the "
        "installed Keylime configuration. Can be provided "
        "multiple times",
        default=[],
        action="append",
        nargs="+",
    )

    parser.add_argument(
        "--out",
        help="Output directory where to put the generated files. "
        "If the user is root, the default path is '/etc/keylime', otherwise "
        "the current directory is used. If provided, the files will be "
        "generated even when the configuration is up-to-date. If the output "
        "files exist, backup files are created to preserve the previous "
        "content.",
        default="",
    )

    parser.add_argument(
        "--mapping",
        help="If provided, then only the provided "
        "mapping file will be used. Otherwise, mappings for "
        'each version found in the "templates" directory will '
        "be applied. The file must be a JSON file containing "
        "the mapping for the new configuration options names "
        "to dictionaries containing the section and option "
        "name from the old configuration file, and the default "
        "value to use in case the option is missing in the "
        "input configuration.",
        default=None,
    )

    parser.add_argument(
        "--templates",
        help="Path to the directory containing "
        "the templates for the configuration files. If not "
        'provided "/usr/share/keylime/templates" is used',
        default="/usr/share/keylime/templates",
    )

    parser.add_argument("--version", help="Target version for the output configuration files", default=None)

    parser.add_argument(
        "--defaults",
        help="If provided, the input file and system installed "
        "configuration files will be ignored, and the default "
        "value will be used for all options.",
        default=False,
        action="store_true",
    )

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    if not args.out:
        if os.geteuid() == 0:
            out_dir = "/etc/keylime"
        else:
            out_dir = "."
    else:
        out_dir = args.out

    if not os.path.exists(out_dir):
        raise Exception(f"Output directory {out_dir} does not exist")

    if not os.path.isdir(out_dir):
        raise Exception(f"File {out_dir} is not a directory")

    component_list = [s for ss in args.component for s in ss]

    if not component_list:
        # If no component was provided, use all available
        components = COMPONENTS
    else:
        clean = set(component_list)
        for c in clean:
            if not c in COMPONENTS:
                logger.debug("Unknown component %s, skipping", c)
        components = list(clean.intersection(COMPONENTS))

    if args.version and not str_to_version(args.version):
        raise Exception(f"Invalid version {args.version} specified in --version: " f"Expected 'MAJOR.MINOR' format")

    if not os.path.exists(args.templates):
        raise Exception(f"Templates directory {args.templates} does not exist")

    if not os.path.isdir(args.templates):
        raise Exception(f"File {args.templates} is not a directory")

    logger.debug("Using templates from directory %s", args.templates)

    if args.defaults:
        old_config = configparser.RawConfigParser()
    else:
        # Get old configuration
        old_config = get_config(args.input, logger=logger)

    # Strip quotes in case the old config was a TOML file
    # This is necessary to allow detecting if the processing modified the config
    strip_quotes(old_config)

    if args.mapping:
        if os.path.isfile(args.mapping):
            mapping_file = args.mapping

            # Apply the single mapping provided
            config = process_mapping(components, old_config, args.templates, mapping_file, args.defaults, logger=logger)
        else:
            raise Exception(f"Could not find provided mapping {args.mapping}")
    else:
        # Apply transformations from the templates in the templates directory
        # If a target version is provided, stop when reaching the target
        config = process_versions(
            components, args.templates, old_config, args.defaults, target_version=args.version, logger=logger
        )

    if config != old_config:
        output(components, config, args.templates, out_dir, logger=logger)
    else:
        logger.info("Configuration is up-to-date")
        if args.out or component_list:
            # If the output directory or component list were specified, write the files even when
            # up-to-date
            output(components, config, args.templates, out_dir, logger=logger)


if __name__ == "__main__":
    main()
