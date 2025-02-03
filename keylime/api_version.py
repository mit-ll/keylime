import re
from logging import Logger
from typing import Dict, List, Union

from packaging import version

VersionType = Union[int, float, str]

CURRENT_VERSION: str = "2.3"
VERSIONS: List[str] = ["1.0", "2.0", "2.1", "2.2", "2.3", "3.0"]
LATEST_VERSIONS: Dict[str, str] = {"1": "1.0", "2": "2.3", "3": "3.0"}
DEPRECATED_VERSIONS: List[str] = ["1.0"]


def current_version() -> str:
    return CURRENT_VERSION


def latest_minor_version(version_type: VersionType) -> str:
    try:
        v_obj = version.parse(str(version_type))
    except version.InvalidVersion:
        return "0"
    if not isinstance(v_obj, version.Version):
        return "0"
    major_v = str(v_obj.major)
    if major_v in LATEST_VERSIONS:
        return LATEST_VERSIONS[major_v]

    return "0"


def all_versions() -> List[str]:
    return VERSIONS.copy()


def is_supported_version(version_type: VersionType) -> bool:
    try:
        v_obj = version.parse(str(version_type))
    except version.InvalidVersion:
        return False
    return v_obj.base_version in VERSIONS


def is_deprecated_version(version_type: VersionType) -> bool:
    try:
        v_obj = version.parse(str(version_type))
    except version.InvalidVersion:
        return False
    return is_supported_version(version_type) and v_obj.base_version in DEPRECATED_VERSIONS


def normalize_version(version_type: VersionType) -> str:
    version_type = str(version_type)
    version_type = version_type.strip("/")
    try:
        base_version = version.parse(version_type).base_version
    except version.InvalidVersion:
        return version_type
    # if the base version is a single number, get the latest minor version
    if "." not in base_version:
        latest_minor = latest_minor_version(base_version)
        if latest_minor != "0":
            return latest_minor
    return base_version


def major(version_type: VersionType) -> int:
    try:
        v_obj = version.parse(str(version_type))
    except version.InvalidVersion:
        return 0
    assert isinstance(v_obj, version.Version)
    return v_obj.major


def minor(version_type: VersionType) -> int:
    try:
        v_obj = version.parse(str(version_type))
    except version.InvalidVersion:
        return 0
    assert isinstance(v_obj, version.Version)
    return v_obj.minor


def log_api_versions(logger: Logger) -> None:
    logger.info("Current API version %s", CURRENT_VERSION)
    versions = all_versions()
    versions.remove(CURRENT_VERSION)
    if versions:
        logger.info("Supported older API versions: " + ", ".join(versions))
    if DEPRECATED_VERSIONS:
        logger.info("Deprecated API versions (soon to be removed): " + ", ".join(DEPRECATED_VERSIONS))


def validate_version(version_type: str) -> bool:
    pattern = re.compile(r"\d.\d")
    return re.fullmatch(pattern, version_type) is not None
