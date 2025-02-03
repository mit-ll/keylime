# Checks whether script is being invoked by tox in a virtual environment
def is_tox_env() -> bool:
    # Import 'os' inside function to avoid polluting the namespace of any module which imports 'keylime.models'
    import os  # pylint: disable=import-outside-toplevel

    return bool(os.environ.get("TOX_ENV_NAME"))


# Only perform automatic imports of submodules if tox is not being used to perform static checks. This is necessary as
# models like RegistrarAgent indirectly import package 'gpg' which is not available in a tox environment as it is
# installed via the system package manager
if not is_tox_env():
    from keylime.models.base.da import da_manager
    from keylime.models.base.db import db_manager
    from keylime.models.common import *
    from keylime.models.registrar import *

    __all__ = ["da_manager", "db_manager"]
