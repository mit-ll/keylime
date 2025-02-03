import base64
import binascii
from inspect import isclass
from typing import Any, Optional, TypeAlias, Union

from sqlalchemy.types import LargeBinary, String

from keylime.models.base.type import ModelType


# TODO: Add documentation
class Binary(ModelType):
    IncomingValue: TypeAlias = Union[bytes, str, None]

    def __init__(self, persist_as=LargeBinary) -> None:
        if not isinstance(persist_as, (LargeBinary, String)) and not issubclass(persist_as, (LargeBinary, String)):
            raise TypeError("field of type 'Binary' must have a persist_as value of type 'LargeBinary' or 'String'")
        if isclass(persist_as):
            persist_as = persist_as()

        super().__init__(persist_as)

    def cast(self, value: IncomingValue) -> Optional[bytes]:
        # Resolving the below pylint warning would negatively impact the readability of this method definition
        # pylint: disable=no-else-return

        if not value:
            return None

        elif isinstance(value, bytes):
            return value

        elif isinstance(value, str):
            try:
                return base64.b64decode(value, validate=True)
            except binascii.Error:
                pass

            try:
                return bytes.fromhex(value)
            except ValueError:
                raise ValueError(
                    f"string value cast to binary is not valid base64 or hex: '{value}'"
                )  # pylint: disable=raise-missing-from

        else:
            raise TypeError(
                f"value cast to binary is of type '{value.__class__.__name__}' but should be either 'bytes' or "
                f"'str': '{value}'"
            )

    def generate_error_msg(self, _value: IncomingValue) -> str:
        return "must be valid binary"

    def _dump(self, value: IncomingValue) -> Optional[str | bytes]:
        # Resolving the below pylint warning would negatively impact the readability of this method definition
        # pylint: disable=no-else-return

        value = self.cast(value)

        if not value:
            return None

        # If the backing database type is a string, encode as base64, otherwise return the raw binary
        if isinstance(self._type_engine, String):
            return base64.b64encode(value).decode("utf-8")
        else:
            return value

    def render(self, value: Any) -> Any:
        value = self.cast(value)
        return base64.b64encode(value).decode("utf-8")

    @property
    def native_type(self) -> type:
        return bytes
