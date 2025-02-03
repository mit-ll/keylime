from datetime import datetime, timezone
from typing import Optional, TypeAlias, Union

from sqlalchemy.types import String

from keylime.models.base.type import ModelType


class Timestamp(ModelType):
    IncomingValue: TypeAlias = Union[datetime, str, int, float, None]

    @staticmethod
    def now():
        return datetime.now(tz=timezone.utc)

    def __init__(self) -> None:
        super().__init__(String)

    def _load_datetime(self, value: datetime) -> datetime:
        if value.tzinfo == timezone.utc:
            return value
        elif value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        else:
            return value.astimezone(tz=timezone.utc)

    def _load_str(self, value: str) -> datetime:
        ts: Optional[datetime] = None

        try:
            ts = datetime.fromisoformat(value)
        except ValueError:
            pass

        if not ts:
            try:
                ts = datetime.fromtimestamp(float(value))
            except ValueError:
                pass

        if not ts:
            raise ValueError(
                f"value cast to timestamp is of type 'str' but does not appear to be a valid ISO8601 datetime or "
                f"Unix timestamp: {value!r}"
            )

        return self._load_datetime(ts)

    def _load_float(self, value: float) -> datetime:
        ts = datetime.fromtimestamp(value)
        return self._load_datetime(ts)

    def _load_int(self, value: int) -> datetime:
        return self._load_float(float(value))

    def cast(self, value: IncomingValue) -> Optional[datetime]:
        if not value:
            return None

        if isinstance(value, datetime):
            return self._load_datetime(value)
        elif isinstance(value, str):
            try:
                return self._load_str(value)
            except ValueError as err:
                raise err
        elif isinstance(value, int):
            return self._load_int(value)
        elif isinstance(value, float):
            return self._load_float(value)
        else:
            raise TypeError(
                f"value cast to timestamp is of type '{value.__class__.__name__}' but should be one of 'str', 'int', "
                f"'float', or 'datetime': '{str(value)}'"
            )

    def generate_error_msg(self, _value: IncomingValue) -> str:
        return "must be a valid ISO8601 datetime or Unix timestamp"

    def _dump(self, value: IncomingValue) -> Optional[str]:
        ts = self.cast(value)

        if not ts:
            return None

        return ts.isoformat(timespec="microseconds")

    def render(self, value: IncomingValue) -> Optional[str]:
        ts = self.cast(value)

        if not ts:
            return None

        return ts.isoformat(timespec="microseconds")

    @property
    def native_type(self) -> type:
        return datetime
