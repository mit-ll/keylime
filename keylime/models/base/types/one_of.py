from collections import Counter
from inspect import isclass
from typing import Any, Optional, TypeAlias, Union

from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.types import Float, Integer, String, TypeEngine

from keylime.models.base.errors import FieldDefinitionInvalid
from keylime.models.base.type import ModelType


class OneOf(ModelType):
    """The OneOf class implements the model type API (by inheriting from ``ModelType``) to create a special hybrid
    data type consisting of the union of zero or more other model types and zero or more literal values. All
    ``ModelType`` instances in the union are expected to have a common ancestor type to which any literals in the union
    are convertible.

    The schema of the backing database table is assumed to declare the corresponding column as being of a database type
    equivalent to the common ancestor type.

    Example 1
    ---------

    You may use the OneOf construct to declare a field that may contain only specific pre-defined values::

        class SomeModel(PersistableModel):
            def _schema(self):
                cls._field("status", OneOf("pending", "successful", "failed"), nullable=True)
                # (Any additional schema declarations...)

    The above declaration creates a status field that must be set to one of ``None``, ``"pending"``, ``"successful"``,
    or ``"failed"``.

    Example 2
    ---------

    Another use is to declare a field which accepts any arbitrary value of a specific type, but also has a set of
    specific values with special meanings::

        class SomeModel(PersistableModel):
            def _schema(self):
                cls._field("cert", OneOf(Certificate, "disabled"))
                # (Any additional schema declarations...)

    The above declaration creates a cert field which contains a certificate but may also be set to the string
    ``"disabled"``. If this field were to be declared simply as being of type ``Certificate`` (without using the OneOf
    construct), setting it to ``"disabled"`` would cause an error as this value is not interpretable as a certificate.

    Example 3
    ---------

    An advanced usage is to declare a field which can contain values of different types::

        class SomeModel(PersistableModel):
            def _schema(self):
                cls._field("authenticator", OneOf(Certificate, Dictionary, String))
                # (Any additional schema declarations...)

    In the above example, we have created a field to contain a certificate, a JSON-convertible dictionary with a public
    key and its algorithm, or a JSON web token (as a string). This is possible as all three types cause data to be
    stored in the database as text.

    It is important that the ``String`` type is listed last as OneOf will attempt to convert incoming values to each
    type in sequence, moving onto the next if conversion fails. If ``String`` were given before ``Certificate``, an
    incoming PEM value would not be cast to a certificate object and remain a string.
    """

    Declaration: TypeAlias = Union[str, int, float, ModelType, TypeEngine, type[ModelType], type[TypeEngine]]
    PermittedList: TypeAlias = list[Union[str, int, float, ModelType]]

    def __init__(self, *args: Declaration) -> None:
        # pylint: disable=super-init-not-called

        self._permitted: OneOf.PermittedList = []

        for item in args:
            if isinstance(item, (str, int, float)):
                self._permitted.append(item)
            elif isinstance(item, ModelType):
                self._permitted.append(item)
            elif isclass(item) and issubclass(item, ModelType):
                self._permitted.append(item())  # type: ignore
            elif isinstance(item, TypeEngine) or (isclass(item) and issubclass(item, TypeEngine)):
                self._permitted.append(ModelType(item))
            else:
                raise FieldDefinitionInvalid("field defined with invalid 'OneOf' construct")

    def cast(self, value: Any) -> Any:
        if value is None or value == "":
            return None

        for item in self._permitted:
            if isinstance(item, ModelType):
                try:
                    return item.cast(value)
                except Exception:
                    continue
            elif isinstance(value, str) and isinstance(item, str) and value.casefold() == item.casefold():
                return item
            elif value == item:
                return value
            else:
                continue

        raise TypeError("value is not allowable by 'OneOf' definition")

    def generate_error_msg(self, _value: Any) -> str:
        return "is not a permitted value"

    def render(self, value: Any) -> Any:
        if value is None or value == "":
            return None

        for item in self._permitted:
            if isinstance(item, ModelType):
                try:
                    return item.render(value)
                except Exception:
                    continue
            elif value == item:
                return value

        raise ValueError("'OneOf' value cannot be rendered by any available renderer")

    def db_dump(self, value: Any, dialect: Dialect) -> Any:
        if value is None or value == "":
            return None

        for item in self._permitted:
            if isinstance(item, ModelType):
                try:
                    return item.db_dump(value, dialect)
                except Exception:
                    continue
            elif value == item:
                return value
            else:
                continue

        raise TypeError("value is not allowable by 'OneOf' definition")

    def db_load(self, value: Any, dialect: Dialect) -> Any:
        if value is None or value == "":
            return None

        for item in self._permitted:
            if isinstance(item, ModelType):
                try:
                    return item.db_load(value, dialect)
                except Exception:
                    continue
            elif isinstance(value, str) and isinstance(item, str) and value.casefold() == item.casefold():
                return item
            elif value == item:
                return value
            else:
                continue

        raise TypeError("value is not allowable by 'OneOf' definition")

    def _lowest_common_ancestor(self, list: list[Any]) -> Optional[type]:
        # pylint: disable=redefined-builtin

        counter: Counter = Counter()

        for item in list:
            if not isclass(item):
                item = item.__class__

            mro = item.mro()

            for cls in reversed(mro):
                counter[cls] += 1

        lca = None

        if len(counter) > 0:
            highest_count = next(iter(counter.values()))

            for cls, count in counter.items():
                if count == highest_count:
                    lca = cls

        return lca

    def get_db_type(self, dialect: Dialect) -> TypeEngine:
        # pylint: disable=no-else-return

        db_types = [item.get_db_type(dialect) for item in self._permitted if isinstance(item, ModelType)]
        lc_db_type = self._lowest_common_ancestor(db_types)

        if lc_db_type not in (None, TypeEngine, object):
            return lc_db_type()  # type: ignore[no-any-return, misc]

        literals = [item for item in self._permitted if not isinstance(item, ModelType)]
        lc_lit_type = self._lowest_common_ancestor(literals)

        if isclass(lc_lit_type):
            if issubclass(lc_lit_type, str):
                return String()
            elif issubclass(lc_lit_type, int):
                return Integer()
            elif issubclass(lc_lit_type, float):
                return Float()

        raise FieldDefinitionInvalid("field defined with invalid 'OneOf' construct")

    def da_dump(self, value: Any) -> Any:
        if value is None or value == "":
            return None

        for item in self._permitted:
            if isinstance(item, ModelType):
                try:
                    return item.da_dump(value)
                except Exception:
                    continue
            elif value == item:
                return value
            else:
                continue

        raise TypeError("value is not allowable by 'OneOf' definition")

    def da_load(self, value: Any) -> Any:
        if value is None or value == "":
            return None

        for item in self._permitted:
            if isinstance(item, ModelType):
                try:
                    return item.da_load(value)
                except Exception:
                    continue
            elif isinstance(value, str) and isinstance(item, str) and value.casefold() == item.casefold():
                return item
            elif value == item:
                return value
            else:
                continue

        raise TypeError("value is not allowable by 'OneOf' definition")

    @property
    def permitted(self) -> PermittedList:
        return self._permitted.copy()

    @property
    def native_type(self) -> type:
        raise NotImplementedError
