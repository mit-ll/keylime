import json
from typing import Optional, TypeAlias, Union

from sqlalchemy.types import Text

from keylime.models.base.type import ModelType


class List(ModelType):
    """The List class implements the model type API (by inheriting from ``ModelType``) to allow model fields to be
    declared as containing objects of type ``list``. Such a field may be set to either (1) a string containing a JSON
    array or (2) a ``list`` object which is representable as a JSON array. The incoming value is always cast to and
    kept in memory as a ``list``. If saved to a database, the ``list`` is converted to its JSON representation.

    The schema of the backing database table is assumed to declare the list-containing column as type ``"Text"``
    or comparable, in line with established Keylime convention. This is somewhat inefficient for database engines which
    have a native JSON database (like PostgreSQL), so we may wish to revisit this choice at a later date.

    Example 1
    ---------

    To use the List type, declare a model field as in the following example::

        class SomeModel(PersistableModel):
            def _schema(self):
                cls._field("names", List, nullable=True)
                # (Any additional schema declarations...)

    Then, you can set the field by providing either a ``list`` or a ``str``, as shown below::

        record = SomeModel.empty()

        # Set names field using ``list``:
        record.names = ["Jane", "John"]

        # Set names field using a ``str`` containing a JSON array:
        record.names = '["Jane", "John"]'

    On performing ``record.commit_changes()``, the list will be saved to the database in its JSON representation.

    Example 2
    ---------

    You may also use the List type's casting functionality outside a model by using the ``cast`` method directly::

        # Casting a ``list`` which is representable as JSON returns it unchanged:
        names = Dictionary().cast(["Jane", "John"])

        # Casting a ``str`` containing a JSON array returns a ``list``:
        names = Dictionary().cast('["Jane", "John"]')
    """

    IncomingValue: TypeAlias = Union[list, str, None]

    def __init__(self) -> None:
        super().__init__(Text)

    def cast(self, value: IncomingValue) -> Optional[list]:
        """Tries to convert the given value to a ``list`` which is representable as a JSON array. Values which do not
        require conversion are returned unchanged.

        :param value: The value to convert (may be a ``str`` containing a JSON array or a ``list``)

        :raises: :class:`TypeError`: ``value`` is of an unexpected data type
        :raises: :class:`ValueError`: ``value`` is of the correct type but cannot be represented as a JSON array

        :returns: A ``list`` object which is JSON representable or None if an empty value is given
        """
        # pylint: disable=no-else-return

        if not value:
            return None

        elif isinstance(value, list):
            try:
                json.dumps(value)
            except TypeError as err:
                raise TypeError(
                    "'list' object cast to list contains values which aren't representable as JSON"
                ) from err

            return value

        elif isinstance(value, str):
            try:
                parsed_list = json.loads(value)
            except json.JSONDecodeError as err:
                raise ValueError(f"string value cast to list is not valid JSON: '{value}'") from err

            if not isinstance(parsed_list, list):
                raise ValueError(f"string value cast to list is not a valid JSON array: '{value}'")

            return parsed_list

        else:
            raise TypeError(
                f"value cast to list is of type '{value.__class__.__name__}' but should be either 'str' or "
                f"'list': '{value}'"
            )

    def generate_error_msg(self, _value: IncomingValue) -> str:
        return "must be a valid JSON array"

    def _dump(self, value: IncomingValue) -> Optional[str]:
        # Cast incoming value to list object
        cast_list = self.cast(value)

        if not cast_list:
            return None

        # Save in DB as JSON
        return json.dumps(cast_list)

    @property
    def native_type(self) -> type:
        return list
