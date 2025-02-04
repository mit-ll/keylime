import re
from inspect import isclass
from typing import TYPE_CHECKING, Any, Optional, TypeAlias, Union

from sqlalchemy.types import TypeEngine

from keylime.models.base.errors import FieldDefinitionInvalid
from keylime.models.base.type import ModelType

if TYPE_CHECKING:
    from keylime.models.base.basic_model import BasicModel
    from keylime.models.base.basic_model_meta import BasicModelMeta


class ModelField:
    """ModelField is used to represent fields in a model. As a Python descriptor [1], when instantiated and assigned to
    a class member, it can be accessed from instances of that class as if it were a property [2] of the instance. This
    makes it possible for a model field to be accessed using dot notation (e.g., ``record.field = 123``) even though its
    data is stored within a private instance variable.

    Typically ModelField is not instantiated outside the ``keylime.models.base`` package.

    [1] https://docs.python.org/3/howto/descriptor.html
    [2] https://docs.python.org/3/library/functions.html#property
    """

    DeclaredFieldType: TypeAlias = Union[ModelType, TypeEngine, type[ModelType], type[TypeEngine]]

    FIELD_NAME_REGEX = re.compile(r"^[A-Za-z_]+[A-Za-z0-9_]*$")

    _name: str
    _data_type: ModelType
    _nullable: bool

    def __init__(self, parent: "BasicModelMeta", name: str, data_type: DeclaredFieldType, **opts) -> None:
        # pylint: disable=redefined-builtin

        if not re.match(ModelField.FIELD_NAME_REGEX, name):
            raise FieldDefinitionInvalid(f"'{name}' is an invalid name for a field")

        self._parent = parent
        self._name = name
        self._nullable = opts.get("nullable", False)
        self._persist = opts.get("persist", True)
        self._render = opts.get("render", True)

        if isinstance(data_type, ModelType):
            self._data_type = data_type
        elif isclass(data_type) and issubclass(data_type, ModelType):
            self._data_type = data_type()  # type: ignore
        elif isinstance(data_type, TypeEngine) or (isclass(data_type) and issubclass(data_type, TypeEngine)):
            self._data_type = ModelType(data_type)
        else:
            raise FieldDefinitionInvalid(
                f"field '{name}' cannot be defined with type '{data_type}' as this is neither a ModelType "
                f"subclass/instance nor a SQLAlchemy data type inheriting from 'sqlalchemy.types.TypeEngine'"
            )

    def __get__(self, obj: Optional["BasicModel"], _objtype: Optional[type["BasicModel"]] = None) -> Any:
        # When the field is accessed from the model class that contains it instead of from an instance of the class,
        # return the field object itself
        if obj is None:
            return self

        # When the field is accessed from a model instance, return the value of the field
        return obj.values.get(self._name)

    def __set__(self, obj: Optional["BasicModel"], value: Any) -> None:
        # Setting the field on the model class is not a valid operation
        if obj is None:
            raise AttributeError(f"field '{self.name}' cannot be set from the model class")

        # When the field is set on a model instance, add the incoming value to changes
        obj.change(self._name, value)

    def __delete__(self, obj: Optional["BasicModel"]) -> None:
        self.__set__(obj, None)

    def __eq__(self, other):
        sa_field = getattr(self.parent.db_mapping, self.name)
        return sa_field.__eq__(other)

    def __ne__(self, other):
        sa_field = getattr(self.parent.db_mapping, self.name)
        return sa_field.__ne__(other)

    def __lt__(self, other):
        sa_field = getattr(self.parent.db_mapping, self.name)
        return sa_field.__lt__(other)

    def __le__(self, other):
        sa_field = getattr(self.parent.db_mapping, self.name)
        return sa_field.__le__(other)

    def __gt__(self, other):
        sa_field = getattr(self.parent.db_mapping, self.name)
        return sa_field.__gt__(other)

    def __ge__(self, other):
        sa_field = getattr(self.parent.db_mapping, self.name)
        return sa_field.__ge__(other)

    @property
    def parent(self) -> "BasicModelMeta":
        return self._parent

    @property
    def name(self) -> str:
        return self._name

    @property
    def data_type(self) -> ModelType:
        return self._data_type

    @property
    def nullable(self) -> bool:
        return self._nullable

    @property
    def persist(self) -> bool:
        return self._persist

    @property
    def render(self) -> bool:
        return self._render
