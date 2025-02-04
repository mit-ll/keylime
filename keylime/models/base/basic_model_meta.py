from abc import ABCMeta
from types import MappingProxyType
from typing import Any, Callable, Mapping, TypeAlias, Union

from sqlalchemy.types import TypeEngine

from keylime.models.base.associations import (
    EmbeddedInAssociation,
    EmbedsManyAssociation,
    EmbedsOneAssociation,
    ModelAssociation,
)
from keylime.models.base.errors import SchemaInvalid
from keylime.models.base.field import ModelField
from keylime.models.base.type import ModelType


class BasicModelMeta(ABCMeta):
    """BasicModelMeta is used to dynamically build model classes based on schema definitions. All models classes which
    inherit from either ``BasicModel`` or ``PersistableModel`` are themselves instances of BasicModelMeta. The meta
    class contains various methods (many of them private/protected) for transforming models. Instance members of the
    meta class become class members of the model, so any method not marked as a ``@staticmethod`` or ``@classmethod`` is
    accessible directly on the model class.

    Schema Helpers
    --------------

    The ``BasicModelMeta`` class provides helper methods (macros) for declaring a model's schema. These are explained in
    the documentation for ``BasicModel``.

    The Lifecycle of a Model Class
    ------------------------------

    When a new model is created by inheriting from ``BasicModel`` (or subclass), ``BasicModelMeta.__new__(...)``
    executes, creating and initialising a number of class members on the model. At this point, no fields or associations
    have been created.

    To cause the declarations in the model's schema to be interpreted, a call to the ``Model.process_schema()`` method
    provided by ``BasicModelMeta`` is required. This method does not usually need to be invoked manually as it should
    be called whenever the first class or instance property/attribute is accessed. It causes the ``Model._schema``
    method, and thus any schema helpers, to be invoked. The schema helpers create the fields, associations and other
    class members. Afterward, ``Model.process_schema()`` disables the schema helpers so that they cannot be used to
    modify the model after this point.
    """

    # pylint: disable=bad-staticmethod-argument, no-value-for-parameter, using-constant-test

    DeclaredFieldType: TypeAlias = Union[ModelType, TypeEngine, type[ModelType], type[TypeEngine]]

    @classmethod
    def _is_model_class(mcs, cls: type) -> bool:  # type: ignore[reportSelfClassParameterName]
        """Checks whether a given class is a model class, either one of the abstract base classes (e.g., BasicModel
        and its subclasses) or an implementation.
        """
        metaclass = type(cls)
        return issubclass(metaclass, BasicModelMeta)

    @classmethod
    def _get_schema_method(mcs, cls: "BasicModelMeta") -> Callable[[], None]:  # type: ignore[reportSelfClassParameterName]
        if not mcs._is_model_class(cls):
            raise TypeError(f"class '{cls.__name__}' is not a model class")

        schema_method = getattr(cls, "_schema", None)

        if not schema_method:
            raise TypeError(f"no _schema method present in class '{cls.__name__}'")

        if not callable(schema_method):
            raise TypeError(f"member '_schema' of class '{cls.__name__}' not callable")

        return schema_method  # type: ignore[no-any-return]

    @classmethod
    def _is_implementation(mcs, cls: "BasicModelMeta") -> bool:  # type: ignore[reportSelfClassParameterName]
        # BasicModelMeta can be used to create an abstract class (e.g., BasicModel or PersistableModel) or an
        # implementation thereof. An implementation will have a non-abstract _schema method
        is_abstract = getattr(mcs._get_schema_method(cls), "__isabstractmethod__", False)
        return bool(not is_abstract)

    @classmethod
    def _getattr(mcs, cls: "BasicModelMeta", name: str, *args: Any, **kwargs: Any) -> Any:  # type: ignore[reportSelfClassParameterName]
        if not mcs._is_implementation(cls):
            raise TypeError(f"cannot get model attribute '{name}' for abstract class '{cls.__name__}'")

        if name.startswith("__"):
            name = f"_{cls.__name__}{name}"

        return getattr(cls, name, *args, **kwargs)

    @classmethod
    def _setattr(mcs, cls: "BasicModelMeta", name: str, value: Any) -> None:  # type: ignore[reportSelfClassParameterName]
        if not mcs._is_implementation(cls):
            raise TypeError(f"cannot set model attribute '{name}' for abstract class '{cls.__name__}'")

        if name.startswith("__"):
            name = f"_{cls.__name__}{name}"

        setattr(cls, name, value)

    @classmethod
    def _make_field(mcs, cls: "BasicModelMeta", name: str, data_type: DeclaredFieldType, **opts) -> ModelField:  # type: ignore[reportSelfClassParameterName]
        fields = mcs._getattr(cls, "__fields")
        associations = mcs._getattr(cls, "__associations")

        if name in fields:
            raise SchemaInvalid(f"field with name '{name}' already exists in model '{cls.__name__}'")

        if name in associations:
            raise SchemaInvalid(
                f"cannot create field '{name}' for model '{cls.__name__}' as an association with that name already "
                f"exists"
            )

        # Create new model field
        field = ModelField(cls, name, data_type, **opts)
        # Add model field to the model's collection of fields
        fields[name] = field
        # Make model field accessible as a member of the class and, thereby, any objects created therefrom
        mcs._setattr(cls, name, field)

        return field

    @classmethod
    def _add_association(mcs, cls: "BasicModelMeta", association: ModelAssociation) -> None:  # type: ignore[reportSelfClassParameterName]
        if not isinstance(association, ModelAssociation):
            raise TypeError(f"cannot add association of type '{type(association).__name__}' to model '{cls.__name__}'")

        fields = mcs._getattr(cls, "__fields")
        associations = mcs._getattr(cls, "__associations")

        if association.name in associations:
            raise SchemaInvalid(f"association with name '{association.name}' already exists in model '{cls.__name__}'")

        if association.name in fields:
            raise SchemaInvalid(
                f"cannot create association '{association.name}' for model '{cls.__name__}' as a field with that name "
                f"already exists"
            )

        # Add association to the model's collection of associations
        associations[association.name] = association
        # Make the associated model accessible as a member of the class/instance
        mcs._setattr(cls, association.name, association)

    @classmethod
    def _log_schema_helper_use(mcs, cls: "BasicModelMeta", helper_name: str, *args: Any, **kwargs: Any) -> None:  # type: ignore[reportSelfClassParameterName]
        if not mcs._is_implementation(cls):
            raise TypeError(f"abstract class '{cls.__name__}' does not have a schema")

        schema_helpers_used = mcs._getattr(cls, "__schema_helpers_used")
        schema_helpers_used.append((helper_name, args, kwargs))

    def __new__(mcs, new_cls_name: str, bases: tuple[type, ...], attrs: dict[str, Any]) -> "BasicModelMeta":
        cls = super().__new__(mcs, new_cls_name, bases, attrs)

        if mcs._is_implementation(cls):
            # Create private class attributes to hold collections of fields and associations (it is not possible to
            # populate these collections until after all model classes are instantiated because associations include
            # cross-model references)
            mcs._setattr(cls, "__fields", {})
            mcs._setattr(cls, "__associations", {})
            # Create attribute to manage model lifecycle
            mcs._setattr(cls, "__schema_status", "pending")
            # Create attribute to keep a record of all schema helpers invoked
            mcs._setattr(cls, "__schema_helpers_used", [])

        return cls

    def _field(cls, name: str, data_type: DeclaredFieldType, nullable: bool = False) -> None:
        if cls.schema_helpers_enabled:
            type(cls)._make_field(cls, name, data_type, nullable=nullable)
            type(cls)._log_schema_helper_use(cls, "_field", name, data_type, nullable)

    def _virtual(cls, name: str, data_type: DeclaredFieldType, nullable: bool = False, render: bool = False) -> None:
        if cls.schema_helpers_enabled:
            type(cls)._make_field(cls, name, data_type, nullable=nullable, persist=False, render=render)
            type(cls)._log_schema_helper_use(cls, "_virtual", name, data_type, nullable, render=render)

    def _embeds_one(cls, name: str, *args: Any, **kwargs: Any) -> None:
        if not cls.schema_helpers_enabled:
            return

        args = (name, *args)
        association = EmbedsOneAssociation(*args, **kwargs)

        type(cls)._add_association(cls, association)
        type(cls)._log_schema_helper_use(cls, "_embeds_one", name, *args, **kwargs)

    def _embeds_many(cls, name: str, *args: Any, **kwargs: Any) -> None:
        if not cls.schema_helpers_enabled:
            return

        args = (name, *args)
        association = EmbedsManyAssociation(*args, **kwargs)

        type(cls)._add_association(cls, association)
        type(cls)._log_schema_helper_use(cls, "_embeds_many", name, *args, **kwargs)

    def _embedded_in(cls, name: str, *args: Any, **kwargs: Any) -> None:
        if not cls.schema_helpers_enabled:
            return

        args = (name, *args)
        association = EmbeddedInAssociation(*args, **kwargs)

        type(cls)._add_association(cls, association)
        type(cls)._log_schema_helper_use(cls, "_embedded_in", name, *args, **kwargs)

    def process_schema(cls) -> None:  # type: ignore[reportSelfClassParameterName]
        if cls.schema_awaiting_processing:
            # Mark schema as being processed to allow schema helpers to mutate the model
            type(cls)._setattr(cls, "__schema_status", "processing")
            # Process schema declarations by retrieving and invoking the _schema method defined by cls
            type(cls)._get_schema_method(cls)()
            # Mark schema processing as complete to prevent further invocations of process_schema
            type(cls)._setattr(cls, "__schema_status", "done")

    @property
    def schema_status(cls) -> bool:
        if not type(cls)._is_implementation(cls):
            raise TypeError(f"abstract class '{cls.__name__}' does not have a schema")

        return bool(type(cls)._getattr(cls, "__schema_status"))

    @property
    def schema_awaiting_processing(cls) -> bool:
        if not type(cls)._is_implementation(cls):
            raise TypeError(f"abstract class '{cls.__name__}' does not have a schema")

        return bool(type(cls)._getattr(cls, "__schema_status") == "pending")

    @property
    def schema_helpers_enabled(cls) -> bool:
        if not type(cls)._is_implementation(cls):
            raise TypeError(f"abstract class '{cls.__name__}' does not have a schema")

        return bool(type(cls)._getattr(cls, "__schema_status") == "processing")

    @property
    def schema_processed(cls) -> bool:
        if not type(cls)._is_implementation(cls):
            raise TypeError(f"abstract class '{cls.__name__}' does not have a schema to process")

        return bool(type(cls)._getattr(cls, "__schema_status") == "done")

    @property
    def fields(cls) -> Mapping[str, ModelField]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        fields = type(cls)._getattr(cls, "__fields")
        return MappingProxyType(fields)

    @property
    def associations(cls) -> Mapping[str, ModelAssociation]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        associations = type(cls)._getattr(cls, "__associations")
        return MappingProxyType(associations)

    @property
    def embeds_one_associations(cls) -> dict[str, EmbedsOneAssociation]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        return {
            name: association
            for name, association in cls.associations.items()
            if isinstance(association, EmbedsOneAssociation)
        }

    @property
    def embeds_many_associations(cls) -> dict[str, EmbedsManyAssociation]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        return {
            name: association
            for name, association in cls.associations.items()
            if isinstance(association, EmbedsManyAssociation)
        }

    @property
    def embedded_in_associations(cls) -> dict[str, EmbeddedInAssociation]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        return {
            name: association
            for name, association in cls.associations.items()
            if isinstance(association, EmbeddedInAssociation)
        }

    @property
    def persistable(cls) -> bool:
        return False

    @property
    def schema_helpers_used(cls) -> list[tuple[str, tuple, dict]]:
        return list(type(cls)._getattr(cls, "__schema_helpers_used")).copy()

    @property
    def _repr_fields(cls) -> list[str]:
        field_names = []
        count = 0

        for name in cls.fields.keys():
            if count >= 5:
                break

            field_names.append(name)
            count += 1

        return field_names
