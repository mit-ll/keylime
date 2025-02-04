import re
from typing import Any, Optional, Pattern, TypeAlias

from sqlalchemy import Column, ForeignKey, Integer, Table, Text
from sqlalchemy.dialects.mysql import LONGTEXT
from sqlalchemy.orm import RelationshipProperty, relationship

from keylime.models.base.associations import (
    BelongsToAssociation,
    EntityAssociation,
    HasManyAssociation,
    HasOneAssociation,
)
from keylime.models.base.basic_model_meta import BasicModelMeta
from keylime.models.base.db import db_manager
from keylime.models.base.errors import SchemaInvalid
from keylime.models.base.field import ModelField


class PersistableModelMeta(BasicModelMeta):
    """PersistableModelMeta extends BasicModelMeta to additionally create those class members which are needed to map a
    model to an entity in a database. Refer to the documentation for BasicModel for an overview of the function of both
    these meta classes.

    Schema Helpers
    --------------

    The ``PersistableModelMeta`` class provides helper methods (macros) for declaring a model's schema, in addition to
    those provided by ``BasicModelMeta``. The helper methods specific to database-backed models are explained in the
    documentation for ``PersistableModel``.

    Changes to the Model Class Lifecycle
    ------------------------------------

    This section assumes familiarity with the lifecycle of a basic model (see ```BasicModelMeta``).

    When a new class is created which inherits from ``PersistableModel``, in addition to those class members which are
    created by ``BasicModelMeta``, a number of database-related class members are created and initialised. Most notably,
    an empty mapping class is created and stored as a member within the model class. This empty class will later be
    processed by the SQLAlchemy ORM and used to perform database queries.

    On calling ``Model.process_schema()``, a number of events take place in sequence. Schema helpers for declaring
    fields and associations create SQLAlchemy ``Column`` objects which are collected in the model class. Then, these are
    used to instantiate a new SQLAlchemy ``Table``, and a SQLAlchemy ``relationship`` is built for each association. The
    columns and relationships are given to SQLAlchemy to transform the empty mapping class into a class which resembles
    the database table with its various entity attributes, constraints, etc.

    The mapping class is used with the SQLAlchemy query API to save and retrieve records which creates an instance of
    the mapping class. Values are transparently copied into and out of this mapping class instance by
    ``PersistableModel`` at the appropriate times.
    """

    # pylint: disable=using-constant-test, no-value-for-parameter, unused-private-member, unsupported-membership-test, no-else-return

    DeclaredFieldType: TypeAlias = BasicModelMeta.DeclaredFieldType

    TABLE_NAME_REGEX: Pattern = re.compile(r"^[A-Za-z_]+[A-Za-z0-9_]*$")

    @staticmethod
    def __new_db_mapping(class_name: str) -> type:
        # Create empty Python class which will later be mapped to a database table
        db_mapping = type(class_name, (object,), {})

        # Because the dynamically-defined mapping class does not belong to a Python module in the usual sense, set
        # the module name to point to this method (where the definition of the mapping class occurs)
        setattr(db_mapping, "__module__", "PersistableModel.__new_db_mapping.<locals>")

        return db_mapping

    @staticmethod
    def __make_db_table(table_name: str, columns: list[Column]) -> Table:
        # Create empty SQLAlchemy Table which will used to map a class to the database
        db_table = Table(table_name, db_manager.registry.metadata)

        # Add the given columns to the table
        for column in columns:
            db_table.append_column(column)  # type: ignore

        return db_table

    @staticmethod
    def __assoc_to_rship(association: "EntityAssociation") -> RelationshipProperty:
        lazy = "joined" if association.preload else "select"
        return relationship(association.other_model.db_mapping, back_populates=association.inverse_of, lazy=lazy)

    @classmethod
    def _make_field(mcs, cls: "BasicModelMeta", name: str, data_type: DeclaredFieldType, **opts) -> ModelField:  # type: ignore[reportSelfClassParameterName]
        if not mcs._is_implementation(cls):
            raise TypeError(f"cannot create model field '{name}' on abstract class '{cls.__name__}'")

        nullable = opts.get("nullable", False)
        primary_key = opts.get("primary_key", False)
        column_args = opts.get("column_args", ())

        if not isinstance(column_args, tuple):
            column_args = (column_args,)

        if primary_key and "_id" in [name for (name, _, _) in cls.schema_helpers_used]:
            raise SchemaInvalid(
                f"cannot create primary key using field '{name}' for model '{cls.__name__}' which already has a "
                f"single-field primary key defined using the 'cls._id(...)' schema helper"
            )

        if primary_key:
            mcs._getattr(cls, "__primary_key").append(name)

        field = super()._make_field(cls, name, data_type, **opts)

        if field.persist:
            db_type = field.data_type.get_db_type(db_manager.engine.dialect)
            db_columns = mcs._getattr(cls, "__db_columns")
            db_columns.append(Column(name, db_type, *column_args, nullable=nullable, primary_key=primary_key))

        return field

    def __new__(mcs, new_cls_name: str, bases: tuple[type, ...], attrs: dict[str, Any]) -> "PersistableModelMeta":
        cls = super().__new__(mcs, new_cls_name, bases, attrs)

        if mcs._is_implementation(cls):
            # Create new empty class to map to database once the schema is processed
            mapping_class = mcs.__new_db_mapping(f"{cls.__name__}Mapping")
            mcs._setattr(cls, "__db_mapping", mapping_class)
            mcs._setattr(cls, "__db_mapping_complete", False)
            # Initialise other attributes which can only be determined upon schema processing
            mcs._setattr(cls, "__table_name", None)
            mcs._setattr(cls, "__db_table", None)
            mcs._setattr(cls, "__db_columns", [])
            mcs._setattr(cls, "__primary_key", [])

        return cls  # type: ignore[reportReturnType, return-value]

    def _persist_as(cls, table_name: str) -> None:
        if not cls.schema_helpers_enabled:
            return

        if not re.match(ModelField.FIELD_NAME_REGEX, table_name):
            raise SchemaInvalid(f"'{table_name}' is an invalid name for a table")

        type(cls)._setattr(cls, "__table_name", table_name)
        type(cls)._log_schema_helper_use(cls, "_persist_as", table_name)

    def _id(cls, name: str, data_type: DeclaredFieldType = Integer) -> None:
        if not cls.schema_helpers_enabled:
            return

        if type(cls)._getattr(cls, "__primary_key"):
            raise SchemaInvalid(
                f"the cls._id({name}, {data_type}) helper cannot be used to create a primary key for model "
                f"'{cls.__name__}' which already has a primary key defined"
            )

        type(cls)._make_field(cls, name, data_type, primary_key=True)
        type(cls)._log_schema_helper_use(cls, "_id", name, data_type)

    def _field(cls, name: str, data_type: DeclaredFieldType, nullable: bool = False, primary_key: bool = False) -> None:
        if not cls.schema_helpers_enabled:
            return

        if isinstance(data_type, Text):
            data_type = data_type.with_variant(LONGTEXT, "mysql")  # type: ignore[arg-type]
            data_type = data_type.with_variant(LONGTEXT, "mariadb")  # type: ignore[arg-type]

        type(cls)._make_field(cls, name, data_type, nullable=nullable, primary_key=primary_key)
        type(cls)._log_schema_helper_use(cls, "_field", name, data_type, nullable=nullable, primary_key=primary_key)

    def _has_one(cls, name: str, *args: Any, **kwargs: Any) -> None:
        if not cls.schema_helpers_enabled:
            return

        args = (name, *args)
        association = HasOneAssociation(*args, **kwargs)

        type(cls)._add_association(cls, association)
        type(cls)._log_schema_helper_use(cls, "_has_one", name, *args, **kwargs)

    def _has_many(cls, name: str, *args: Any, **kwargs: Any) -> None:
        if not cls.schema_helpers_enabled:
            return

        args = (name, *args)
        association = HasManyAssociation(*args, **kwargs)

        type(cls)._add_association(cls, association)
        type(cls)._log_schema_helper_use(cls, "_has_many", name, *args, **kwargs)

    def _belongs_to(cls, name: str, *args: Any, primary_key: bool = False, **kwargs: Any) -> None:
        if not cls.schema_helpers_enabled:
            return

        args = (name, *args)
        association = BelongsToAssociation(*args, **kwargs)

        # Get the associated model
        other_model = association.other_model
        # Get the name of the field to be used as the foreign key (usually "{association name}_id")
        foreign_key = association.foreign_key

        if primary_key and "_id" in [name for (name, _, _) in cls.schema_helpers_used]:
            raise SchemaInvalid(
                f"cannot create primary key using field '{foreign_key}' for model '{cls.__name__}' which already has a "
                f"single-field primary key defined using the 'cls._id(...)' schema helper"
            )

        if len(other_model.primary_key) != 1:
            raise SchemaInvalid(
                f"model '{cls.__name__}' has a belongs_to association with model '{other_model.__name__}' which has a "
                f"composite primary key (the associated model must have a primary key consisting of a single field)"
            )

        # Get the name of the field which serves as the ID (primary key) of the associated model
        (other_model_id,) = other_model.primary_key
        # The data type of the foreign key in this model should match the data type of the associated model's ID field
        foreign_key_type = cls._getattr(other_model, "_fields")[other_model_id].data_type

        # Create the field for the foreign key
        type(cls)._make_field(
            cls,
            name=foreign_key,
            data_type=foreign_key_type,
            nullable=True,
            primary_key=primary_key,
            column_args=(ForeignKey(f"{other_model.table_name}.{other_model_id}"),),
        )

        type(cls)._add_association(cls, association)
        type(cls)._log_schema_helper_use(cls, "_belongs_to", name, *args, primary_key=primary_key, **kwargs)

    def process_schema(cls) -> None:
        # If schema has already been processed, do not process again
        if not cls.schema_awaiting_processing:
            return

        # First, build the model's internal representation of the schema, as defined
        super().process_schema()

        # Then, if no primary key has been defined by the schema, create the default "id" primary key
        if not cls.primary_key:
            field = type(cls)._make_field(cls, "id", Integer, primary_key=True)
            type(cls)._getattr(cls, "__primary_key").append(field)

        # Check that a table name has been declared
        if not cls.table_name:
            raise SchemaInvalid(
                f"peristable model '{cls.__name__}' must be given a database table name by calling "
                f"the 'cls._persist_as(table_name)' helper from the '_schema' method"
            )

        # Prepare SQLAlchemy table object using the model's schema
        table = type(cls).__make_db_table(cls.table_name, cls.db_columns)
        setattr(cls, f"_{cls.__name__}__db_table", table)

        # Build SQLAlchemy Relationships from the associations defined by the model's schema
        relationships = {name: type(cls).__assoc_to_rship(assoc) for name, assoc in cls.entity_associations.items()}
        # Use SQLAlchemy to map the empty mapping class to the DB by providing the SQLAlchemy Table and Relationships
        db_manager.registry.map_imperatively(cls.db_mapping, cls.db_table, properties=relationships)  # type: ignore[reportArgumentType]

        # Also perform the DB mapping for each associated model to ensure this is done prior to attempting any queries
        for _, association in cls.associations.items():
            if association.other_model.schema_awaiting_processing:
                association.other_model.process_schema()

    @property
    def table_name(cls) -> str:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        return str(type(cls)._getattr(cls, "__table_name"))

    @property
    def db_mapping(cls) -> type:
        return type(cls)._getattr(cls, "__db_mapping")  # type: ignore[no-any-return]

    @property
    def db_mapping_complete(cls) -> bool:
        if not type(cls)._is_implementation(cls):
            raise TypeError(f"abstract class '{cls.__name__}' does not have a schema to map to database")

        return bool(type(cls)._getattr(cls, "__db_mapping_complete"))

    @property
    def db_table(cls) -> Table:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        return type(cls)._getattr(cls, "__db_table")  # type: ignore[no-any-return]

    @property
    def db_columns(cls) -> list[Column]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        return list(type(cls)._getattr(cls, "__db_columns")).copy()

    @property
    def primary_key(cls) -> list[str]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        return list(type(cls)._getattr(cls, "__primary_key")).copy()

    @property
    def id_field(cls) -> Optional[ModelField]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        primary_key = type(cls)._getattr(cls, "__primary_key")
        field_count = len(primary_key)

        if field_count < 1 or field_count > 1:
            return None

        return cls.fields[primary_key[0]]  # pylint: disable=unsubscriptable-object

    @property
    def entity_associations(cls) -> dict[str, EntityAssociation]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        return {
            name: association
            for name, association in cls.associations.items()
            if isinstance(association, EntityAssociation)
        }

    @property
    def has_one_associations(cls) -> dict[str, HasOneAssociation]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        return {
            name: association
            for name, association in cls.associations.items()
            if isinstance(association, HasOneAssociation)
        }

    @property
    def has_many_associations(cls) -> dict[str, HasManyAssociation]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        return {
            name: association
            for name, association in cls.associations.items()
            if isinstance(association, HasManyAssociation)
        }

    @property
    def belongs_to_associations(cls) -> dict[str, BelongsToAssociation]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        return {
            name: association
            for name, association in cls.associations.items()
            if isinstance(association, BelongsToAssociation)
        }

    @property
    def persistable(cls) -> bool:
        return True

    @property
    def _repr_fields(cls) -> list[str]:
        field_names = super()._repr_fields
        field_names = [name for name in field_names if name not in cls.primary_key]
        field_names = cls.primary_key + field_names
        return field_names[:5]
