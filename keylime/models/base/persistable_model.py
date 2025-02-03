from typing import Any, Optional, Sequence

from sqlalchemy import or_

from keylime.models.base.basic_model import BasicModel
from keylime.models.base.db import db_manager
from keylime.models.base.errors import FieldValueInvalid, QueryInvalid
from keylime.models.base.persistable_model_meta import PersistableModelMeta


class PersistableModel(BasicModel, metaclass=PersistableModelMeta):
    """PersistableModel extends the BasicModel class to provide additional functionality for saving and retrieving
    records to and from a database. Internally, a SQLAlchemy-mapped class is built dynamically from the schema
    defined by the implementing class, and model change operations are mapped to their SQLAlchemy equivalent.
    Additionally, a query API is provided to fetch data from the database and properly instantiate records.

    For details on the schema, data validation and change management APIs, refer to the documentation for
    ``BasicModel``. You should subclass ``BasicModel`` directly in cases where you need an in-memory model that is
    not persisted to the database.

    Linking to a Database Table
    ---------------------------

    All models which inherit from ``PersistableModel`` should have, at minimum, a ``cls._persist_as(...)`` declaration
    present in their schema. This sets the database table name which will be used to produce database queries to save
    and retrieve the model's records. Note that ``PersistableModel`` will not create the named table automatically, so
    new database-backed models should be accompanied by a migration to create a table with a matching schema in the
    database engine.

    Additionally, it is likely that you will want your model to have a unique identifier. You can do so by adding a
    ``cls._id(...)`` declaration to the schema which specifies the existence of a single-field primary key. If you wish
    to have a composite primary key (useful for join tables), you should instead provide the ``primary_key=True`` option
    when declaring the fields that make up the primary key. Note that if the rows from the linked database table are
    intended to be referenced by other rows in the database, you must use a single-field primary key.

    Associations
    ------------

    You may wish to indicate that an association exists between different models. The schema helpers which should be
    used will depend on the type of association you are trying to establish. See the examples which follow.

    To create a one-to-one association between two database-backed models::

        def Employee(PersistableModel):
            @classmethod
            def _schema(cls):
                cls._id("email", String)
                cls._has_one("office", Office)

        def Office(PersistableModel):
            @classmethod
            def _schema(cls):
                cls._id("room_number", Integer)
                cls._belongs_to("employee", Employee, foreign_key="employee_email")
                # This will automatically create a field called "employee_email" to reference the employee

    To create a one-to-many association between two database-backed models::

        def BlogPost(PersistableModel):
            @classmethod
            def _schema(cls):
                cls._id("id", Integer)
                cls._has_many("comments", Comment)

        def Comment(PersistableModel):
            @classmethod
            def _schema(cls):
                cls._id("id", Integer)
                cls._belongs_to("blog_post", BlogPost)
                # Without the "foreign_key" option, a default foreign key field called "blog_post_id" will be created

    In order to create a many-to-many association, you need to create a model corresponding to a join table:

        def Student(PersistableModel):
            @classmethod
            def _schema(cls):
                cls._id("id", Integer)
                cls._has_many("student_classes", StudentClass)

        def Class(PersistableModel):
            @classmethod
            def _schema(cls):
                cls._id("id", Integer)
                cls._has_many("student_classes", StudentClass)

        def StudentClass(PersistableModel):
            @classmethod
            def _schema(cls):
                cls._belongs_to("student", Student)
                cls._belongs_to("class", Class)

    Fetching Records
    ----------------

    You can use the provided query methods to fetch records from the database and instantiate them as a model instance:

    * ``Model.get(123)`` will return the record with an ID of ``123`` or ``None`` if it does not exist
    * ``Model.get(field_1="abc", field_2="def")`` will return the record with the two fields set to the given values
    * ``Model.all(field_3=True)`` will return all matching records
    * ``Model.all_ids(field_3=True)`` will return all the IDs of the matching records

    These method calls will also cause any associated records to be fetched, as long as the association is declared
    with the preload option set to ``True`` (the default). These can be accessed using the association name (e.g.,
    ``employee.office`` if ``employee`` is a record and ``office`` is the name of an association).

    Persisting and Deleting Records
    -------------------------------

    To save a new or modified record to the database, simply call ``record.commit_changes()`` which should succeed as
    long as no errors are present in the record and no database constraints are violated.

    For deleting a record from the database, ``PersistableModel`` provides ``record.delete()``.
    """

    # pylint: disable=using-constant-test

    INST_ATTRS: tuple[str, ...] = (*BasicModel.INST_ATTRS, "_db_mapping_inst")

    @classmethod
    def _build_filter_criterion(cls, name, values):
        sa_field = getattr(cls.db_mapping, name)

        if values is None:
            return []

        if not isinstance(values, tuple):
            values = (values,)

        criteria = [sa_field == value for value in values]

        return or_(*criteria)

    @classmethod
    def _query(cls, session, args, kwargs, subject=None):
        if not subject:
            subject = cls.db_mapping

        filters = kwargs
        sort_criteria = kwargs.get("sort_", ())

        if not isinstance(sort_criteria, (list, tuple)):
            sort_criteria = (sort_criteria,)

        if sort_criteria:
            del filters["sort_"]

        if filters and args:
            raise QueryInvalid("a PersistableModel query must use filters or SQLAlchemy expressions but not both")

        if filters:
            filter_criteria = [
                cls._build_filter_criterion(name, values) for name, values in filters.items() if values is not None
            ]
        else:
            filter_criteria = args

        return session.query(subject).filter(*filter_criteria).order_by(*sort_criteria)

    @classmethod
    def all(cls, *args: Any, **kwargs: Any) -> Sequence["PersistableModel"]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        with db_manager.session_context() as session:
            results = cls._query(session, args, kwargs).all()

        return [cls(mapping_inst) for mapping_inst in results]

    @classmethod
    def all_ids(cls, *args: Any, **kwargs: Any) -> Sequence[Any]:
        if cls.schema_awaiting_processing:
            cls.process_schema()

        if not cls.id_field:
            raise QueryInvalid(f"model '{cls.__name__}' does not have a field which is used as an ID")

        id_column = cls.db_table.columns[cls.id_field.name]

        with db_manager.session_context() as session:
            results = cls._query(session, args, kwargs, subject=id_column).all()

        return [getattr(row, cls.id_field.name) for row in results]

    @classmethod
    def get(cls, *args: Any, record_id: Optional[Any] = None, **kwargs: Any) -> Optional["PersistableModel"]:
        # pylint: disable=no-else-return

        if cls.schema_awaiting_processing:
            cls.process_schema()

        if record_id:
            if not cls.id_field:
                raise QueryInvalid(f"model '{cls.__name__}' does not have a field which is used as an ID")

            kwargs[cls.id_field.name] = record_id

        with db_manager.session_context() as session:
            results = cls._query(session, args, kwargs).first()

        if results:
            return cls(results)
        else:
            return None

    def __init__(self, data: Optional[dict | object] = None, process_associations: bool = True) -> None:
        if isinstance(data, type(self).db_mapping):
            super().__init__({}, process_associations)
            self._init_from_mapping(data, process_associations)
        else:
            super().__init__(data, process_associations)  # type: ignore[reportArgumentType, arg-type]

    def _init_from_mapping(self, mapping_inst: object, process_associations: bool) -> None:
        self._db_mapping_inst = mapping_inst

        for name, field in type(self).fields.items():
            if not field.persist:
                continue

            value = getattr(mapping_inst, name)
            self._committed[name] = field.data_type.db_load(value, db_manager.engine.dialect)

        if process_associations:
            for name, association in type(self).associations.items():
                association_mapping = getattr(mapping_inst, name)

                if association_mapping is not None:
                    value = association.other_model(association_mapping, process_associations=False)
                    setattr(self, name, value)

    def _init_from_dict(self, data: dict, _process_associations: bool) -> None:
        self._db_mapping_inst = type(self).db_mapping()

        for name, value in data:
            self.change(name, value)
            setattr(self._db_mapping_inst, name, value)

        self._force_commit_changes()

    def commit_changes(self) -> None:
        if not self.changes_valid:
            raise FieldValueInvalid(f"pending changes for model '{type(self).__name__}' have validation errors")

        for name, value in self._changes.items():
            self._committed[name] = value

            field = type(self).fields[name]

            if field.persist:
                setattr(self._db_mapping_inst, name, field.data_type.db_dump(value, db_manager.engine.dialect))

        with db_manager.session_context() as session:
            session.add(self._db_mapping_inst)

        self.clear_changes()

    def delete(self) -> None:
        with db_manager.session_context() as session:
            session.delete(self._db_mapping_inst)  # type: ignore[no-untyped-call]
