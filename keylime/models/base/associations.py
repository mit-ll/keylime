from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Optional, Union

from keylime.models.base.errors import AssociationTypeMismatch, AssociationValueInvalid

if TYPE_CHECKING:
    from keylime.models.base.basic_model import BasicModel
    from keylime.models.base.persistable_model import PersistableModel


class AssociatedRecordSet(set["BasicModel"]):
    """An AssociatedRecordSet contains a set of model instances (i.e., *records*) linked to a *parent record* by way of
    an association established between two models. With a "to-many" association, the set can contain an unbounded number
    of records but with a "to-one" association, the set will only ever contain one at most.
    """

    def __init__(self, parent_record: "BasicModel", association: "ModelAssociation", *args: Any, **kwargs: Any) -> None:
        self._parent_record = parent_record
        self._association = association
        super().__init__(*args, **kwargs)

    def add(self, record: "BasicModel", populate_inverse: bool = True) -> None:
        if not isinstance(record, self.model):
            raise AssociationTypeMismatch(
                f"value of type '{record.__class__.__name__}' cannot be added to AssociatedRecordSet of type"
                f"'{self.model.__name__}'"
            )

        # If the caller has indicated that the inverse association should be populated and the association does have
        # an inverse association defined, back-populate the inverse association by creating a reference to the
        # association's parent record in the record being added to the set
        if populate_inverse and self.association.inverse_association:  # type: ignore
            # Get the record set of the inverse association
            inverse_record_set = self.association.inverse_association.get_record_set(record)  # type: ignore

            # If the association is a "to-one" association, then its record set should always contain, at most, one
            # record, so clear the set before adding the parent record
            if isinstance(self.association, (HasOneAssociation, BelongsToAssociation)):  # type: ignore
                inverse_record_set.clear()

            # Add the association's parent record to the record set of the inverse association
            inverse_record_set.add(self.parent_record, populate_inverse=False)

        super().add(record)

    @property
    def parent_record(self) -> "BasicModel":
        return self._parent_record

    @property
    def association(self) -> "ModelAssociation":
        return self._association

    @property
    def model(self) -> type["BasicModel"]:
        return self.association.other_model  # type: ignore


class ModelAssociation(ABC):
    """A ModelAssociation represents a one-way association from one model to another. It cannot be instantiated directly
    and should be inherited from and customised for the specific type of association.

    As a Python descriptor [1], ModelAssociation allows associated records to be accessed from the parent record using
    dot notation. However, because the __get__ and __set__ methods need to differ depending on the association type (a
    "to-one" association should produce a single record whereas a "to-many" should return the whole
    AssociatedRecordSet), these are left to be defined by the subclass. Even so, protected getters and setters are
    provided by ModelAssociation to make these implementations as simple as possible and avoid duplication.

    [1] https://docs.python.org/3/howto/descriptor.html
    """

    def __init__(self, name: str, other_model: type["BasicModel"], inverse_of: Optional[str] = None) -> None:
        self._name: str = name
        self._private_member: str = "_" + name
        self._other_model: type["BasicModel"] = other_model
        self._inverse_of: Optional[str] = inverse_of

    @abstractmethod
    def __get__(
        self, parent_record: "BasicModel", objtype: Optional[type["BasicModel"]] = None
    ) -> Union[AssociatedRecordSet, "BasicModel", "ModelAssociation", None]:
        pass

    def __delete__(self, parent_record: "BasicModel") -> None:
        self.get_record_set(parent_record).clear()

    def _get_one(self, parent_record: "BasicModel") -> Union["BasicModel", "ModelAssociation", None]:
        if parent_record is None:
            return self

        record_set = self.get_record_set(parent_record)

        if len(record_set) == 1:
            (parent_record,) = record_set
            return parent_record

        return None

    def _get_many(self, parent_record: "BasicModel") -> Union[AssociatedRecordSet, "ModelAssociation", None]:
        if parent_record is None:
            return self

        return self.get_record_set(parent_record)

    def _set_one(self, parent_record: "BasicModel", other_record: "BasicModel") -> None:
        if not isinstance(other_record, self.other_model):
            raise AssociationTypeMismatch(
                f"association '{self.name}' was given a value of type '{type(other_record).__name__}' which is not an "
                f"instance of '{self.other_model.__name__}' as required by the '{type(parent_record).__name__}' model"
            )

        record_set = self.get_record_set(parent_record)
        record_set.clear()
        record_set.add(other_record)

    def get_record_set(self, parent_record: "BasicModel") -> AssociatedRecordSet:
        if not hasattr(parent_record, self._private_member):
            setattr(parent_record, self._private_member, AssociatedRecordSet(parent_record, self))

        return getattr(parent_record, self._private_member)  # type: ignore[no-any-return]

    @property
    def name(self) -> str:
        return self._name

    @property
    def other_model(self) -> type["BasicModel"]:
        return self._other_model

    @property
    def inverse_of(self) -> Optional[str]:
        if not self._inverse_of:
            # Get all associations which point from the associated model back to the parent model
            candidates = [assoc for assoc in self.other_model.associations.values() if assoc.other_model == self]

            # If there is only one such association in the associated model, the inverse association is unambiguous
            if len(candidates) == 1:
                self._inverse_of = candidates[0].name

        return self._inverse_of

    @property
    def inverse_association(self) -> Optional["ModelAssociation"]:
        if not self.inverse_of:
            return None

        return getattr(self.other_model, self.inverse_of)  # type: ignore[no-any-return]

    @property
    @abstractmethod
    def preload(self) -> bool:
        pass


class EmbeddedAssociation(ModelAssociation):
    @property
    def preload(self) -> bool:
        return True


class EmbedsOneAssociation(EmbeddedAssociation):
    def __get__(
        self, parent_record: "BasicModel", _objtype: Optional[type["BasicModel"]] = None
    ) -> Union["BasicModel", "EmbedsOneAssociation", None]:
        return self._get_one(parent_record)

    def __set__(self, parent_record: "BasicModel", other_record: "BasicModel") -> None:
        self._set_one(parent_record, other_record)

    if TYPE_CHECKING:

        def _get_one(self, parent_record: "BasicModel") -> Union["BasicModel", "EmbedsOneAssociation", None]:
            ...


class EmbedsManyAssociation(EmbeddedAssociation):
    def __get__(
        self, parent_record: "BasicModel", _objtype: Optional[type["BasicModel"]] = None
    ) -> Union["AssociatedRecordSet", "EmbedsManyAssociation", None]:
        return self._get_many(parent_record)

    if TYPE_CHECKING:

        def _get_many(self, parent_record: "BasicModel") -> Union[AssociatedRecordSet, "EmbedsManyAssociation", None]:
            ...


class EmbeddedInAssociation(EmbeddedAssociation):
    def __get__(
        self, parent_record: "BasicModel", _objtype: Optional[type["BasicModel"]] = None
    ) -> Union["BasicModel", "EmbedsOneAssociation", None]:
        return self._get_one(parent_record)

    def __set__(self, parent_record: "BasicModel", other_record: "BasicModel") -> None:
        self._set_one(parent_record, other_record)

    if TYPE_CHECKING:

        def _get_one(self, parent_record: "BasicModel") -> Union["BasicModel", "EmbedsOneAssociation", None]:
            ...


class EntityAssociation(ModelAssociation):
    """EntityAssociation extends ModelAssociation to provide additional functionality common to associations which
    map to a relationship between database entities.
    """

    def __init__(
        self,
        name: str,
        other_model: type["PersistableModel"],
        inverse_of: Optional[str] = None,
        foreign_key: Optional[str] = None,
        preload: bool = True,
    ) -> None:
        self._foreign_key: Optional[str] = foreign_key
        self._preload: bool = preload
        super().__init__(name, other_model, inverse_of)

    @property
    def foreign_key(self) -> Optional[str]:
        foreign_key = self._foreign_key

        # If no foreign key was declared for the association, see if is obtainable from the inverse association
        if not foreign_key:
            foreign_key = getattr(self.inverse_association, "_foreign_key", None)  # type: ignore

        return foreign_key

    @property
    def inverse_association(self) -> Optional["EntityAssociation"]:
        ...

    @property
    def preload(self) -> bool:
        return self._preload

    if TYPE_CHECKING:

        def _get_one(self, parent_record: "BasicModel") -> Union["PersistableModel", "EntityAssociation", None]:
            ...

        def _get_many(self, parent_record: "BasicModel") -> Union[AssociatedRecordSet, "EntityAssociation", None]:
            ...

        @property
        def other_model(self) -> type["PersistableModel"]:
            ...


class HasOneAssociation(EntityAssociation):
    """A HasOneAssociation is an association between database-backed models which allows a record to be linked to
    one other. As this is achieved in the database engine with a foreign key in the associated record, it needs a
    corresponding BelongsToAssociation in the associated model.
    """

    def __get__(
        self, parent_record: "BasicModel", _objtype: Optional[type["BasicModel"]] = None
    ) -> Union["PersistableModel", "HasOneAssociation", None]:
        return self._get_one(parent_record)

    def __set__(self, parent_record: "BasicModel", other_record: "PersistableModel") -> None:
        self._set_one(parent_record, other_record)

    if TYPE_CHECKING:

        def _get_one(self, parent_record: "BasicModel") -> Union["PersistableModel", "HasOneAssociation", None]:
            ...


class HasManyAssociation(EntityAssociation):
    """A HasManyAssociation is an association between database-backed models which allows a record to be linked to
    an number of others. As this is achieved in the database engine with a foreign key in the associated records, it
    needs a corresponding BelongsToAssociation in the associated model.
    """

    def __get__(
        self, parent_record: "BasicModel", _objtype: Optional[type["BasicModel"]] = None
    ) -> Union["AssociatedRecordSet", "HasManyAssociation", None]:
        return self._get_many(parent_record)

    if TYPE_CHECKING:

        def _get_many(self, parent_record: "BasicModel") -> Union[AssociatedRecordSet, "HasManyAssociation", None]:
            ...


class BelongsToAssociation(EntityAssociation):
    """A BelongsToAssociation is the inverse of a HasOneAssociation or HasManyAssociation. Like a HasOneAssociation, it
    links its parent record to, at most, one other record. In addition, it populates the parent record's foreign key
    field whenever the associated record changes.
    """

    def __init__(
        self,
        name: str,
        other_model: type["PersistableModel"],
        nullable: bool = False,
        inverse_of: Optional[str] = None,
        foreign_key: Optional[str] = None,
        preload: bool = True,
    ):
        self._nullable: bool = nullable
        super().__init__(name, other_model, inverse_of, foreign_key, preload)

    def __get__(
        self, parent_record: "BasicModel", _objtype: Optional[type["BasicModel"]] = None
    ) -> Union["PersistableModel", "BelongsToAssociation", None]:
        return self._get_one(parent_record)

    def __set__(self, parent_record: "BasicModel", other_record: "PersistableModel") -> None:
        if not type(other_record).id_field:
            raise AssociationValueInvalid(
                f"adding record to '{type(parent_record).__name__}.{self.name}' failed because "
                f"'{type(other_record).__name__}' does not have a single-field primary key"
            )

        # Create reference in record to the associated record
        self._set_one(parent_record, other_record)

        # Get the associated record's ID
        other_record_id = getattr(other_record, type(other_record).id_field.name)  # type: ignore[reportOptionalMemberAccess, union-attr]

        # Add the associated record's ID to the record
        if other_record_id and hasattr(parent_record, self.foreign_key):
            setattr(parent_record, self.foreign_key, other_record_id)

    if TYPE_CHECKING:

        def _get_one(self, parent_record: "BasicModel") -> Union["PersistableModel", "BelongsToAssociation", None]:
            ...

    @property
    def foreign_key(self) -> str:
        foreign_key = super().foreign_key

        # If no foreign key was declared for the association (or the inverse association), use default
        if not foreign_key:
            foreign_key = f"{self.name}_id"

        return foreign_key

    @property
    def nullable(self) -> bool:
        return self._nullable
