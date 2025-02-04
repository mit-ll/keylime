import base64
import binascii
import re
from abc import ABC, abstractmethod
from types import MappingProxyType
from typing import Any, Container, Iterable, Mapping, Optional, Pattern, Sequence, Union

from keylime.models.base.basic_model_meta import BasicModelMeta
from keylime.models.base.errors import FieldValueInvalid, UndefinedField


class BasicModel(ABC, metaclass=BasicModelMeta):
    """A model is a class which represents a data object in the system, each with a number of defined "fields".
    Individual instances are known as "records" and contain values for the model's fields. Models encapsulate the
    functionality related to querying, manipulating, validating and displaying records.

    The BasicModel abstract class provides the basic functionality common to all models including:

    * a domain-specific language (DSL) for specifying a schema to which individual records are expected to adhere;
    * a validation API for checking that the fields adhere to an expected format; and
    * an API for collecting changes to a record and applying them if they pass validation rules.

    If you need to persist a model to the database, you should subclass ``PersistableModel`` instead (which itself
    inherits from ``BasicModel``).

    Declaring a Model and Its Schema
    --------------------------------

    To create a new model, declare a new class which inherits from ``BasicModel`` and implement the required ``_schema``
    class method::

        def User(BasicModel):
            @classmethod
            def _schema(cls):
                cls._field("email", String, nullable=True)
                # (Any additional fields...)

    Fields are defined using the ``cls._field(...)`` helper method. Calls to this method (or any other helper) must
    happen within the ``_schema`` method to ensure that they are invoked at the right point in the model's lifecycle.
    The ``_field`` method takes a name, data type and an optional list of options. When subclassing ``BasicModel``
    directly as in the example above, the only option accepted is ``nullable`` which controls whether the field will
    accept empty values like ``None`` or ``""``.

    Schema helper methods mutate the model, causing various class members to be created or modified dynamically at time
    of invocation. For instance, the "email" field declared in the example above causes a ``ModelField`` instance to be
    added to the ``User`` class as a descriptor. This allows access of the field value via dot notation::

        user = User.empty()
        user.name = "John"
        print(user.name) #=> "John"

    Definitions of the helper methods can be found in the ``BasicModelMeta`` class.

    Associations
    ------------

    Models can be linked to other models so that records may contain references to other records. For the moment, no
    associations can be declared on a model based on ``BasicModel`` but this will likely change in the future. See the
    documentation for ``PersistableModel`` for associations which can be declared on database-backed models.

    Mutating Records
    ----------------

    As shown previously, it is possible to change a field by assigning it as if it were a property/attribute of the
    record. Behind the scenes, this calls the ``record.change(...)`` method which can also be invoked directly. The new
    value is saved in a dictionary of pending changes accessible from ``record.changes``.

    For convenience, you may change several fields at once by calling ``record.cast_changes(data, fields)`` where
    ``data`` is a dictionary with the new values and ``fields`` is a list of field names to change. ``data`` may contain
    any arbitrary data (even data which originates from outside the application) as only the fields explicitly listed in
    ``fields`` will be affected. This is illustrated below::

        def change_user_profile(user, profile_data):
            user.cast_changes(profile_data, ["name", "email", "phone"])
            # ...

        # Data received in HTTP request:
        request_data = {
            "name": "John",
            "email": "jsmith@example.com",
            "admin": True
        }
        change_user_profile(user, request_data)

        # "admin" field has not been changed:
        print(user.admin) #=> False

    Pending changes can be accepted by calling ``record.commit_changes()``. This causes the values in ``record.changes``
    to be moved to the ``record.committed`` dictionary. A common pattern is to queue up changes to several fields,
    perform validation on the pending changes, and then commit them all in one go.

    Accessing Field Values
    ----------------------

    Reading a field value using dot notation will return any pending change for the field. If no pending change is
    present in the record, this will fall back on the committed value for the field. Alternatively, you may access
    values from ``record.values`` which uses this same behaviour. This is illustrated by the below example::

        print(user.committed.get("name")) #=> "John"
        print(user.changes.get("name"))   #=>  None
        print(user.values.get("name"))    #=> "John"
        print(user.name)                  #=> "John"

        user.change("name", "Jane")

        print(user.committed.get("name")) #=> "John"
        print(user.changes.get("name"))   #=> "Jane"
        print(user.values.get("name"))    #=> "Jane"
        print(user.name)                  #=> "Jane"

    Data Validation
    ---------------

    Pending changes can be checked to conform to the expected format by using the various data validation methods. For
    example, calling ``record.validate_length("name", max: 50)`` will check that the "name" field is no longer than 50
    characters. If the check fails, an error will be recorded for that field.

    When errors are present in a record, ``record.commit_changes()`` raises a ``FieldValueInvalid`` exception. You can
    check whether there are any errors present for the record's pending changes by calling ``record.changes_valid``.
    And you can get the dictionary of errors (organised by field) from ``record.errors``.

    There are validation methods for various types of data and situations. However, you may need perform your own custom
    data validation. In such case, you can call ``record._add_error(field, msg)`` where ``field`` is the name of the
    field with the invalid change and ``msg`` is a short explanation of why the change is considered invalid. You should
    expect ``msg`` to be returned to the API consumer in an HTTP response, so it should not contain sensitive
    information about the internal state of the server.

    NOTE: You may find it peculiar that validation rules are not defined within each field declaration, a common pattern
    for data model libraries. This design is intentional as it provides more flexibility, allowing you to apply
    validation rules conditionally depending on the circumstance or current state of the record. See the "Paradigms for
    Good Model Design" section for details.

    Rendering Records
    -----------------

    Calling ``record.render()`` produces a JSON-serialisable dictionary of the record's contents with field names mapped
    to field values. When using this method to produce user-facing output, e.g., in the context of an HTTP response, it
    is recommended that you pass in a list of allowable fields. When the method is used in this way, no field which
    isn't explicitly listed will be included in the output. This helps ensure that no field containing sensitive data
    (e.g., a password) is explicitly output.

    NOTE: You should do this even when the information in your model is entirely benign. You may not be able to predict
    what fields will be added to the model in the future.

    You may wish to override the render method to provide a sensible default for the list of allowable fields. That way,
    a call to ``record.render()`` with no arguments will return those specific fields, rather than the entire record.
    This saves on typing, reduces complexity in your controllers, and prevents users of your model from accidentally
    leaking sensitive data. Here is an example of how you may achieve this::

        def render(self, only=None):
            if not only:
                only = ["username", "bio"]

            return super().render(only)

    Paradigms for Good Model Design
    -------------------------------

    When creating a new model, you should avoid defining public methods, getters and setters or properties for
    retrieving and mutating individual fields as these are already provided for you, being generated in response to the
    schema you've defined. Because of this, you should not attempt to validate data at the point of being received by a
    field, or try to prevent fields from being accessed or mutated from outside the model/record.

    Instead, your methods should be concerned with managing the data lifecycle of the model. When data is changed as a
    result of a particular event, your model should have a way of handling that specific scenario, including performing
    the relevant data validation.

    To illustrate this, imagine a ``User`` model for a typical web application. Records of this model are created when a
    user registers and changed when a user edits their profile settings. The app also has a way of resetting a user's
    password if forgotten. One way of handling all of this is to define different methods for each possibility, e.g.:

    * ``User.register(data)``: a class method that creates and returns a new ``User`` object using the ``data`` received
      from the registration form
    * ``user.edit_profile(data)``: an instance method which changes the existing ``user`` using ``data`` received from
      the profile edit form
    * ``user.reset_password(data)``: an instance method which changes the existing ``user`` using ``data`` received
      from the password reset form

    Each of these methods would likely call ``cls.cast_changes(...)`` internally to only modify those fields which are
    permitted to be changed in each circumstance. Then, they would perform validation of the incoming data (using the
    various ``cls.validate...`` methods) as relevant. These methods may also set or initialise internal fields such as
    the timestamp at which the user account is created.

    Treating each scenario separately allows us to prevent changes to a user's date of birth and username after account
    creation. The password field can be required during registration but optional when the user is editing their
    profile. And we can prevent a password reset if the user has not confirmed their email address.

    We may also vary how a given field is treated based on the value of another field. For instance, we could check that
    a "confirm password" field matches the "password" field but only if the password is currently being changed,
    allowing the user to leave these fields blank on the profile edit form if they are only changing other settings.
    This is a technique that is used quite heavily in the ``RegistrarAgent`` model, for example, to require the presence
    of a DevID in the absence of an EK cert and vice versa.

    You should think about output in the same way. A user will appear differently in an admin interface than when shown
    as a public profile, so it would make sense to provide multiple render functions, e.g., ``user.render_full()`` and
    ``user.render_public()``.

    It is important to recognise that many models are simpler than our ``User`` example such that updating a record
    looks mostly the same across all scenarios and the action of creating a record is not much different either. In
    these cases, it may make sense to provide a single ``record.update(data)`` instance method and chain this with a
    call to the built-in ``Model.empty()`` class method when you need to create new records::

        record = Model.empty().update(data)

    However, you should still think carefully about the data lifecycle of a "simple" model as you may need to manage how
    parts of it transform over time, depending on the context of other changes. For example, when the EK or AK of a
    ``RegistrarAgent`` record changes, the "active" field is reset to false to require a repeat of the
    TPM2_ActivateCredential process and cryptography bind the AK to EK.
    """

    INST_ATTRS: tuple[str, ...] = ("_committed", "_changes", "_errors")

    @classmethod
    @abstractmethod
    def _schema(cls) -> None:
        pass

    @classmethod
    def empty(cls) -> "BasicModel":
        return cls()

    def __init__(self, data: Optional[dict] = None, process_associations: bool = True) -> None:
        # Populate field and association collections and create instance members based on the defined schema
        if type(self).schema_awaiting_processing:
            type(self).process_schema()

        # Collection for the record's current data
        self._committed: dict[str, Any] = {}
        # Collection to keep pending changes to be made to the record's data
        self._changes: dict[str, Any] = {}
        # Collection of errors related to the pending changes
        self._errors: dict[str, list[str]] = {}

        if data is None:
            data = {}

        if isinstance(data, dict):
            self._init_from_dict(data, process_associations)
        else:
            raise TypeError(
                f"model '{self.__class__.__name__}' cannot be initialised with data of type '{data.__class__.__name__}'"
            )

    def _init_from_dict(self, data: dict, _process_associations: bool) -> None:
        for name, value in data:
            self.change(name, value)

        self._force_commit_changes()

    def __setattr__(self, name: str, value: Any) -> None:
        if (
            not name.startswith("_")
            and name not in dir(self)
            and name not in type(self).INST_ATTRS
            and name not in type(self).fields.keys()
            and name not in type(self).associations.keys()
        ):
            msg = f"cannot set '{name}' as model '{type(self).__name__}' defines no field or attribute with that name"
            raise AttributeError(msg)

        super().__setattr__(name, value)

    # TODO: Uncomment
    """ def __getattribute__(self, name: str) -> Any:
        try:
            return super().__getattribute__(name)
        except AttributeError:
            msg = f"cannot get '{name}' as model '{type(self).__name__}' defines no field or attribute with that name"
            raise AttributeError(msg) from None
    """

    def __repr__(self) -> str:
        """Returns a code-like string representation of the model instance

        :returns: string
        """
        # pylint: disable=redefined-builtin

        repr = f"{self.__class__.__name__}("
        repr_fields = self.__class__._repr_fields
        count = 0

        for field_name in repr_fields:
            field_value = str(getattr(self, field_name))
            field_value = (field_value[:32] + "...") if len(field_value) > 32 else field_value

            repr += f"{field_name}: {field_value}, "
            count += 1

        if count < len(repr_fields):
            repr += "..."
        else:
            repr = repr.rstrip(", ")

        repr += ")"

        return repr

    def change(self, name: str, value: Any) -> None:
        if name not in self.__class__.fields:
            raise UndefinedField(f"field '{name}' does not exist in model '{self.__class__.__name__}'")

        # Reset the errors for the field to an empty list
        self._errors[name] = []

        # Get Field instance for name in order to obtain its type (ModelType object)
        field = self.__class__.fields[name]

        try:
            # Attempt to cast incoming value to field's declared type
            self._changes[name] = field.data_type.cast(value)
        except Exception:
            # If above casting fails, produce a type mismatch message and add it the field's list of errors
            self._add_error(name, field.data_type.generate_error_msg(value))

        if not field.nullable and value is None:
            self._add_error(name, "cannot be null")

    def cast_changes(self, changes: Mapping[str, Any], permitted: Optional[Sequence[str]] = None) -> None:
        if permitted is None:
            permitted = []

        for name, value in changes.items():
            if (name not in permitted) or (name not in self.__class__.fields):
                continue

            self.change(name, value)

    def commit_changes(self) -> None:
        if not self.changes_valid:
            raise FieldValueInvalid(f"pending changes for model '{self.__class__.__name__}' have validation errors")

        for name, value in self._changes.items():
            if value is None and not self.__class__.fields[name].nullable:
                raise FieldValueInvalid(f"field 'name' for model '{self.__class__.__name__}' is not nullable")

            self._committed[name] = value

        self.clear_changes()

    def _force_commit_changes(self) -> None:
        for name, value in self._changes.items():
            self._committed[name] = value

        self.clear_changes()

    def clear_changes(self) -> None:
        self._changes.clear()
        self._errors.clear()

    def errors_for(self, field: str) -> list[str]:
        if not self._errors.get(field):
            self._errors[field] = []

        return list(self._errors[field]).copy()

    def _add_error(self, field: str, msg: str) -> None:
        if not self._errors.get(field):
            self._errors[field] = []

        if msg not in self._errors[field]:
            self._errors[field].append(msg)

    def validate_required(self, fields: Union[str, Sequence[str]], msg: str = "is required") -> None:
        if isinstance(fields, str):
            fields = [fields]

        for field in fields:
            if not self.values.get(field):
                self._add_error(field, msg)

    def validate_base64(self, fields: Union[str, Sequence[str]], msg: str = "must be Base64 encoded") -> None:
        if isinstance(fields, str):
            fields = [fields]

        for field in fields:
            value = self.values.get(field) or ""

            try:
                base64.b64decode(value, validate=True)
            except binascii.Error:
                self._add_error(field, msg)

    def validate_inclusion(self, field: str, data: Union[Container, Iterable], msg: str = "is invalid") -> None:
        if self.values.get(field) not in data:
            self._add_error(field, msg)

    def validate_exclusion(self, field: str, data: Union[Container, Iterable], msg: str = "is invalid") -> None:
        if self.values.get(field) in data:
            self._add_error(field, msg)

    def validate_subset(self, field: str, data: Sequence, msg: str = "has an invalid entry") -> None:
        value_as_set = set(self.values.get(field, set()))

        if len(value_as_set) == 0 or value_as_set.issubset(data):
            self._add_error(field, msg)

    def validate_length(
        self, field: str, min: Optional[int] = None, max: Optional[int] = None, msg: Optional[str] = None
    ) -> None:
        # pylint: disable=redefined-builtin

        value = self.values.get(field)
        length = len(value) if value else 0
        element_type = "character" if isinstance(value, str) else "item"

        if min and length < min:
            self._add_error(field, msg or f"should be at least {length} {element_type}(s)")

        if max and length > max:
            self._add_error(field, msg or f"should be at most {length} {element_type}(s)")

    def validate_number(self, field: str, *expressions: tuple[str, int | float], msg: Optional[str] = None) -> None:
        value = self.values.get(field)

        if not value:
            return

        for exp in expressions:
            if exp[0] == "<" and value >= exp[1]:
                self._add_error(field, msg or f"must be less than {exp[1]}")
            elif exp[0] == ">" and value <= exp[1]:
                self._add_error(field, msg or f"must be greater than {exp[1]}")
            elif exp[0] == "<=" and value > exp[1]:
                self._add_error(field, msg or f"must be less than or equal to {exp[1]}")
            elif exp[0] == ">=" and value < exp[1]:
                self._add_error(field, msg or f"must be greater than or equal to {exp[1]}")
            elif exp[0] == "==" and value != exp[1]:
                self._add_error(field, msg or f"must be equal to {exp[1]}")
            elif exp[0] == "!=" and value == exp[1]:
                self._add_error(field, msg or f"must not be equal to {exp[1]}")

    def validate_format(self, field: str, format: Union[str, Pattern], msg: Optional[str] = None) -> None:
        # pylint: disable=redefined-builtin

        value = self.values.get(field, "")

        if not re.fullmatch(format, value):
            self._add_error(field, msg or "does not have the correct format")

    def validate_snake_case(self, fields: Union[str, Sequence[str]], msg: Optional[str] = None):
        msg = msg or "can only contain lowercase letters, numbers and underscores"

        for field in fields:
            self.validate_format(field, "[a-z0-9_]+", msg)

    def _render_field(self, name: str, data: dict[str, Any]) -> dict[str, Any]:
        field = self.__class__.fields[name]
        value = getattr(self, name, None)

        if field.render:
            data[name] = field.data_type.render(value)

        return data

    def _render_embedded_record(self, name: str, data: dict[str, Any]) -> dict[str, Any]:
        value = getattr(self, name, None)
        data[name] = value.render() if value is not None else None
        return data

    def _render_embedded_record_set(self, name: str, data: dict[str, Any]) -> dict[str, Any]:
        value = getattr(self, name, None)

        if value is None:
            data[name] = None
        else:
            data[name] = []

            for record in value:
                data[name].append(record.render())

        return data

    def render(self, only: Optional[Sequence[str]] = None) -> dict[str, Any]:
        data = {}

        # Locate record members by iterating through schema helper calls so that fields ane embedded records are
        # rendered in the order in which they were defined
        for _, args, kwargs in self.__class__.schema_helpers_used:
            # Get member name from kwargs passed to schema helper or first positional argument
            first_arg = args[0] if len(args) > 0 else None
            name = kwargs.get("name") or first_arg

            # If the "name" obtained does not look like a name, skip
            if not name or not isinstance(name, str):
                continue

            # If member name not present in provided allowlist, skip
            if only and name not in only:
                continue

            # If member name is the name of a field, render its value according to the field's data type
            if name in self.__class__.fields.keys():
                self._render_field(name, data)
            # If member name is the name of an embedded record, render the full record
            elif name in self.__class__.embeds_one_associations.keys():
                self._render_embedded_record(name, data)
            # If member name is the name of a set of embedded records, render as a list of records
            elif name in self.__class__.embeds_many_associations.keys():
                self._render_embedded_record_set(name, data)

        return data

    @property
    def committed(self) -> Mapping[str, Any]:
        return MappingProxyType(self._committed)

    @property
    def changes(self) -> Mapping[str, Any]:
        return MappingProxyType(self._changes)

    @property
    def values(self) -> Mapping[str, Any]:
        return MappingProxyType({**self.committed, **self.changes})

    @property
    def errors(self) -> Mapping[str, Sequence | Mapping]:
        errors = {field: errors for field, errors in self._errors.items() if len(errors) > 0}

        embeds = {**self.__class__.embeds_one_associations, **self.__class__.embeds_many_associations}

        for name, embed in self.__class__.embeds_one_associations.items():
            (record,) = embed.get_record_set(self) or (None,)

            if record and record.errors:
                errors.update({f"{name}.{fname}": error for fname, error in record.errors.items()})

        for name, embed in self.__class__.embeds_many_associations.items():
            for index, record in enumerate(embed.get_record_set(self)):
                if record.errors:
                    errors.update({f"{name}[{index}].{fname}": error for fname, error in record.errors.items()})

        return errors

    @property
    def changes_valid(self) -> bool:
        return len(self.errors) == 0
