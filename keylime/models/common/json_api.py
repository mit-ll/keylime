from keylime.models.base import *


class APIModel(BasicModel):
    def render(self, only=None):
        output = super().render(only)
        output_copy = output.copy()

        # Within JSON:API constructs, do not render null items
        for name, value in output_copy.items():
            if value is None:
                del output[name]

        return output


class APIDocument(APIModel):
    @classmethod
    def _schema(cls):
        cls._embeds_many("data", APIResource)
        cls._virtual("multiresource", Boolean)

        cls._field("errors", List, nullable=True)
        cls._field("meta", Dictionary, nullable=True)
        cls._field("jsonapi", Dictionary, nullable=True)
        cls._field("links", Dictionary, nullable=True)
        cls._field("included", Dictionary, nullable=True)

    @classmethod
    def create_data_doc(cls, type, data, id=None):
        if not isinstance(data, (dict, list)):
            raise TypeError("cannot create JSON:API document: 'data' must be a dictionary or list")

        document = cls.empty()
        document.multiresource = isinstance(data, list)

        if isinstance(data, dict):
            data = [data]

        for element in data:
            if not isinstance(element, dict):
                raise TypeError("cannot create JSON:API document: each element in 'data' must be a dictionary")

            resource = APIResource.create(type, element, id=id)
            document.data.add(resource)

        return document

    @classmethod
    def create_errors_doc(cls, errors):
        if not isinstance(errors, list):
            raise TypeError("cannot create JSON:API document: 'errors' must be a list")

        document = cls.empty()

        for error in errors:
            if not isinstance(error, dict):
                raise TypeError("cannot create JSON:API document: each element in 'errors' must be a dictionary")

        document.change("errors", errors)

        return document

    @property
    def data(self):
        # pylint: disable=no-else-return

        assoc = self.__class__.embeds_many_associations["data"]
        record_set = assoc.get_record_set(self)

        if not self.multiresource:
            return record_set

        if len(record_set) == 1:
            (record,) = record_set
            return record
        else:
            return None

    @property
    def errors(self):
        return self.values.get("errors")

    def render(self, only=None):
        if not self.data and not self.errors and not self.meta:
            raise ValueError("invalid JSON:API document: at least one of 'data', 'errors' or 'meta' is required")

        if self.data and self.errors:
            raise ValueError("invalid JSON:API document: only one of 'data' or 'errors' is permitted")

        output = super().render(only)

        # If the document is meant to represent a single resource, render it as a dictionary, rather than a list
        if not self.multiresource:
            if len(output["data"]) == 0:
                output["data"] = None
            elif len(output["data"]) == 1:
                output["data"] = output["data"][0]
            else:
                raise ValueError(
                    "multiple resources found in JSON:API document which was initialised as a single-resource document"
                )

        return output


class APIResource(APIModel):
    @classmethod
    def _schema(cls):
        cls._embedded_in("document", APIDocument)

        cls._field("type", String, nullable=True)
        cls._field("id", String, nullable=True)
        cls._field("attributes", Dictionary, nullable=True)
        cls._field("relationships", Dictionary, nullable=True)
        cls._field("links", Dictionary, nullable=True)
        cls._field("meta", Dictionary, nullable=True)

        # Note: ``lid`` (local identifier) field is not implemented

    @classmethod
    def create(cls, type, attributes, id=None):
        if not isinstance(attributes, dict):
            raise TypeError("cannot create JSON:API resource: 'type' must be a string")

        if id and not isinstance(id, str):
            raise TypeError("cannot create JSON:API resource: 'id' must be a string")

        if not isinstance(attributes, dict):
            raise TypeError("cannot create JSON:API resource: 'attributes' must be a dictionary")

        resource = cls.empty()
        resource.type = type
        resource.id = id
        resource.attributes = attributes

        return resource
