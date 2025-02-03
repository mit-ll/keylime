from keylime.models.base import *


class IdentityBinding(BasicModel):
    @classmethod
    def _schema(cls):
        cls._embedded_in("identity", Identity)

        cls._field("parent", String)
        cls._field("method", OneOf("cert_comparison", "tpm_challenge"))

    @classmethod
    def create(cls, parent, method) -> "IdentityBinding":
        if isinstance(parent, Identity):
            parent = parent.name

        record = IdentityBinding.empty()
        record.parent = parent
        record.method = method
        return record  # type: ignore

    def finalise(self):
        self.validate_snake_case("parent")


class IdentityTrust(BasicModel):
    @staticmethod
    def select_least_trusted(*trust_objects):
        if len(trust_objects) == 0:
            raise ValueError("IdentityTrust.select_least_trusted(...) expects at least 1 argument")

        trust_levels = ["undecided", "untrusted", "semitrusted", "trusted"]
        least_trusted = trust_objects[0].trust if isinstance(trust_objects[0], Identity) else trust_objects[0]

        for trust_object in trust_objects:
            if isinstance(trust_object, Identity):
                trust_object = trust_object.trust

            if trust_levels[trust_object.status] < trust_levels[least_trusted.status]:
                least_trusted = trust_object

        return least_trusted

    @classmethod
    def _schema(cls):
        cls._embedded_in("identity", Identity)

        cls._field("status", OneOf("undecided", "untrusted", "semitrusted", "trusted"))
        cls._field("method", OneOf("trust_store", "web_hook_override", "inheritance"), nullable=True)
        cls._field("inherited_from", String, nullable=True)

    @classmethod
    def empty(cls) -> "IdentityDecision":
        record = super().empty()
        record.status = "undecided"
        record.method = None
        return record  # type: ignore

    def update(self, status, method):
        if method == "inheritance":
            raise ValueError(
                "cannot use IdentityTrust.update(...) to update trust status using inheritance; call "
                "IdentityTrust.inherit_from(...) instead"
            )

        self.status = status
        self.method = method

    def inherit_from(self, other_identity):
        self.status = other_identity.trust.status
        self.method = "inheritance"
        self.inherited_from = other_identity.name

    def finalise(self):
        self.validate_snake_case("inherited_from")

        if self.status != "undecided":
            self.validate_required("method")

        if self.method == "inheritance":
            self.validate_required("inherited_from")
        elif self.inherited_from:
            self._add_error("inherited_from", "must be null when trust status is not determined by inheritance")

    def render(self, only=None):
        only = only or ["status", "method", "inherited_from"]

        output = super().render(only)

        if output.get("method") != "inheritance":
            del output["inherited_from"]

        return output


class Identity(BasicModel):
    @classmethod
    def _schema(cls):
        cls._embedded_in("identity_decision_notification", IdentityDecision)

        cls._field("class", OneOf("identifier", "certificate", "public_key", "shared_key"))
        cls._field("name", String)
        cls._field("value", OneOf(Certificate, Text))
        cls._embeds_many("bindings", IdentityBinding)
        cls._embeds_one("trust", IdentityTrust)

    @classmethod
    def empty(cls) -> "Identity":
        record = super().empty()
        record.trust = IdentityTrust.empty()
        return record  # type: ignore

    @classmethod
    def create(cls, identity_class, name, value) -> "Identity":
        record = Identity.empty()

        record.change("class", identity_class)
        record.change("name", name)
        record.change("value", value)

        return record

    def add_binding(self, parent, method):
        if isinstance(parent, Identity) and not parent.name:
            raise ValueError(f"cannot add binding between identity '{self.name}' and an identity with no name")

        binding = IdentityBinding.create(parent, method)
        self.bindings.add(binding)

    def finalise(self):
        self.trust.finalise()

        for binding in self.bindings:
            binding.finalise()

        self.validate_snake_case("name")

        match self.values["class"]:
            case "public_key" | "shared_key":
                self.validate_base64("value")
            case "certificate":
                if not isinstance(self.values["value"], Certificate):
                    self._add_error("value", Certificate().generate_error_msg(self.values["value"]))


class IdentityDecision(BasicModel):
    @classmethod
    def _schema(cls):
        cls._embeds_many("identities", Identity)

        cls._field("root_identities", List)
        cls._field("unbound_identities", List)
        cls._field("platform_identified", Boolean)
        cls._field("generated_at", Timestamp)

        cls._virtual("binding_trees", List)

    @classmethod
    def empty(cls) -> "IdentityDecision":
        record = super().empty()
        record.generated_at = Timestamp.now()
        return record  # type: ignore

    def _build_binding_tree(self, parent):
        """Builds a trust inheritance tree from a parent identity to all of its subordinate identities. An example tree
        might look something like this::

                   iak_cert
                   /      \
                 iak      serial_no
               /  |  \
            ak1  ak2  ak3
                   
        Each node in the tree is represented in memory by a 2-tuple: ``(parent, children)``. The above tree would
        therefore result in the following representation::
        
            ( "iak_cert", [
                ( "iak", [ 
                            ("ak1", []),
                            ("ak2", []),
                            ("ak3", [])
                        ] ),
                ( "serial_no", [] )
            ] )

        This causes all descendents of "iak_cert" to inherit its trust status. 

        The method works by building the tree in a top-down fashion, starting from the given parent identity and finding
        all identities which are immediate descendents (children) of the parent, i.e., identities which have a binding
        to the parent identity. The method is then called recursively on each of the children, using the child as the
        new parent identity. If a parent has no children, the method returns it as a leaf node (a parent with an empty
        list, representing a null subtree).

        When an identity appears in multiple places in a tree, or in multiple trees, the identity inherits its trust
        status from whichever parent has been granted the lowest level of trust.
        """
        children = []

        for identity in self.identities:
            if identity.name == parent:
                parent_identity = identity
                break

        if not parent_identity:
            raise ValueError(f"cannot find identity with name '{parent}'")

        # Iterate over all identities and their bindings to find identities which directly inherit from the parent
        for identity in self.identities:
            for binding in identity.bindings:
                if binding.parent == parent:
                    # If the current identity inherits directly from ``parent``, add it to the list of parents
                    children.append(identity.name)

                    # Skip trust inheritance if the identity has its own trust status already set, unless that trust
                    # status was reached on the basis of another ancestor identity (i.e., the identity, or one of its
                    # ancestors, has more than one parent identity)
                    if identity.trust.method not in (None, "inheritance"):
                        continue

                    if identity.trust.status == "undecided":
                        # If the identity's trust status has not been decided, use the status status of the parent
                        identity.trust.status = parent_identity.trust.status
                        identity.trust.inherited_from = parent
                    else:
                        # If the identity's trust status has previously been inherited from an ancestor, check its
                        # current trust status against that of ``parent`` and use whichever is considered less trusted
                        new_status = IdentityTrust.select_least_trusted(identity, parent_identity).status

                        # Only update the identity's trust status and "inherited_from" property if this results in a
                        # status different from what was set previously
                        if new_status != identity.trust.status:
                            identity.trust.status = new_status
                            identity.trust.inherited_from = parent

                    # Communicate that the identity's trust status was reached by way of inheritance
                    identity.trust.method = "inheritance"

        # Call the method again on each of the children and build a list from the return values
        children = [self._build_binding_tree(child) for child in children]

        return (parent, children)

    def _build_binding_trees(self):
        """Finds all root identities (identities which are not bound to any parent identity), builds an inheritance
        tree for each (see the singular version of this method: ``self._build_binding_tree(...)``), and updates the
        ``binding_trees`` virtual field to reflect the result.
        """
        trees = []

        for identity in self.identities:
            # If the identity has no bindings, this means it has no parent identities and is therefore a root identity
            if identity.name and len(identity.bindings) == 0:
                trees.append(self._build_binding_tree(identity.name))

        self.change("binding_trees", trees)

    def _categorise_identities(self):
        root_identities = []
        unbound_identities = []

        if self.binding_trees:
            for tree in self.binding_trees:
                match tree:
                    case (parent, []):
                        unbound_identities.append(parent)
                    case (parent, _):
                        root_identities.append(parent)
                    case _:
                        continue

        self.root_identities = root_identities
        self.unbound_identities = unbound_identities

    def _set_platform_identified_flag(self):
        flag = False

        for identity in self.identities:
            if identity.values.get("class") == "identifier" and identity.trust.status == "trusted":
                flag = True
                break

        self.platform_identified = flag

    def finalise(self):
        for identity in self.identities:
            identity.finalise()

        self._build_binding_trees()
        self._categorise_identities()
        self._set_platform_identified_flag()
