from keylime import keylime_logging
from keylime.models.base import Timestamp
from keylime.models.verifier import VerifierAgent, PushAttestation
from keylime.web.base import Controller

logger = keylime_logging.init_logging("verifier")


class PushAttestationController(Controller):
    """The PushAttestationController services requests for the management of attestation resources when the verifier is
    operating in push mode. Such attestation resources are represented by instances of the ``PushAttestation`` model.

    Attestation evidence is prepared and sent according the push attestation protocol which operates in two phases::

                          Agent                                           Verifier
                          -----                                           --------
                            │                                                 │
                        ┬   │                 1. Capabilities                 █─────────────────┐
                        │   │ ----------------------------------------------> █                 │
             1st Phase: │   │         i.e., supported TPM algorithms          █   Attestation   │
           ------------ │   │                                                 █    resource     │
           CAPABILITIES │   │                                                 █     created     │
            NEGOTIATION │   │            2. Attestation Parameters            █                 │
                        │   │ <---------------------------------------------- █        │        │
                        ┴   │    i.e., ima offset, chosen algorithms, etc.    █────────│────────┘
                            │                                                 │        │
                            │                                                 │        │
                        ┬   │                   3. Evidence                   █────────│────────┐
                        │   │ ----------------------------------------------> █        🡓        │
             2nd Phase: │   │       i.e., quote, UEFI log, IMA log, etc.      █   Attestation   │
             ---------- │   │                                                 █    resource     │
               EVIDENCE │   │                                                 █     updated     │
               HANDLING │   │                   4. Response                   █                 │
                        │   │ <---------------------------------------------- █                 │
                        ┴   │  i.e., whether the request appears well-formed  █─────────────────┘
                            │                                                 │


    Identifying Attestation Resources
    ---------------------------------

    Each attestation resource is scoped to an agent and is identified by an auto-incrementing index (starting from 0).
    While this index may be used to reference a particular attestation, most often it is the latest attestation which is
    relevant. Routes are therefore provided (in ``keylime.web.verifier_server``) to GET and PATCH the latest attestation
    resource. Requests which match these routes are handled by the ``show_latest`` and ``update_latest`` actions
    respectively.

    The following paths may therefore refer to the same attestation resource if a total of five (5) attestations exist
    for agent 1:
    
        * /v3/agents/1/attestations/4
        * /v3/agents/1/attestations/latest

    Lifetime of an Attestation Resource
    -----------------------------------

    Even though every attestation resource is uniquely identifiable by an ``(agent_id, index)`` tuple, attestation
    resources are not accessible indefinitely forever. This is because old attestations records are automatically
    cleared to limit the storage requirements of the database.

    Generally, the latest attestation and any attestations which fail verification are always retained. The specifics
    are documented in `keylime.models.verifier.push_attestation`.

    Creating Attestation Resources
    ------------------------------
    
    An attestation resource is only creatable under certain conditions to enforce correct behaviour of untrusted agents
    which may make requests to the verifier at will.

    A request to create a new attestation resource may fail for any of the following reasons:

        * the agent does not exist (404 "Not Found");
        * attestations are disabled for the agent, e.g., if a previous verification failed (403 "Forbidden");
        * the request has been received too soon after evidence was received for the previous attestation (429 "Too Many
          Requests");
        * verification of a previous attestation is still in progress (503 "Service Unavailable");
        * the request data was not as expected (400 "Bad Request"); or
        * the request was received while another request to create an attestation resource was still being processed
          (409 "Conflict").

    In all cases other than the first two, the request may be re-attempted. When a 429 or 503 status is returned, the
    ``Retry-After`` HTTP header indicates the number of seconds after which the request will be accepted.

    Details about each error condition can be found by inspecting the ``errors`` structure in the JSON response.
    
    Mutating Attestation Resources
    ------------------------------
    
    Any given attestation resource may only be updated once after creation to supply the evidence for the attestation.
    At this point, assuming the received evidence is in the expected format, the resource becomes immutable for the
    remainder of its lifetime.

    A request to update an attestation resource may fail for any of the following reasons:

        * the attestation resource never existed (404 "Not Found");
        * the attestation resource no longer exists (410 "Gone");
        * the attestation resource has already been updated with the expected evidence (403 "Forbidden");
        * the nonce for the attestation resource has expired (403 "Forbidden");
        * the evidence provided was not as expected (400 "Bad Request"); or
        * too many worker processes are currently occupied by a verification task (503 "Service Unavailable").

    In the final two cases, the request may be re-attempted. When a 503 status is returned, the ``Retry-After`` HTTP
    header indicates the estimated number of seconds after which the verifier will accept the evidence.
    
    In all other cases, a new attestation resource must first be created before the verifier will accept evidence from
    that specific agent.

    Details about each error condition can be found by inspecting the ``errors`` structure in the JSON response.

    Performance Considerations
    --------------------------

    In general, the cooperative multitasking of the underlying web framework ensures that long-running I/O tasks do
    not block a worker process from handling other requests in the interim. However, because verification is largely a
    CPU-bound task, when a worker is busy processing a verification, that process is blocked until the task is complete.
    A number of mechanisms have been implemented to limit this impact, some of which are user-configurable:

        * To prevent the verifier from being overloaded with constant attestations from an individual agent, creation of
          a new attestation is not allowed until a certain amount of time has passed since evidence was received for the
          agent's previous attestation. This is determined by the ``quote_interval`` config option which is also used to
          determine the ``next_attestation_expected_after`` ISO datetime returned to the agent when valid evidence is
          received. The user should set ``quote_interval`` based on their desired attestation frequency.

        * To prevent attestations from taking so long as to exhaust the verifier's resources, e.g., if an agent, perhaps
          maliciously, sends an excessive amount of data as evidence, the verifier will give up trying to verify an 
          attestation after a certain cut off is reached. This is determined by the ``verification_timeout`` config
          option. When set to 0 (the default), verifications will time out after m*3 seconds where m is the average time
          taken to process attestations since the verifier was started. When a value > 0 is given, this is interpreted
          as a fixed timeout in seconds.

        * To allow the verifier to respond to requests even when many attestations are received all at once, a number of
          worker processes are kept free for request handling and will not perform verification tasks. This number is
          usually determined by the formula floor(n*r) where n is the total number of workers and r is the percentage
          which will dedicated to servicing incoming requests. When the formula returns <1, a single dedicated worker is
          used. But when n equals one, a warning is produced as no process can be dedicated. The value of r is 25% by
          default but may be overriden by setting the ``dedicated_web_workers`` config value to a different percentage.
          Alternatively, a fixed number may be provided instead.

    Additionally:

        * Regardless of how long a verification task takes, it will not block the verifier from issuing its response to
          the agent which submitted the evidence.

        * When an agent submits evidence but all the worker processes which are not dedicated to request handling are
          occupied by a verification task, the verifier will instruct the agent to wait a certain amount of time before
          retrying. This value is determined by the formula n*m where n is a count of the requests which the verifier 
          has had to reject for this reason (including the current request) and m is the average number of seconds the
          verifier has taken to complete each verification task since starting. The value n is reset to 0 when enough
          workers become available to service more verification tasks.
    """

    # GET /v3[.:minor]/agents/:agent_id/attestations
    def index(self, agent_id, **_params):
        results = PushAttestation.all(agent_id=agent_id)

        self.respond(200, "Success", [attestation.render() for attestation in results])

    # GET /v3[.:minor]/agents/:agent_id/attestations/:index
    def show(self, agent_id, index, **_params):
        attestation = PushAttestation.get(agent_id=agent_id, index=index)

        if not attestation:
            self.respond(404, f"Agent with ID '{agent_id}' not found")
            return

        self.respond(200, "Success", attestation.render())

    # GET /v3[.:minor]/agents/:agent_id/attestations/latest
    def show_latest(self, agent_id, **_params):
        last_attestation = PushAttestation.get_latest(agent_id)

        if not last_attestation:
            self.respond(404, f"Agent with ID '{agent_id}' not found")
            return

        self.respond(200, "Success", last_attestation.render())

    # POST /v3[.:minor]/agents/:agent_id/attestations
    def create(self, agent_id, **params):
        agent = VerifierAgent.get(agent_id)

        if not agent:
            self.respond(404)
            return

        if agent.accept_attestations is False:
            self.respond(403)
            return

        retry_seconds = PushAttestation.accept_new_attestations_in(agent_id)

        # Reject request if a new attestation is not yet expected (due to quote_interval or an active verification task)
        if retry_seconds:
            self.action_handler.set_header("Retry-After", retry_seconds)
            self.respond(429)
            return

        new_attestation = PushAttestation.create(agent_id, agent, params)

        if new_attestation.errors:
            msgs = []
            for field, errors in new_attestation.errors.items():
                for error in errors:
                    msgs.append(f"{field} {error}")
            self.respond(400, "Bad Request", {"errors": msgs})
            return

        try:
            new_attestation.commit_changes()
        except ValueError:
            # Another attestation for this agent was created while this request is being processed. Reject the request
            # as otherwise the new attestation may be created prior to or shortly after evidence is received and
            # processed for the other attestation, meaning that the configured quote interval would not be respected
            self.respond(409)
            return

        # The attestation was created successfully, so delete any previous attestation for which evidence was never
        # received or for which verification never completed
        new_attestation.cleanup_stale_priors()

        response = new_attestation.render(
            [
                "agent_id",
                "nonce",
                "nonce_created_at",
                "nonce_expires_at",
                "status",
                "hash_alg",
                "enc_alg",
                "sign_alg",
                "starting_ima_offset",
            ]
        )
        response = {**response, "pcr_mask": agent.tpm_policy}
        self.respond(200, "Success", response)

    # PATCH /v3[.:minor]/agents/:agent_id/attestations/:index
    def update(self, agent_id, index, **params):
        latest_attestation = PushAttestation.get_latest(agent_id)

        # Only allow the attestation at 'index' to be updated if it is the latest attestation
        if latest_attestation.index == index:
            self.update_latest(agent_id, **params)
        else:
            self.respond(403)

    # PATCH /v3[.:minor]/agents/:agent_id/attestations/latest
    def update_latest(self, agent_id, **params):
        agent = VerifierAgent.get(agent_id)

        # get last attestation entry for the agent
        attestation = PushAttestation.get_latest(agent_id)

        if not attestation:
            self.respond(404)
            return

        if attestation.status != "waiting":
            self.respond(403)
            return

        if attestation.nonce_expires_at < Timestamp.now():
            self.respond(403)
            return

        attestation.receive_evidence(params)

        # last_attestation will contain errors if the JSON request is malformed/invalid (e.g., if an unrecognised hash
        # algorithm is provided) but not if the quote verification fails (including if the quote cannot be verified as
        # authentic, if the IMA/MB logs cannot be verified as authentic, or if the logs do not meet policy)
        if not attestation.changes_valid:
            msgs = []
            for field, errors in attestation.errors.items():
                for error in errors:
                    msgs.append(f"{field} {error}")
            self.respond(400, "Bad Request", {"errors": msgs})
            return

        attestation.commit_changes()
        time_to_next_attestation = attestation.next_attestation_expected_after - Timestamp.now()
        response = {"time_to_next_attestation": int(time_to_next_attestation.total_seconds())}
        self.respond(200, "Success", response)

        # Verify attestation after response is sent, so that the agent does not need to wait for the verification to
        # complete. Ideally, in the future, we would want to create a pool of verification worker processes
        # (separate from the web server workers) which will call this method whenever a new verification task is added
        # to a queue
        attestation.verify_evidence()


