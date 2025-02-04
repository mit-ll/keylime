from keylime import keylime_logging
from keylime.models import RegistrarAgent
from keylime.web.base import Controller

logger = keylime_logging.init_logging("registrar")


class AgentsController(Controller):
    # GET /v2[.:minor]/agents/
    def index(self, **_params):
        results = RegistrarAgent.all_ids()

        self.respond(200, "Success", {"uuids": results})

    # GET /v2[.:minor]/agents/:agent_id/
    def show(self, agent_id, **_params):
        agent = RegistrarAgent.get(agent_id)

        if not agent:
            self.respond(404, f"Agent with ID '{agent_id}' not found")
            return

        if not agent.active:
            self.respond(404, f"Agent with ID '{agent_id}' has not been activated")
            return

        self.respond(200, "Success", agent.render())

    # POST /v2[.:minor]/agents/[:agent_id]
    async def create(self, agent_id, **params):
        agent = RegistrarAgent.get(agent_id) or RegistrarAgent.empty()  # type: ignore[no-untyped-call]
        agent.update({"agent_id": agent_id, **params})
        challenge = agent.produce_ak_challenge()

        if not challenge or not agent.changes_valid:
            self.log_model_errors(agent, logger)
            self.respond(400, "Could not register agent with invalid data")
            return

        await agent.notify_webhooks()

        agent.commit_changes()
        self.respond(200, "Success", {"blob": challenge})

    # DELETE /v2[.:minor]/agents/:agent_id/
    def delete(self, agent_id, **_params):
        agent = RegistrarAgent.get(agent_id)

        if not agent:
            self.respond(404, f"Agent with ID '{agent_id}' not found")
            return

        agent.delete()
        self.respond(200, "Success")

    # POST /v2[.:minor]/agents/:agent_id/[activate]
    async def activate(self, agent_id, auth_tag, **_params):
        agent = RegistrarAgent.get(agent_id)

        if not agent:
            self.respond(404, f"Agent with ID '{agent_id}' not found")
            return

        accepted = agent.verify_ak_response(auth_tag)

        await agent.notify_webhooks()

        if accepted:
            agent.commit_changes()
            self.respond(200, "Success")
        else:
            agent.delete()

            self.respond(
                400,
                f"Auth tag '{auth_tag}' for agent '{agent_id}' does not match expected value. The agent has been "
                f"deleted from the database and will need to be restarted to reattempt registration",
            )
