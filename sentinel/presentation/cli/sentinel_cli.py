"""
SENTINEL™ CLI

Command-line interface for SENTINEL™ security operations.
"""

from __future__ import annotations

import asyncio

import click


@click.group()
@click.version_option(version="1.0.0", prog_name="SENTINEL™")
def main():
    """SENTINEL™ — Agentic Security Platform.

    Your agents have no security team. Until now.
    """


@main.command()
@click.option("--host", default="0.0.0.0", help="Bind host")
@click.option("--port", default=8000, help="Bind port")
def serve(host: str, port: int):
    """Start the SENTINEL™ API server."""
    import uvicorn

    uvicorn.run(
        "sentinel.presentation.api.app:app",
        host=host,
        port=port,
        reload=False,
    )


@main.command()
def status():
    """Show current SENTINEL™ threat posture."""
    from sentinel.infrastructure.config.dependency_injection import create_container

    async def _status():
        container = create_container()
        agents = await container.agent_repo.get_all()
        threats = await container.threat_repo.get_open_threats()
        incidents = await container.incident_repo.get_active_incidents()

        click.echo("SENTINEL™ Status")
        click.echo("=" * 40)
        click.echo(f"Monitored Agents:  {len(agents)}")
        click.echo(f"Open Threats:      {len(threats)}")
        click.echo(f"Active Incidents:  {len(incidents)}")

        if threats:
            click.echo("\nOpen Threats:")
            for t in threats:
                click.echo(f"  [{t.level.value}] {t.category.value} — agent={t.agent_id} score={t.score.value}")

    asyncio.run(_status())


@main.command()
def scan():
    """Run RECON attack surface scan."""
    from sentinel.infrastructure.config.dependency_injection import create_container

    async def _scan():
        container = create_container()
        agents = await container.discover_agents.execute()
        click.echo(f"Discovered {len(agents['agents'])} agents")

        permissions = await container.audit_permissions.execute()
        click.echo(f"Attack Surface Score: {permissions['attack_surface_score']}")

        if permissions.get("over_privileged_agents"):
            click.echo("\nOver-privileged Agents:")
            for agent in permissions["over_privileged_agents"]:
                click.echo(f"  - {agent['id']}: {agent['tool_count']} tools")

    asyncio.run(_scan())


@main.command()
@click.argument("agent_id")
@click.argument("reason")
def isolate(agent_id: str, reason: str):
    """Isolate an agent by VAID."""
    from sentinel.infrastructure.config.dependency_injection import create_container

    async def _isolate():
        container = create_container()
        result = await container.isolate_agent.execute(
            agent_id=agent_id,
            reason=reason,
        )
        if result.get("success"):
            click.echo(f"Agent {agent_id} isolated: {reason}")
        else:
            click.echo(f"Failed to isolate agent: {result.get('error')}")

    asyncio.run(_isolate())


if __name__ == "__main__":
    main()
