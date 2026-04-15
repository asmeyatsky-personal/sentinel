"""Tests for Incident entity — pure domain tests, no mocks."""

from __future__ import annotations

from sentinel.domain.entities.incident import (
    Incident,
    IncidentContainedEvent,
    IncidentStatus,
    ResponseAction,
)
from sentinel.domain.value_objects.threat_level import ThreatLevel


def _make_incident(**overrides) -> Incident:
    defaults = {
        "id": "incident-1",
        "threat_ids": ("threat-1",),
        "affected_agent_ids": ("agent-1",),
        "severity": ThreatLevel.HIGH,
    }
    defaults.update(overrides)
    return Incident(**defaults)


class TestIncident:
    def test_create_incident(self):
        incident = _make_incident()
        assert incident.status is IncidentStatus.DETECTED
        assert incident.contained_at is None

    def test_add_response_action(self):
        incident = _make_incident()
        updated = incident.add_response_action(ResponseAction.AGENT_ISOLATED)
        assert ResponseAction.AGENT_ISOLATED in updated.actions_taken
        assert updated.status is IncidentStatus.CONTAINING
        assert incident.status is IncidentStatus.DETECTED

    def test_mark_contained(self):
        incident = _make_incident()
        incident = incident.add_response_action(ResponseAction.AGENT_ISOLATED)
        contained = incident.mark_contained()
        assert contained.status is IncidentStatus.CONTAINED
        assert contained.contained_at is not None

    def test_mark_contained_emits_event(self):
        incident = _make_incident()
        incident = incident.add_response_action(ResponseAction.TOOL_BLOCKED)
        contained = incident.mark_contained()
        assert len(contained.domain_events) == 1
        event = contained.domain_events[0]
        assert isinstance(event, IncidentContainedEvent)
        assert "TOOL_BLOCKED" in event.actions_taken

    def test_resolve(self):
        incident = _make_incident()
        resolved = incident.resolve()
        assert resolved.status is IncidentStatus.RESOLVED
        assert resolved.resolved_at is not None

    def test_expand_blast_radius(self):
        incident = _make_incident()
        expanded = incident.expand_blast_radius(("agent-2", "agent-3"))
        assert "agent-2" in expanded.blast_radius_agent_ids
        assert "agent-3" in expanded.blast_radius_agent_ids

    def test_expand_blast_radius_no_duplicates(self):
        incident = _make_incident()
        expanded = incident.expand_blast_radius(("agent-2",))
        expanded2 = expanded.expand_blast_radius(("agent-2", "agent-3"))
        assert expanded2.blast_radius_agent_ids.count("agent-2") == 1

    def test_mttc(self):
        incident = _make_incident()
        assert incident.mean_time_to_contain_seconds is None
        contained = incident.mark_contained()
        assert contained.mean_time_to_contain_seconds is not None
        assert contained.mean_time_to_contain_seconds >= 0
