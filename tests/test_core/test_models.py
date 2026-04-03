"""Tests for core models."""
from arcanum.core.models import Mode, Status, Severity, StashType


def test_mode_enum():
    assert Mode.AUTOPILOT.value == "autopilot"
    assert Mode.COPILOT.value == "copilot"
    assert Mode.MANUAL.value == "manual"


def test_severity_enum():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFO.value == "info"


def test_stash_type_enum():
    assert StashType.CREDENTIAL.value == "credential"
    assert StashType.HOST.value == "host"
    assert StashType.PAYLOAD.value == "payload"


def test_status_enum():
    assert Status.CREATED.value == "created"
    assert Status.RUNNING.value == "running"
    assert Status.COMPLETE.value == "complete"
