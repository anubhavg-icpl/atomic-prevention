from datetime import datetime, timedelta, timezone
import json

from agent.atomic_prevention_runner import (
    _get_verdict,
    _uec_detection_techniques,
    _uec_technique_matches,
)
from backend.app.services.log_sanitizer import redact_text, sanitize_log_items
from backend.app.services.uec_correlation import _finding_time, _technique_matches


def test_detection_indicator_without_block_is_detected():
    verdict, reason = _get_verdict(
        process_started=True,
        exit_code=0,
        timed_out=False,
        stderr_text="",
        stdout_text="EDR detected suspicious behaviour",
        error_message=None,
        plat="linux",
    )
    assert verdict == "detected"
    assert "detected" in reason


def test_block_indicator_takes_precedence_over_detection():
    verdict, _ = _get_verdict(
        process_started=True,
        exit_code=1,
        timed_out=False,
        stderr_text="blocked by policy and detected",
        stdout_text="",
        error_message=None,
        plat="linux",
    )
    assert verdict == "blocked"


def test_log_redaction_removes_credentials_and_bounds_output():
    dirty = "password=hunter2 api_key=abc123 Authorization: Bearer secret"
    clean = redact_text(dirty, char_limit=1000)
    assert "hunter2" not in clean
    assert "abc123" not in clean
    assert "secret" not in clean
    assert redact_text("x" * 30, char_limit=10).endswith("...[truncated]")


def test_nested_log_entries_are_bounded():
    values = [{"nested": {"token": "super-secret", "text": "safe"}} for _ in range(20)]
    cleaned = sanitize_log_items(values, max_entries=2, max_total_chars=500)
    assert len(cleaned) == 2
    assert "super-secret" not in str(cleaned)


def test_uec_parent_technique_matches_sub_technique():
    assert _technique_matches("T1059.004", ["T1059"])
    assert _technique_matches("T1059", ["T1059.004"])
    assert not _technique_matches("T1059.004", ["T1218"])


def test_agent_local_uec_technique_match_is_conservative():
    payload = json.dumps({"techniques": ["T1059"], "ruleUid": "fixture"})
    assert _uec_detection_techniques(payload) == ["T1059"]
    assert _uec_technique_matches("T1059.004", _uec_detection_techniques(payload))
    assert not _uec_technique_matches("T1218.011", _uec_detection_techniques(payload))


def test_finding_time_is_timezone_aware():
    value = _finding_time({"occurredAt": "2026-10-27T12:25:00Z"})
    assert value is not None
    assert value.tzinfo is not None
    assert abs(value - datetime(2026, 10, 27, 12, 25, tzinfo=timezone.utc)) < timedelta(seconds=1)


def test_uec_db_permission_denied_degrades_instead_of_crashing(monkeypatch):
    """Reproduces the exact traceback seen on a real host: /var/lib/uec-sensor/ is root:root
    0700, so a non-root agent's Path.is_file() raises PermissionError BEFORE reaching the
    sqlite3.connect() that is already try/except-guarded. That must degrade, not crash
    run_playbook before results are uploaded."""
    import pathlib
    from agent import atomic_prevention_runner as runner

    def raise_eacces(self):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(pathlib.Path, "is_file", raise_eacces)
    result = runner._correlate_uec_findings(
        [{"verdict": "allowed", "started_at": "2026-01-01T00:00:00Z", "finish_time": "2026-01-01T00:00:01Z"}],
        "linux",
    )
    assert result["available"] is False
    assert "permission" in result["reason"].lower()
