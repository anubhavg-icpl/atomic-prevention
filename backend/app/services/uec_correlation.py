"""Correlate completed Atomic Prevention tests with authoritative UEC findings."""

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.models.playbook import PlaybookRun
from backend.app.models.result import TestResult
from backend.app.models.test_case import PreventionTest
from backend.app.services.uec_client import UecClient


async def correlate_run(db: AsyncSession, run_id: str) -> dict[str, Any] | None:
    """Promote only ``allowed`` results to ``detected`` on a UEC finding match.

    Matching uses the strongest available identity: device, execution interval,
    and ATT&CK parent/sub-technique. Generic event tokens are intentionally not
    used because they produce false positives on busy hosts.
    """
    if not settings.uec_enabled or not settings.uec_correlation_enabled:
        return None

    run = await db.get(PlaybookRun, run_id)
    if not run:
        return None
    client = UecClient()
    if not client.configured:
        run.uec_match_status = "not_configured"
        await db.commit()
        return None

    rows = (
        await db.execute(
            select(TestResult, PreventionTest)
            .outerjoin(PreventionTest, TestResult.test_id == PreventionTest.id)
            .where(TestResult.run_id == run_id)
        )
    ).all()

    try:
        device = await client.find_device(run.hostname)
        if not device:
            run.uec_match_status = "device_not_found"
            await db.commit()
            return None

        device_id = str(device.get("id") or device.get("deviceId") or "")
        run.uec_device_id = device_id
        page = await client.threat_findings(
            device_id=device_id,
            days=1,
            limit=200,
            started_at=run.started_at,
            completed_at=run.completed_at,
        )
    except Exception as exc:
        run.uec_match_status = "error"
        _append_run_log(
            run,
            "warning",
            "uec_match",
            f"UEC correlation failed without exposing credentials: {type(exc).__name__}",
        )
        await db.commit()
        return None

    findings = page.get("items", [])
    grace = timedelta(seconds=max(0, settings.uec_match_grace_seconds))
    run_start = _utc(run.started_at or _min_start(rows))
    run_end = _utc(run.completed_at or datetime.now(timezone.utc))
    findings = [
        finding for finding in findings
        if _in_interval(_finding_time(finding), run_start - grace, run_end + grace)
    ]

    changed = False
    for result, test in rows:
        if result.verdict != "allowed":
            result.uec_match_status = "not_candidate"
            continue

        technique = test.technique_id if test else ""
        start = _utc(result.executed_at or run_start)
        end = _utc(result.execution_completed_at or start + timedelta(milliseconds=result.execution_time_ms or 0))
        candidates = [
            finding for finding in findings
            if _in_interval(_finding_time(finding), start - grace, end + grace)
            and _technique_matches(technique, _finding_techniques(finding))
        ]
        ambiguous = _is_ambiguous(candidates, start, end, rows)
        if not candidates:
            result.uec_match_status = "no_match"
            continue
        if ambiguous:
            result.uec_match_status = "ambiguous"
            result.uec_matches = candidates[:10]
            continue

        result.verdict = "detected"
        result.uec_match_status = "matched"
        result.uec_matches = candidates[:10]
        result.agent_logs = list(result.agent_logs or []) + [{
            "source": "uec-api",
            "level": "info",
            "phase": "uec_match",
            "message": "UEC threat finding matched this execution interval and ATT&CK technique.",
            "findings": candidates[:10],
        }]
        changed = True

    counts = {"blocked": 0, "detected": 0, "allowed": 0, "error": 0}
    for result, _test in rows:
        if result.verdict in counts:
            counts[result.verdict] += 1
    run.summary = counts
    run.uec_match_status = "matched" if changed else ("no_match" if findings else "no_findings")
    _append_run_log(
        run,
        "info" if changed else "debug",
        "uec_match",
        f"UEC correlation status: {run.uec_match_status}; findings in run window: {len(findings)}",
    )
    await db.commit()
    return counts


def _append_run_log(run: PlaybookRun, level: str, phase: str, message: str) -> None:
    logs = list(run.debug_logs or [])
    logs.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "source": "uec-api",
        "phase": phase,
        "message": message,
    })
    run.debug_logs = logs[-500:]


def _finding_time(finding: dict[str, Any]) -> datetime | None:
    value = finding.get("timeGenerated") or finding.get("occurredAt") or finding.get("timestamp")
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return _utc(parsed)
    except (TypeError, ValueError):
        return None


def _finding_techniques(finding: dict[str, Any]) -> list[str]:
    values = finding.get("techniques")
    if isinstance(values, list):
        return [str(value).upper() for value in values if value]
    value = finding.get("technique")
    return [str(value).upper()] if value else []


def _technique_matches(expected: str, actual: list[str]) -> bool:
    if not expected or not actual:
        return False
    expected = expected.upper()
    parent = expected.split(".", 1)[0]
    return any(value == expected or value.split(".", 1)[0] == parent for value in actual)


def _in_interval(value: datetime | None, start: datetime, end: datetime) -> bool:
    return value is not None and start <= value <= end


def _is_ambiguous(
    candidates: list[dict[str, Any]], start: datetime, end: datetime, rows: list[Any]
) -> bool:
    """Flag overlapping same-technique tests when one finding could belong to either."""
    if len(candidates) != 1:
        return False
    finding_time = _finding_time(candidates[0])
    if finding_time is None:
        return True
    for result, test in rows:
        if result.verdict != "allowed" or not test:
            continue
        other_start = _utc(result.executed_at or start)
        other_end = _utc(
            result.execution_completed_at
            or other_start + timedelta(milliseconds=result.execution_time_ms or 0)
        )
        if other_start <= finding_time <= other_end and (other_start, other_end) != (start, end):
            return True
    return False


def _min_start(rows: list[Any]) -> datetime:
    values = [result.executed_at for result, _test in rows if result.executed_at]
    return min(values, default=datetime.now(timezone.utc))


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
