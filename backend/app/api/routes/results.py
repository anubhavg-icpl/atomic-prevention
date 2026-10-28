import json
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, File, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.db.database import get_db
from backend.app.models.playbook import PlaybookRun
from backend.app.models.result import TestResult
from backend.app.models.test_case import PreventionTest
from backend.app.services.log_sanitizer import redact_text, sanitize_log_item, sanitize_log_items
from backend.app.services.uec_correlation import correlate_run

router = APIRouter()
VERDICTS = ("blocked", "detected", "allowed", "error")


def _bounded_text(value: Any, limit: int = 16_000) -> str | None:
    return redact_text(value, limit)


def _bounded_logs(value: Any, limit: int = 500) -> list[dict[str, Any]]:
    return sanitize_log_items(value, max_entries=limit)


def _first(*values: Any) -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return None


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


class TestResultInput(BaseModel):
    test_id: str
    technique_id: str = ""
    test_name: str = ""
    source: str = "external-agent"
    command: str = ""
    executor: str = ""
    verdict: str  # blocked | detected | allowed | error
    exit_code: int | None = None
    error_message: str | None = None
    execution_time_ms: int = 0
    executed_at: datetime | None = None
    completed_at: datetime | None = None
    stdout: str | None = None
    stderr: str | None = None
    agent_logs: list[dict[str, Any]] = []


async def _ensure_external_tests(db, results: list[TestResultInput]) -> None:
    """Create catalog rows for external runner tests not exported from this server."""
    from backend.app.models.technique import Technique

    existing_ids = {
        row.id
        for row in (
            await db.execute(select(PreventionTest.id).where(PreventionTest.id.in_([r.test_id for r in results])))
        ).all()
    }
    for result in results:
        if not result.technique_id or result.test_id in existing_ids:
            continue
        if not await db.get(Technique, result.technique_id):
            db.add(Technique(
                id=result.technique_id,
                name=result.technique_id,
                sources=[result.source],
            ))
        db.add(PreventionTest(
            id=result.test_id,
            technique_id=result.technique_id,
            source=result.source,
            name=result.test_name or result.test_id,
            description="Imported from an external QA runner",
            command=redact_text(result.command, 16_000) or "",
            executor=result.executor or "manual",
            platforms=[],
            metadata_={"external": True},
        ))
        existing_ids.add(result.test_id)


class SubmitResultsRequest(BaseModel):
    playbook_id: str
    hostname: str = ""
    started_at: datetime | None = None
    completed_at: datetime | None = None
    results: list[TestResultInput]
    platform: str = ""
    os_version: str = ""
    agent_name: str = ""
    agent_version: str = ""
    sensor_logs: list[dict[str, Any]] = []
    debug_logs: list[dict[str, Any]] = []
    performance: dict[str, Any] = {}


@router.post("/submit")
async def submit_results(
    request: SubmitResultsRequest,
    db: AsyncSession = Depends(get_db),
):
    run_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    run_started = request.started_at or min(
        (r.executed_at for r in request.results if r.executed_at), default=now
    )
    run_completed = request.completed_at or max(
        (r.completed_at for r in request.results if r.completed_at),
        default=max((r.executed_at for r in request.results if r.executed_at), default=now),
    )

    summary = {"blocked": 0, "detected": 0, "allowed": 0, "error": 0}

    run = PlaybookRun(
        id=run_id,
        playbook_id=request.playbook_id,
        hostname=request.hostname,
        started_at=run_started,
        completed_at=run_completed,
        platform=request.platform,
        os_version=request.os_version,
        agent_name=request.agent_name,
        agent_version=request.agent_version,
        sensor_logs=_bounded_logs(request.sensor_logs),
        debug_logs=_bounded_logs(request.debug_logs),
        performance=sanitize_log_item(request.performance),
    )
    db.add(run)
    await _ensure_external_tests(db, request.results)

    for r in request.results:
        verdict = r.verdict if r.verdict in VERDICTS else "error"
        summary[verdict] = summary.get(verdict, 0) + 1

        result = TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            test_id=r.test_id,
            verdict=verdict,
            exit_code=r.exit_code,
            error_message=r.error_message,
            execution_time_ms=r.execution_time_ms,
            executed_at=r.executed_at or now,
            execution_completed_at=r.completed_at,
            stdout=_bounded_text(r.stdout),
            stderr=_bounded_text(r.stderr),
            agent_logs=_bounded_logs(r.agent_logs),
        )
        db.add(result)

    run.summary = summary
    await db.commit()
    summary = await correlate_run(db, run_id) or summary

    return {"run_id": run_id, "summary": summary}


MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB


@router.post("/upload")
async def upload_results_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """Upload a results JSON file from the PowerShell agent (offline mode).

    Accepts the JSON file that Invoke-AtomicPrevention saves to disk, parses it,
    and stores the results in the database just like the /submit endpoint.
    """
    if file.size and file.size > MAX_UPLOAD_SIZE:
        return JSONResponse(status_code=413, content={"error": "File too large. Max 10MB."})

    try:
        content = await file.read()
        if len(content) > MAX_UPLOAD_SIZE:
            return JSONResponse(status_code=413, content={"error": "File too large. Max 10MB."})
        data = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JSONResponse(
            status_code=400,
            content={"error": "Invalid JSON file"},
        )

    # Validate structure - the PS agent outputs this format
    playbook_info = data.get("playbook", {})
    results_list = data.get("results", [])
    hostname = data.get("hostname", "")
    run_timestamp = data.get("run_timestamp", "")
    platform = _first(data.get("platform"), data.get("Platform")) or ""
    os_version = _first(data.get("os_version"), data.get("OsVersion")) or ""
    agent_name = _first(data.get("agent_name"), data.get("AgentName")) or ""
    agent_version = _first(data.get("agent_version"), data.get("AgentVersion")) or ""
    sensor_logs = data.get("sensor_logs") or data.get("SensorLogs") or []
    debug_logs = data.get("debug_logs") or data.get("DebugLogs") or []
    performance = _first(data.get("performance"), data.get("Performance")) or {}
    submitted_started = _parse_datetime(_first(data.get("started_at"), data.get("StartedAt")))
    submitted_completed = _parse_datetime(_first(data.get("completed_at"), data.get("CompletedAt")))

    if not results_list:
        return JSONResponse(
            status_code=400,
            content={"error": "No results found in uploaded file"},
        )

    run_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    # Parse timestamp from file if available
    started_at = now
    if run_timestamp:
        try:
            started_at = datetime.fromisoformat(run_timestamp.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            started_at = now

    summary = {"blocked": 0, "detected": 0, "allowed": 0, "error": 0}

    run = PlaybookRun(
        id=run_id,
        playbook_id=playbook_info.get("id", f"uploaded-{run_id[:8]}"),
        hostname=hostname,
        started_at=submitted_started or started_at,
        completed_at=submitted_completed or now,
        platform=platform,
        os_version=os_version,
        agent_name=agent_name,
        agent_version=agent_version,
        sensor_logs=_bounded_logs(sensor_logs),
        debug_logs=_bounded_logs(debug_logs),
        performance=sanitize_log_item(performance),
    )
    db.add(run)

    external_results: list[TestResultInput] = []
    for r in results_list:
        external_results.append(TestResultInput(
            test_id=r.get("TestId") or r.get("test_id") or str(uuid.uuid4()),
            technique_id=_first(r.get("technique_id"), r.get("TechniqueId")) or "",
            test_name=_first(r.get("test_name"), r.get("TestName"), r.get("name")) or "",
            source=_first(r.get("source"), r.get("Source")) or "external-agent",
            command=_first(r.get("command"), r.get("Command")) or "",
            executor=_first(r.get("executor"), r.get("Executor")) or "",
        ))
    await _ensure_external_tests(db, external_results)

    for r in results_list:
        # Handle both dict and object-style keys from PowerShell JSON
        test_id = r.get("TestId") or r.get("test_id", str(uuid.uuid4()))
        verdict_raw = r.get("Verdict") or r.get("verdict", "error")
        verdict = verdict_raw if verdict_raw in VERDICTS else "error"
        exit_code = r.get("ExitCode") or r.get("exit_code")
        error_msg = r.get("ErrorMessage") or r.get("error_message")
        exec_time = r.get("ExecutionTimeMs") or r.get("execution_time_ms", 0)
        executed_at = _parse_datetime(_first(r.get("executed_at"), r.get("ExecutedAt")))
        completed_at = _parse_datetime(_first(r.get("completed_at"), r.get("CompletedAt")))
        stdout = _bounded_text(_first(r.get("stdout"), r.get("StdOut")))
        stderr = _bounded_text(_first(r.get("stderr"), r.get("StdErr")))
        agent_logs = _bounded_logs(_first(r.get("agent_logs"), r.get("AgentLogs")) or [])

        # Skip "skipped" results
        if verdict_raw == "skipped":
            continue

        summary[verdict] = summary.get(verdict, 0) + 1

        result = TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            test_id=test_id,
            verdict=verdict,
            exit_code=exit_code,
            error_message=error_msg,
            execution_time_ms=exec_time or 0,
            executed_at=executed_at or started_at,
            execution_completed_at=completed_at,
            stdout=stdout,
            stderr=stderr,
            agent_logs=agent_logs,
        )
        db.add(result)

    run.summary = summary
    await db.commit()
    summary = await correlate_run(db, run_id) or summary

    return {
        "run_id": run_id,
        "summary": summary,
        "source": "file_upload",
        "filename": file.filename,
    }


@router.get("/stats")
async def results_stats(db: AsyncSession = Depends(get_db)):
    """Aggregate prevention statistics across all runs."""
    runs_result = await db.execute(select(PlaybookRun))
    all_runs = runs_result.scalars().all()

    total_blocked = sum((r.summary or {}).get("blocked", 0) for r in all_runs)
    total_detected = sum((r.summary or {}).get("detected", 0) for r in all_runs)
    total_allowed = sum((r.summary or {}).get("allowed", 0) for r in all_runs)
    total_error = sum((r.summary or {}).get("error", 0) for r in all_runs)
    scored_total = total_blocked + total_detected + total_allowed
    visibility_total = total_blocked + total_detected

    return {
        "prevention_score": round((total_blocked / scored_total) * 100) if scored_total > 0 else 0,
        "visibility_score": round((visibility_total / scored_total) * 100) if scored_total > 0 else 0,
        "detection_score": round((visibility_total / scored_total) * 100) if scored_total > 0 else 0,
        "total_blocked": total_blocked,
        "total_detected": total_detected,
        "total_allowed": total_allowed,
        "total_error": total_error,
        "total_runs": len(all_runs),
    }


@router.get("/runs/{run_id}")
async def get_run(run_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(PlaybookRun).where(PlaybookRun.id == run_id)
    )
    run = result.scalar_one_or_none()
    if not run:
        return JSONResponse(status_code=404, content={"error": "Run not found"})

    results_query = await db.execute(
        select(TestResult, PreventionTest)
        .outerjoin(PreventionTest, TestResult.test_id == PreventionTest.id)
        .where(TestResult.run_id == run_id)
    )
    result_rows = results_query.all()

    return {
        "id": run.id,
        "playbook_id": run.playbook_id,
        "hostname": run.hostname,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "platform": run.platform or "",
        "os_version": run.os_version or "",
        "agent_name": run.agent_name or "",
        "agent_version": run.agent_version or "",
        "summary": run.summary or {},
        "sensor_logs": run.sensor_logs or [],
        "debug_logs": run.debug_logs or [],
        "performance": run.performance or {},
        "uec_match_status": run.uec_match_status or "not_evaluated",
        "uec_device_id": run.uec_device_id or "",
        "results": [
            {
                "id": r.id,
                "test_id": r.test_id,
                "test_name": test.name if test else "",
                "technique_id": test.technique_id if test else "",
                "source": test.source if test else "",
                "command": test.command if test else "",
                "executor": test.executor if test else "",
                "verdict": r.verdict,
                "exit_code": r.exit_code,
                "error_message": r.error_message,
                "execution_time_ms": r.execution_time_ms,
                "executed_at": r.executed_at.isoformat() if r.executed_at else None,
                "completed_at": r.execution_completed_at.isoformat() if r.execution_completed_at else None,
                "stdout": r.stdout or "",
                "stderr": r.stderr or "",
                "agent_logs": r.agent_logs or [],
                "uec_match_status": r.uec_match_status or "not_evaluated",
                "uec_matches": r.uec_matches or [],
            }
            for r, test in result_rows
        ],
    }


@router.get("/verdicts")
async def get_technique_verdicts(db: AsyncSession = Depends(get_db)):
    """Return per-technique verdicts from all test results.

    For each technique that has results, returns the worst-case verdict:
    - If ANY test was 'allowed', the technique is 'allowed' (no control coverage)
    - Otherwise if ANY test was 'detected', the technique is 'detected' (partial coverage)
    - Otherwise if ANY test was 'blocked', the technique is 'blocked'
    - Otherwise 'untested'

    Used by the MITRE matrix to color cells green/red.
    """
    results_q = await db.execute(
        select(TestResult.verdict, PreventionTest.technique_id)
        .join(PreventionTest, TestResult.test_id == PreventionTest.id)
    )
    rows = results_q.all()

    if not rows:
        return {"verdicts": {}}

    # Group verdicts by technique
    tech_verdicts: dict[str, set[str]] = {}
    for verdict, technique_id in rows:
        if technique_id not in tech_verdicts:
            tech_verdicts[technique_id] = set()
        tech_verdicts[technique_id].add(verdict)

    # Worst-case ordering: no coverage > detection-only > prevention.
    result: dict[str, str] = {}
    for tech_id, verdict_set in tech_verdicts.items():
        if "allowed" in verdict_set:
            result[tech_id] = "allowed"
        elif "detected" in verdict_set:
            result[tech_id] = "detected"
        elif "blocked" in verdict_set:
            result[tech_id] = "blocked"
        else:
            result[tech_id] = "untested"

    return {"verdicts": result}


@router.get("/playbook/{playbook_id}")
async def get_runs_for_playbook(playbook_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(PlaybookRun)
        .where(PlaybookRun.playbook_id == playbook_id)
        .order_by(PlaybookRun.started_at.desc())
    )
    runs = result.scalars().all()

    return {
        "runs": [
            {
                "id": r.id,
                "hostname": r.hostname,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "summary": r.summary or {},
            }
            for r in runs
        ]
    }
