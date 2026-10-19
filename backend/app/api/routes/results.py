import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.db.database import get_db
from backend.app.models.playbook import PlaybookRun
from backend.app.models.result import TestResult

router = APIRouter()


class TestResultInput(BaseModel):
    test_id: str
    verdict: str  # "blocked" | "allowed" | "error"
    exit_code: int | None = None
    error_message: str | None = None
    execution_time_ms: int = 0


class SubmitResultsRequest(BaseModel):
    playbook_id: str
    hostname: str = ""
    results: list[TestResultInput]


@router.post("/submit")
async def submit_results(
    request: SubmitResultsRequest,
    db: AsyncSession = Depends(get_db),
):
    run_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    summary = {"blocked": 0, "allowed": 0, "error": 0}

    run = PlaybookRun(
        id=run_id,
        playbook_id=request.playbook_id,
        hostname=request.hostname,
        started_at=now,
        completed_at=now,
    )
    db.add(run)

    for r in request.results:
        verdict = r.verdict if r.verdict in ("blocked", "allowed", "error") else "error"
        summary[verdict] = summary.get(verdict, 0) + 1

        result = TestResult(
            id=str(uuid.uuid4()),
            run_id=run_id,
            test_id=r.test_id,
            verdict=verdict,
            exit_code=r.exit_code,
            error_message=r.error_message,
            execution_time_ms=r.execution_time_ms,
            executed_at=now,
        )
        db.add(result)

    run.summary = summary
    await db.commit()

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

    summary = {"blocked": 0, "allowed": 0, "error": 0}

    run = PlaybookRun(
        id=run_id,
        playbook_id=playbook_info.get("id", f"uploaded-{run_id[:8]}"),
        hostname=hostname,
        started_at=started_at,
        completed_at=now,
    )
    db.add(run)

    for r in results_list:
        # Handle both dict and object-style keys from PowerShell JSON
        test_id = r.get("TestId") or r.get("test_id", str(uuid.uuid4()))
        verdict_raw = r.get("Verdict") or r.get("verdict", "error")
        verdict = verdict_raw if verdict_raw in ("blocked", "allowed", "error") else "error"
        exit_code = r.get("ExitCode") or r.get("exit_code")
        error_msg = r.get("ErrorMessage") or r.get("error_message")
        exec_time = r.get("ExecutionTimeMs") or r.get("execution_time_ms", 0)

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
            executed_at=started_at,
        )
        db.add(result)

    run.summary = summary
    await db.commit()

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
    total_allowed = sum((r.summary or {}).get("allowed", 0) for r in all_runs)
    total_error = sum((r.summary or {}).get("error", 0) for r in all_runs)
    scored_total = total_blocked + total_allowed

    return {
        "prevention_score": round((total_blocked / scored_total) * 100) if scored_total > 0 else 0,
        "total_blocked": total_blocked,
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
        select(TestResult).where(TestResult.run_id == run_id)
    )
    test_results = results_query.scalars().all()

    return {
        "id": run.id,
        "playbook_id": run.playbook_id,
        "hostname": run.hostname,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "summary": run.summary or {},
        "results": [
            {
                "id": r.id,
                "test_id": r.test_id,
                "verdict": r.verdict,
                "exit_code": r.exit_code,
                "error_message": r.error_message,
                "execution_time_ms": r.execution_time_ms,
            }
            for r in test_results
        ],
    }


@router.get("/verdicts")
async def get_technique_verdicts(db: AsyncSession = Depends(get_db)):
    """Return per-technique verdicts from all test results.

    For each technique that has results, returns the worst-case verdict:
    - If ANY test was 'allowed', the technique is 'allowed' (gap found)
    - If ALL tests were 'blocked', the technique is 'blocked' (controls working)
    - Otherwise 'untested'

    Used by the MITRE matrix to color cells green/red.
    """
    from backend.app.models.test_case import PreventionTest

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

    # Worst-case: if any test allowed, technique is allowed
    result: dict[str, str] = {}
    for tech_id, verdict_set in tech_verdicts.items():
        if "allowed" in verdict_set:
            result[tech_id] = "allowed"
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
