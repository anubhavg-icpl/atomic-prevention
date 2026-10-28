import uuid
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.db.database import get_db
from backend.app.models.qa import GitlabIssue
from backend.app.services.log_sanitizer import redact_text
from backend.app.services.gitlab_client import GitlabClient
from backend.app.services.qa_orchestrator import QaOrchestrator, QaRunNotFound

router = APIRouter()


class CreateIssueRequest(BaseModel):
    project_id: str
    title: str | None = None
    description: str | None = None
    labels: list[str] | None = None


class CreateIssuesRequest(CreateIssueRequest):
    mode: str = "consolidated"  # consolidated | finding


@router.post("/runs/{run_id}/analyze")
async def analyze_run(run_id: str, db: AsyncSession = Depends(get_db)):
    try:
        analysis = await QaOrchestrator(db).analyze_run(run_id)
    except QaRunNotFound as exc:
        return JSONResponse(status_code=404, content={"error": str(exc)})

    if (
        settings.gitlab_enabled
        and settings.gitlab_auto_create_issues
        and settings.gitlab_default_project
    ):
        issue_result = await create_issues(
            analysis["id"],
            CreateIssuesRequest(
                project_id=settings.gitlab_default_project,
                mode=settings.gitlab_auto_issue_mode,
            ),
            db,
        )
        if isinstance(issue_result, JSONResponse):
            analysis["gitlab_auto_create_error"] = "GitLab issue automation failed"
        else:
            analysis["gitlab_issues"] = issue_result.get("issues", [])
            analysis["gitlab_issue_mode"] = issue_result.get("mode")
    return analysis


@router.get("/runs/{run_id}/analysis")
async def latest_analysis(run_id: str, db: AsyncSession = Depends(get_db)):
    analysis = await QaOrchestrator(db).latest_analysis(run_id)
    if not analysis:
        return JSONResponse(status_code=404, content={"error": "Analysis not found"})
    issues = (
        await db.execute(
            select(GitlabIssue)
            .where(GitlabIssue.run_id == run_id)
            .order_by(GitlabIssue.created_at.desc())
        )
    ).scalars().all()
    analysis["gitlab_issues"] = [
        _serialize_issue(issue, {"state": "opened"}) for issue in issues
    ]
    return analysis


@router.post("/analyses/{analysis_id}/issue")
async def create_issue(
    analysis_id: str,
    request: CreateIssueRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        record, draft = await QaOrchestrator(db).issue_draft(analysis_id)
    except QaRunNotFound as exc:
        return JSONResponse(status_code=404, content={"error": str(exc)})

    client = GitlabClient()
    marker = f"atomic-prevention-run:{record.run_id}"
    title = redact_text(
        request.title or draft.get("title") or "Endpoint control QA findings", 255
    ) or "Endpoint control QA findings"
    description = redact_text(request.description or draft.get("description") or "", 100_000) or ""
    labels = request.labels if request.labels is not None else draft.get("labels", [])
    description = f"{description.rstrip()}\n\n---\n`{marker}`"

    # gitlab_issues.marker is UNIQUE: a repeat call must return the stored record, not insert a duplicate
    existing = (
        await db.execute(select(GitlabIssue).where(GitlabIssue.marker == marker))
    ).scalar_one_or_none()
    if existing:
        return _serialize_issue(existing, {"state": "opened"})

    try:
        result = await client.create_issue(
            project_id=request.project_id,
            title=title,
            description=description,
            labels=labels,
            marker=marker,
        )
    except Exception as exc:
        return JSONResponse(status_code=502, content={"error": str(exc)})

    issue = result["issue"]
    issue_record = GitlabIssue(
        id=str(uuid.uuid4()),
        run_id=record.run_id,
        project_id=str(request.project_id),
        project_path=str(issue.get("references", {}).get("full", "")),
        iid=str(issue.get("iid", "")),
        title=str(issue.get("title", title)),
        web_url=str(issue.get("web_url", "")),
        created="created" if result["created"] else "existing",
        marker=marker,
        metadata_={"analysis_id": analysis_id, "gitlab_url": settings.gitlab_url},
    )
    db.add(issue_record)
    await db.commit()
    return _serialize_issue(issue_record, issue)


@router.post("/analyses/{analysis_id}/issues")
async def create_issues(
    analysis_id: str,
    request: CreateIssuesRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        record, draft = await QaOrchestrator(db).issue_draft(analysis_id)
    except QaRunNotFound as exc:
        return JSONResponse(status_code=404, content={"error": str(exc)})

    if request.mode != "finding":
        single = await create_issue(analysis_id, request, db)
        if isinstance(single, JSONResponse):  # propagate 404/502 instead of wrapping it
            return single
        return {"issues": [single], "mode": "consolidated"}

    findings = [
        # "error" is test-harness/environment noise (platform-mismatched test, missing
        # prerequisite), not a real detection/prevention gap — never file a ticket for it.
        finding for finding in (record.result or {}).get("findings", [])
        if isinstance(finding, dict) and finding.get("status") in {"allowed", "detected"}
    ][:50]
    if not findings:
        return JSONResponse(status_code=400, content={"error": "No actionable findings to create issues for"})

    client = GitlabClient()
    created: list[dict[str, Any]] = []
    for index, finding in enumerate(findings, 1):
        test_marker = str(finding.get("test_id") or f"finding-{index}")
        marker = f"atomic-prevention-run:{record.run_id}:test:{test_marker}"
        existing = (
            await db.execute(select(GitlabIssue).where(GitlabIssue.marker == marker))
        ).scalar_one_or_none()
        if existing:
            created.append(_serialize_issue(existing, {"state": "opened"}))
            continue

        title = redact_text(
            _no_shouting(str(finding.get("title") or f"QA finding {index}")), 255
        ) or f"QA finding {index}"
        description = redact_text(_finding_markdown(record, finding, marker), 100_000)
        try:
            result = await client.create_issue(
                project_id=request.project_id,
                title=title,
                description=description,
                labels=request.labels if request.labels is not None else draft.get("labels", []),
                marker=marker,
            )
        except Exception as exc:
            return JSONResponse(
                status_code=502,
                content={"error": str(exc), "issues": created, "mode": "finding"},
            )

        issue = result["issue"]
        issue_record = GitlabIssue(
            id=str(uuid.uuid4()),
            run_id=record.run_id,
            project_id=str(request.project_id),
            project_path=str(issue.get("references", {}).get("full", "")),
            iid=str(issue.get("iid", "")),
            title=str(issue.get("title", title)),
            web_url=str(issue.get("web_url", "")),
            created="created" if result["created"] else "existing",
            marker=marker,
            metadata_={"analysis_id": analysis_id, "finding": finding, "mode": "finding"},
        )
        db.add(issue_record)
        await db.commit()
        created.append(_serialize_issue(issue_record, issue))

    return {"issues": created, "mode": "finding"}


def _serialize_issue(record: GitlabIssue, issue: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": record.id,
        "run_id": record.run_id,
        "project_id": record.project_id,
        "project_path": record.project_path,
        "iid": record.iid,
        "title": record.title,
        "web_url": record.web_url,
        "created": record.created,
        "state": issue.get("state", ""),
    }


def _no_shouting(value: str) -> str:
    letters = [char for char in value if char.isalpha()]
    upper_ratio = sum(char.isupper() for char in letters) / len(letters) if letters else 0
    return value.capitalize() if upper_ratio > 0.6 else value


def _finding_markdown(record, finding: dict[str, Any], marker: str) -> str:
    payload = record.result if isinstance(record.result, dict) else {}
    run = payload.get("run", {})
    test = next((t for t in payload.get("tests", []) if t.get("id") == finding.get("test_id")), {})
    logs = test.get("agent_logs") or []
    lines = [
        "## Endpoint control QA finding",
        "",
        f"- Run: `{record.run_id}`",
        f"- Host: `{run.get('hostname', '')}`",
        f"- Technique: `{finding.get('technique_id', '')}`",
        f"- Test: `{finding.get('test_id', '')}`",
        f"- Status: {finding.get('status', '')}",
        f"- Severity: {finding.get('severity', '')}",
        f"- Exit code: `{test.get('exit_code', '')}`",
        "",
        "### Detail",
        str(finding.get("detail", "")),
        "",
        "### Recommendation",
        str(finding.get("recommendation", "")),
    ]
    # evidence blocks: fenced so captured output cannot inject markdown/quick-actions
    for title, body in (
        ("Command", test.get("command")),
        ("Stdout", test.get("stdout")),
        ("Stderr", test.get("stderr")),
        ("Agent log", "\n".join(f"{l.get('level', '')} {l.get('message', '')}" for l in logs[-10:] if isinstance(l, dict))),
    ):
        if body:
            lines += ["", f"### {title}", "```text", str(body).replace("```", "'''"), "```"]
    lines += ["", "---", f"`{marker}`"]
    return "\n".join(lines)[:100_000]
