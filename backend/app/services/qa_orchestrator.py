"""End-to-end QA analysis over Atomic Prevention, UEC, and Claude."""

import json
import re
import time
import uuid
from datetime import timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.models.playbook import PlaybookRun
from backend.app.models.qa import QaAnalysis
from backend.app.models.result import TestResult
from backend.app.models.test_case import PreventionTest
from backend.app.services.claude_client import ClaudeClient
from backend.app.services.uec_client import UecClient


class QaRunNotFound(ValueError):
    pass


class QaOrchestrator:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def analyze_run(self, run_id: str) -> dict[str, Any]:
        run, rows = await self._load_run(run_id)
        uec = UecClient()
        uec_data: dict[str, Any] = {"available": False}
        if settings.uec_enabled and settings.uec_correlation_enabled and uec.configured:
            try:
                started = _aware_datetime(run.started_at)
                completed = _aware_datetime(run.completed_at)
                device = await uec.find_device(run.hostname)
                device_id = str(device.get("id") or device.get("deviceId") or "") if device else None
                findings = await uec.threat_findings(
                    device_id=device_id,
                    days=1,
                    limit=100,
                    started_at=started,
                    completed_at=completed,
                )
                sensor_state = await uec.device_detection_state(device_id) if device_id else {}
                uec_data = {
                    "available": True,
                    "device": _compact(device, 30) if device else None,
                    # Correlation is finding-driven. Generic event fan-out is
                    # deliberately avoided to keep QA completion latency low.
                    "events": {"items": [], "total": 0, "has_more": False},
                    "findings": findings,
                    "sensor_state": _compact(sensor_state, 50),
                }
            except Exception as exc:
                uec_data = {"available": False, "error": str(exc)}

        compact_run = self._compact_run(run, rows, uec_data)
        provider = "rules"
        model = ""
        analysis: dict[str, Any]
        claude = ClaudeClient()
        if claude.configured:
            try:
                started_at = time.monotonic()
                analysis = await claude.analyze_json(_SYSTEM_PROMPT, json.dumps(compact_run, separators=(",", ":")))
                usage = analysis.pop("_usage", {}) if isinstance(analysis, dict) else {}
                analysis = _validated_analysis(analysis)
                analysis["usage"] = {
                    **(usage if isinstance(usage, dict) else {}),
                    "latency_ms": int((time.monotonic() - started_at) * 1000),
                }
                provider = "claude"
                model = claude.model
            except Exception as exc:
                analysis = _deterministic_analysis(compact_run)
                analysis["integration_notes"] = [f"Claude analysis unavailable: {exc}"]
        else:
            analysis = _deterministic_analysis(compact_run)

        record = QaAnalysis(
            id=str(uuid.uuid4()),
            run_id=run.id,
            provider=provider,
            model=model,
            summary=analysis.get("summary", ""),
            result={
                **analysis,
                "uec": uec_data,
                # already redacted + size-capped by _compact_run; GitLab issue bodies reuse it as evidence
                "tests": compact_run["tests"],
                "run": {
                    "id": run.id,
                    "playbook_id": run.playbook_id,
                    "hostname": run.hostname,
                    "started_at": run.started_at.isoformat() if run.started_at else None,
                    "completed_at": run.completed_at.isoformat() if run.completed_at else None,
                    "summary": run.summary or {},
                },
            },
        )
        self.db.add(record)
        await self.db.commit()
        return _serialize_analysis(record)

    async def latest_analysis(self, run_id: str) -> dict[str, Any] | None:
        result = await self.db.execute(
            select(QaAnalysis)
            .where(QaAnalysis.run_id == run_id)
            .order_by(QaAnalysis.created_at.desc())
            .limit(1)
        )
        record = result.scalar_one_or_none()
        return _serialize_analysis(record) if record else None

    async def issue_draft(self, analysis_id: str) -> tuple[QaAnalysis, dict[str, Any]]:
        record = await self.db.get(QaAnalysis, analysis_id)
        if not record:
            raise QaRunNotFound("Analysis not found")
        payload = record.result or {}
        draft = payload.get("issue")
        if not isinstance(draft, dict):
            draft = _deterministic_analysis(payload.get("run", {}))["issue"]
        return record, draft

    async def _load_run(self, run_id: str) -> tuple[PlaybookRun, list[Any]]:
        run = await self.db.get(PlaybookRun, run_id)
        if not run:
            raise QaRunNotFound("Run not found")
        result = await self.db.execute(
            select(TestResult, PreventionTest)
            .outerjoin(PreventionTest, TestResult.test_id == PreventionTest.id)
            .where(TestResult.run_id == run_id)
            .order_by(TestResult.executed_at)
        )
        return run, result.all()

    def _compact_run(
        self, run: PlaybookRun, rows: list[Any], uec_data: dict[str, Any]
    ) -> dict[str, Any]:
        tests = []
        for result, test in rows:
            tests.append({
                "id": result.test_id,
                "name": test.name if test else "",
                "technique_id": test.technique_id if test else "",
                "source": test.source if test else "",
                "executor": test.executor if test else "",
                "command": _redact((test.command if test else "")[:600]),
                "verdict": result.verdict,
                "exit_code": result.exit_code,
                "error_message": _redact((result.error_message or "")[:500]),
                "stdout": _redact((result.stdout or "")[:1000]),
                "stderr": _redact((result.stderr or "")[:1000]),
                "agent_logs": (result.agent_logs or [])[:20],
            })
        return {
            "run": {
                "id": run.id,
                "playbook_id": run.playbook_id,
                "hostname": run.hostname,
                "platform": run.platform or "",
                "os_version": run.os_version or "",
                "agent_version": run.agent_version or "",
                "summary": run.summary or {},
                "performance": _compact(run.performance or {}, 30),
                "sensor_logs": _compact((run.sensor_logs or [])[:100], 30),
                "debug_logs": _compact((run.debug_logs or [])[:100], 30),
            },
            "tests": tests,
            "uec": uec_data,
        }


_SYSTEM_PROMPT = """You are a precise endpoint-security QA analyst. Use only the supplied data.
Classify each test as blocked (execution prevented), detected (telemetry/alert only, not prevented), allowed (no prevention or detection), or error.
Return strict JSON with: summary, overall_status, findings, issue, confidence.
Findings need technique_id, test_id, status, severity, title, detail, recommendation.
The issue needs a sentence-case title, markdown description, and labels. Be terse: summary under 60 words, each finding detail under 40 words, at most 15 findings, issue description under 250 words. Return only the JSON object. Never include credentials, tokens, or raw secrets."""


def _deterministic_analysis(payload: dict[str, Any]) -> dict[str, Any]:
    tests = payload.get("tests", []) if isinstance(payload, dict) else []
    findings = []
    for test in tests:
        if test.get("verdict") not in {"allowed", "detected", "error"}:
            continue
        status = test.get("verdict")
        severity = "high" if status == "allowed" else "medium" if status == "detected" else "low"
        findings.append({
            "technique_id": test.get("technique_id", ""),
            "test_id": test.get("id", ""),
            "status": status,
            "severity": severity,
            "title": _no_shouting(str(test.get("name", "Test finding"))),
            "detail": str(test.get("error_message") or test.get("stdout") or "Review the captured execution output.")[:1000],
            "recommendation": "Tune prevention so this technique is blocked, then retain the detection signal." if status != "error" else "Fix the test harness before judging the control.",
        })
    summary_counts = payload.get("run", {}).get("summary", {}) if isinstance(payload.get("run"), dict) else {}
    allowed = int(summary_counts.get("allowed", 0))
    detected = int(summary_counts.get("detected", 0))
    errors = int(summary_counts.get("error", 0))
    title = _no_shouting("Endpoint control QA findings")
    description = _markdown_issue(payload, findings)
    return {
        "summary": _no_shouting(f"{allowed} allowed, {detected} detection-only, and {errors} error results need review."),
        "overall_status": "allowed" if allowed else "detected" if detected else "error" if errors else "blocked",
        "findings": findings[:100],
        "issue": {
            "title": title,
            "description": description,
            "labels": ["qa", "atomic-prevention", "endpoint-security"],
        },
        "confidence": "high" if findings else "medium",
    }


def _markdown_issue(payload: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    run = payload.get("run", {}) if isinstance(payload.get("run"), dict) else {}
    lines = [
        "## Endpoint control QA report",
        "",
        f"- Run: `{run.get('id', '')}`",
        f"- Host: `{run.get('hostname', '')}`",
        f"- Platform: `{run.get('platform', '')}`",
        "",
        "### Findings",
    ]
    if findings:
        for finding in findings[:100]:
            lines.append(
                f"- **{_no_shouting(str(finding.get('title', 'Finding')))}** — {finding.get('status')} · `{finding.get('technique_id', '')}`"
            )
            lines.append(f"  {finding.get('detail', '')}")
            lines.append(f"  Recommendation: {finding.get('recommendation', '')}")
    else:
        lines.append("No unresolved findings were found.")
    return "\n".join(lines)[:100_000]


def _validated_analysis(value: dict[str, Any]) -> dict[str, Any]:
    findings = []
    for raw in value.get("findings", []):
        if not isinstance(raw, dict):
            continue
        status = str(raw.get("status", "error")).lower()
        if status not in {"blocked", "detected", "allowed", "error"}:
            status = "error"
        findings.append({
            "technique_id": str(raw.get("technique_id", ""))[:64],
            "test_id": str(raw.get("test_id", ""))[:128],
            "status": status,
            "severity": str(raw.get("severity", "medium")).lower()[:24],
            "title": _no_shouting(str(raw.get("title", "Finding")))[:255],
            "detail": str(raw.get("detail", ""))[:4000],
            "recommendation": str(raw.get("recommendation", ""))[:2000],
        })
    issue = value.get("issue") if isinstance(value.get("issue"), dict) else {}
    labels = [str(label)[:64] for label in issue.get("labels", []) if str(label).strip()][:10]
    return {
        "summary": _no_shouting(str(value.get("summary", "QA analysis completed")))[:4000],
        "overall_status": str(value.get("overall_status", "error")).lower()[:24],
        "findings": findings[:100],
        "issue": {
            "title": _no_shouting(str(issue.get("title", "Endpoint control QA findings")))[:255],
            "description": str(issue.get("description", ""))[:100_000],
            "labels": labels or ["qa", "atomic-prevention", "endpoint-security"],
        },
        "confidence": str(value.get("confidence", "medium")).lower()[:24],
    }


def _no_shouting(value: str) -> str:
    letters = [char for char in value if char.isalpha()]
    upper_ratio = sum(char.isupper() for char in letters) / len(letters) if letters else 0
    if upper_ratio > 0.6:
        return value.capitalize()
    return value


def _compact(value: Any, limit: int) -> Any:
    if isinstance(value, dict):
        return {str(key): _compact(item, limit) for key, item in list(value.items())[:limit]}
    if isinstance(value, list):
        return [_compact(item, limit) for item in value[:limit]]
    if isinstance(value, str):
        return _redact(value[:2000])
    return value


_SENSITIVE_PATTERNS = [
    re.compile(r"(?i)(x-api-key\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)\S+"),
    re.compile(r"(?i)((?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*)\S+"),
]


def _redact(value: str) -> str:
    redacted = value
    for pattern in _SENSITIVE_PATTERNS:
        redacted = pattern.sub(r"\1<redacted>", redacted)
    return redacted


def _aware_datetime(value: Any):
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _serialize_analysis(record: QaAnalysis) -> dict[str, Any]:
    return {
        "id": record.id,
        "run_id": record.run_id,
        "provider": record.provider,
        "model": record.model,
        "summary": record.summary,
        "result": record.result or {},
        "created_at": record.created_at.isoformat() if record.created_at else None,
    }
