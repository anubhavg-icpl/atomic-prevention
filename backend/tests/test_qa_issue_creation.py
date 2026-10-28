"""Per-finding GitLab issue creation: the route must not 500 and must be idempotent."""

import asyncio

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.app.api.routes import qa
from backend.app.db.database import Base
from backend.app.models.qa import QaAnalysis
from backend.app.models import adversary, playbook, qa as qa_models, result, technique, test_case  # noqa: F401  (register all tables on Base.metadata)


class FakeGitlab:
    calls: list[str] = []

    async def create_issue(self, *, project_id, title, description, labels=None, marker=None):
        FakeGitlab.calls.append(marker)
        return {
            "created": True,
            "project_id": project_id,
            "issue": {"iid": len(FakeGitlab.calls), "title": title, "web_url": f"https://gl/{marker}",
                      "references": {"full": "grp/proj#1"}, "state": "opened"},
        }


async def _run(monkeypatch):
    monkeypatch.setattr(qa, "GitlabClient", FakeGitlab)
    FakeGitlab.calls = []
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)() as db:
        db.add(QaAnalysis(id="a1", run_id="r1", result={
            "findings": [
                {"test_id": "t1", "title": "Allowed one", "status": "allowed"},
                {"test_id": "t2", "title": "Blocked fine", "status": "blocked"},
                {"test_id": "t3", "title": "Detected only", "status": "detected"},
            ],
            "issue": {"title": "x", "description": "d", "labels": ["qa"]},
        }))
        await db.commit()
        req = qa.CreateIssuesRequest(project_id="532", mode="finding")
        first = await qa.create_issues("a1", req, db)
        second = await qa.create_issues("a1", req, db)  # rerun must not duplicate
    return first, second


def test_finding_mode_creates_one_issue_per_actionable_finding_and_is_idempotent(monkeypatch):
    first, second = asyncio.run(_run(monkeypatch))
    assert first["mode"] == "finding"
    assert len(first["issues"]) == 2  # blocked finding is not actionable
    assert len(second["issues"]) == 2
    assert len(FakeGitlab.calls) == 2  # second pass hit the local marker cache, not GitLab


def test_issue_body_carries_run_evidence_and_fences_output():
    rec = QaAnalysis(id="a2", run_id="r2", result={
        "run": {"hostname": "UEC_CDK_RHEL_8_10-3980"},
        "tests": [{"id": "t1", "command": "sh -c id", "stdout": "uid=0 ```boom", "stderr": "",
                   "exit_code": 0, "agent_logs": [{"level": "info", "message": "verdict allowed"}]}],
    })
    body = qa._finding_markdown(rec, {"test_id": "t1", "technique_id": "T1003.007", "status": "allowed",
                                      "severity": "high", "detail": "d", "recommendation": "r"}, "m")
    assert "UEC_CDK_RHEL_8_10-3980" in body and "sh -c id" in body and "verdict allowed" in body
    assert body.count("```") == 6  # command, stdout, agent log fences only; payload fence stripped


def test_consolidated_issue_twice_returns_same_record_not_500(monkeypatch):
    async def run():
        monkeypatch.setattr(qa, "GitlabClient", FakeGitlab)
        FakeGitlab.calls = []
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)() as db:
            db.add(QaAnalysis(id="a3", run_id="r3", result={"issue": {"title": "t", "description": "d", "labels": []}}))
            await db.commit()
            req = qa.CreateIssueRequest(project_id="532")
            return await qa.create_issue("a3", req, db), await qa.create_issue("a3", req, db)
    first, second = asyncio.run(run())
    assert first["iid"] == second["iid"]
    assert len(FakeGitlab.calls) == 1  # no second GitLab call
