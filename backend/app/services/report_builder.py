from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.playbook import PlaybookRun
from backend.app.models.result import TestResult
from backend.app.models.test_case import PreventionTest
from backend.app.core.mitre import get_mitre_client


class ReportBuilder:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def build_run_report(self, run_id: str) -> dict | None:
        """Build a detailed report for a playbook run."""
        result = await self.db.execute(
            select(PlaybookRun).where(PlaybookRun.id == run_id)
        )
        run = result.scalar_one_or_none()
        if not run:
            return None

        # Get all results with test details
        results_query = await self.db.execute(
            select(TestResult, PreventionTest)
            .join(PreventionTest, TestResult.test_id == PreventionTest.id)
            .where(TestResult.run_id == run_id)
        )
        rows = results_query.all()

        mitre = await get_mitre_client()

        # Build technique-level summary
        technique_results: dict[str, dict] = {}
        for test_result, test in rows:
            tid = test.technique_id
            if tid not in technique_results:
                tech_info = mitre.get_technique(tid) or {}
                technique_results[tid] = {
                    "technique_id": tid,
                    "technique_name": tech_info.get("name", "Unknown"),
                    "tactics": tech_info.get("tactics", []),
                    "tests": [],
                    "blocked": 0,
                    "allowed": 0,
                    "error": 0,
                }

            technique_results[tid]["tests"].append({
                "test_id": test.id,
                "test_name": test.name,
                "source": test.source,
                "verdict": test_result.verdict,
                "execution_time_ms": test_result.execution_time_ms,
                "error_message": test_result.error_message,
            })
            technique_results[tid][test_result.verdict] = (
                technique_results[tid].get(test_result.verdict, 0) + 1
            )

        # Calculate overall score
        total_blocked = sum(t["blocked"] for t in technique_results.values())
        total_allowed = sum(t["allowed"] for t in technique_results.values())
        total_error = sum(t["error"] for t in technique_results.values())
        total = total_blocked + total_allowed + total_error
        scored_total = total_blocked + total_allowed
        prevention_score = (total_blocked / scored_total * 100) if scored_total > 0 else 0

        return {
            "run_id": run.id,
            "playbook_id": run.playbook_id,
            "hostname": run.hostname,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "completed_at": run.completed_at.isoformat() if run.completed_at else None,
            "summary": {
                "total_tests": total,
                "blocked": total_blocked,
                "allowed": total_allowed,
                "error": total_error,
                "prevention_score": round(prevention_score, 1),
            },
            "techniques": list(technique_results.values()),
        }

    async def get_dashboard_stats(self) -> dict:
        """Get overall dashboard statistics."""
        total_runs = await self.db.scalar(
            select(func.count()).select_from(PlaybookRun)
        ) or 0

        total_results = await self.db.scalar(
            select(func.count()).select_from(TestResult)
        ) or 0

        blocked_count = await self.db.scalar(
            select(func.count())
            .select_from(TestResult)
            .where(TestResult.verdict == "blocked")
        ) or 0

        allowed_count = await self.db.scalar(
            select(func.count())
            .select_from(TestResult)
            .where(TestResult.verdict == "allowed")
        ) or 0

        scored_results = blocked_count + allowed_count
        prevention_rate = (blocked_count / scored_results * 100) if scored_results > 0 else 0

        return {
            "total_runs": total_runs,
            "total_results": total_results,
            "blocked": blocked_count,
            "allowed": allowed_count,
            "prevention_rate": round(prevention_rate, 1),
        }
