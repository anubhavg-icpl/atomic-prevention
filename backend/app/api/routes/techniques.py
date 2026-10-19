from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.db.database import get_db
from backend.app.models.technique import Technique
from backend.app.models.test_case import PreventionTest

router = APIRouter()


def _platform_filter_tests(tests: list, platform: str | None) -> list:
    """Filter tests by platform (checks the test's platforms JSON array)."""
    if not platform:
        return tests
    plat = platform.lower()
    return [t for t in tests if plat in [p.lower() for p in (t.platforms or [])]]


async def _count_tests_for_technique(
    db: AsyncSession, technique_id: str, platform: str | None = None
) -> int:
    """Count tests for a technique, optionally filtered by platform."""
    query = select(PreventionTest).where(PreventionTest.technique_id == technique_id)
    result = await db.execute(query)
    tests = result.scalars().all()
    if platform:
        plat = platform.lower()
        tests = [t for t in tests if plat in [p.lower() for p in (t.platforms or [])]]
    return len(tests)


@router.get("")
async def list_techniques(
    tactic: str | None = None,
    platform: str | None = None,
    source: str | None = None,
    search: str | None = None,
    skip: int = 0,
    limit: int = Query(default=50, le=200),
    db: AsyncSession = Depends(get_db),
):
    query = select(Technique)

    if search:
        query = query.where(
            Technique.name.ilike(f"%{search}%")
            | Technique.id.ilike(f"%{search}%")
            | Technique.description.ilike(f"%{search}%")
        )

    # Fetch ALL matching rows first so we can filter JSON fields in Python
    # (SQLite JSON support is limited, so tactic/platform/source filtering
    # must happen in Python, not SQL).  We paginate *after* filtering so
    # the total count and page boundaries are correct.
    result = await db.execute(query)
    all_techniques = list(result.scalars().all())

    # Filter JSON fields in Python
    if tactic:
        all_techniques = [t for t in all_techniques if tactic in (t.tactics or [])]
    if platform:
        all_techniques = [
            t for t in all_techniques
            if platform.lower() in [p.lower() for p in (t.platforms or [])]
        ]
    if source:
        all_techniques = [t for t in all_techniques if source in (t.sources or [])]

    # Correct total *after* filtering
    total_count = len(all_techniques)

    # Paginate the filtered list
    techniques = all_techniques[skip : skip + limit]

    # Enrich each technique with test count (filtered by platform if specified)
    enriched = []
    for t in techniques:
        data = _serialize_technique(t)
        test_count = await _count_tests_for_technique(db, t.id, platform)

        if "." not in t.id:
            # Parent technique: also count sub-technique tests
            sub_query = select(PreventionTest).where(
                PreventionTest.technique_id.like(f"{t.id}.%")
            )
            sub_result = await db.execute(sub_query)
            sub_tests = sub_result.scalars().all()
            if platform:
                sub_tests = [st for st in sub_tests if platform.lower() in [p.lower() for p in (st.platforms or [])]]
            sub_count = len(sub_tests)
            data["test_count"] = test_count + sub_count
            data["own_test_count"] = test_count
            data["sub_test_count"] = sub_count
        else:
            data["test_count"] = test_count
        enriched.append(data)

    return {"techniques": enriched, "total": total_count}


@router.get("/stats")
async def technique_stats(db: AsyncSession = Depends(get_db)):
    tech_count = await db.scalar(select(func.count()).select_from(Technique))
    test_count = await db.scalar(select(func.count()).select_from(PreventionTest))

    return {
        "total_techniques": tech_count or 0,
        "total_tests": test_count or 0,
    }


@router.get("/{technique_id}")
async def get_technique(
    technique_id: str,
    platform: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Technique).where(Technique.id == technique_id)
    )
    technique = result.scalar_one_or_none()
    if not technique:
        return JSONResponse(status_code=404, content={"error": "Technique not found"})

    # Get tests directly mapped to this technique
    tests_result = await db.execute(
        select(PreventionTest).where(PreventionTest.technique_id == technique_id)
    )
    tests = list(tests_result.scalars().all())

    # For parent techniques, also include sub-technique tests
    sub_techniques = []
    if "." not in technique_id:
        sub_tests_result = await db.execute(
            select(PreventionTest).where(PreventionTest.technique_id.like(f"{technique_id}.%"))
        )
        sub_tests = sub_tests_result.scalars().all()
        tests.extend(sub_tests)

        sub_techs_result = await db.execute(
            select(Technique).where(Technique.id.like(f"{technique_id}.%"))
        )
        sub_techniques = [
            {"id": st.id, "name": st.name, "tactics": st.tactics or [], "platforms": st.platforms or []}
            for st in sub_techs_result.scalars().all()
        ]

    # Filter tests by platform if specified
    if platform:
        plat = platform.lower()
        tests = [t for t in tests if plat in [p.lower() for p in (t.platforms or [])]]

    data = _serialize_technique(technique)
    data["tests"] = [_serialize_test(t) for t in tests]
    data["sub_techniques"] = sub_techniques
    return data


def _serialize_technique(t: Technique) -> dict:
    return {
        "id": t.id,
        "name": t.name,
        "description": t.description,
        "tactics": t.tactics or [],
        "platforms": t.platforms or [],
        "sources": t.sources or [],
        "url": t.url,
    }


def _serialize_test(t: PreventionTest) -> dict:
    return {
        "id": t.id,
        "technique_id": t.technique_id,
        "source": t.source,
        "name": t.name,
        "description": t.description,
        "command": t.command,
        "executor": t.executor,
        "cleanup_command": t.cleanup_command,
        "elevation_required": t.elevation_required,
        "binary_path": t.binary_path,
        "risk_level": t.risk_level,
        "platforms": t.platforms or [],
        "runnable": (t.metadata_ or {}).get("runnable", True),
        "readiness_reasons": (t.metadata_ or {}).get("readiness_reasons", []),
    }
