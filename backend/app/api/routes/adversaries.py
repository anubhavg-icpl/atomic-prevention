from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.db.database import get_db
from backend.app.models.adversary import AdversaryGroup
from backend.app.models.technique import Technique

router = APIRouter()


@router.get("")
async def list_adversaries(
    search: str | None = None,
    skip: int = 0,
    limit: int = Query(default=50, le=200),
    db: AsyncSession = Depends(get_db),
):
    query = select(AdversaryGroup)

    if search:
        query = query.where(
            AdversaryGroup.name.ilike(f"%{search}%")
            | AdversaryGroup.id.ilike(f"%{search}%")
        )

    # Get total count before pagination
    count_query = select(func.count()).select_from(query.subquery())
    total_count = await db.scalar(count_query) or 0

    result = await db.execute(query.offset(skip).limit(limit))
    groups = result.scalars().all()

    return {
        "adversaries": [_serialize_group(g) for g in groups],
        "total": total_count,
    }


@router.get("/stats")
async def adversary_stats(db: AsyncSession = Depends(get_db)):
    count = await db.scalar(select(func.count()).select_from(AdversaryGroup))
    return {"total_groups": count or 0}


@router.get("/{group_id}")
async def get_adversary(group_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AdversaryGroup).where(AdversaryGroup.id == group_id)
    )
    group = result.scalar_one_or_none()
    if not group:
        return JSONResponse(status_code=404, content={"error": "Adversary group not found"})

    # Get associated techniques
    technique_ids = group.technique_ids or []
    techniques = []
    if technique_ids:
        tech_result = await db.execute(
            select(Technique).where(Technique.id.in_(technique_ids))
        )
        techniques = tech_result.scalars().all()

    data = _serialize_group(group)
    data["techniques"] = [
        {
            "id": t.id,
            "name": t.name,
            "tactics": t.tactics or [],
            "platforms": t.platforms or [],
        }
        for t in techniques
    ]
    return data


def _serialize_group(g: AdversaryGroup) -> dict:
    return {
        "id": g.id,
        "name": g.name,
        "description": g.description,
        "aliases": g.aliases or [],
        "technique_count": len(g.technique_ids or []),
        "url": g.url,
    }
