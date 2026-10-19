from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.db.database import get_db
from backend.app.models.playbook import Playbook, PlaybookRun
from backend.app.services.playbook_generator import PlaybookGenerator

router = APIRouter()


class CustomPayload(BaseModel):
    url: str | None = None
    command: str | None = None
    name: str | None = None
    executor: str = "powershell"
    technique_id: str = "T0000"


class GeneratePlaybookRequest(BaseModel):
    adversary_group_id: str | None = None
    adversary_group_name: str | None = None
    technique_ids: list[str] | None = None
    name: str | None = None
    platforms: list[str] | None = None
    custom_payloads: list[CustomPayload] | None = None


@router.post("/generate")
async def generate_playbook(
    request: GeneratePlaybookRequest,
    db: AsyncSession = Depends(get_db),
):
    generator = PlaybookGenerator(db)
    playbook = await generator.generate(
        adversary_group_id=request.adversary_group_id,
        adversary_group_name=request.adversary_group_name,
        technique_ids=request.technique_ids,
        name=request.name,
        platforms=request.platforms,
        custom_payloads=[p.model_dump() for p in request.custom_payloads] if request.custom_payloads else None,
    )

    if not playbook:
        return JSONResponse(
            status_code=400,
            content={"error": "No matching tests found for the given criteria"},
        )

    return _serialize_playbook(playbook)


@router.get("")
async def list_playbooks(
    skip: int = 0,
    limit: int = Query(default=50, le=200),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Playbook).order_by(Playbook.created_at.desc()).offset(skip).limit(limit)
    )
    playbooks = result.scalars().all()
    return {"playbooks": [_serialize_playbook_summary(p) for p in playbooks]}


@router.get("/stats")
async def playbook_stats(db: AsyncSession = Depends(get_db)):
    playbook_count = await db.scalar(select(func.count()).select_from(Playbook))
    run_count = await db.scalar(select(func.count()).select_from(PlaybookRun))
    return {"total_playbooks": playbook_count or 0, "total_runs": run_count or 0}


@router.get("/{playbook_id}")
async def get_playbook(playbook_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Playbook).where(Playbook.id == playbook_id)
    )
    playbook = result.scalar_one_or_none()
    if not playbook:
        return JSONResponse(status_code=404, content={"error": "Playbook not found"})

    return _serialize_playbook(playbook)


@router.get("/{playbook_id}/export")
async def export_playbook(playbook_id: str, db: AsyncSession = Depends(get_db)):
    """Export playbook as JSON for the PowerShell agent."""
    generator = PlaybookGenerator(db)
    export = await generator.export_for_agent(playbook_id)
    if not export:
        return JSONResponse(status_code=404, content={"error": "Playbook not found"})
    return export


def _serialize_playbook(p: Playbook) -> dict:
    return {
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "adversary_group_id": p.adversary_group_id,
        "adversary_group_name": p.adversary_group_name,
        "technique_ids": p.technique_ids or [],
        "test_ids": p.test_ids or [],
        "metadata": p.metadata_ or {},
        "created_at": p.created_at.isoformat() if p.created_at else None,
    }


def _serialize_playbook_summary(p: Playbook) -> dict:
    return {
        "id": p.id,
        "name": p.name,
        "adversary_group_name": p.adversary_group_name,
        "technique_count": len(p.technique_ids or []),
        "test_count": len(p.test_ids or []),
        "created_at": p.created_at.isoformat() if p.created_at else None,
    }
