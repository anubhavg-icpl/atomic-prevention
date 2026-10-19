import logging
import uuid
from collections import Counter
from hashlib import sha256

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.mitre import get_mitre_client
from backend.app.db.database import get_db
from backend.app.models.technique import Technique
from backend.app.models.test_case import PreventionTest
from backend.app.models.playbook import Playbook
from backend.app.ingestion.registry import get_registry

logger = logging.getLogger(__name__)
router = APIRouter()

# Namespace for deterministic test IDs (enables idempotent re-syncs)
_TEST_ID_NAMESPACE = uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")


def _build_test_ids(source_id: str, tests: list[dict]) -> list[str]:
    """Keep legacy IDs unless their truncated command key collides."""
    base_keys = [
        f"{source_id}:{test['name']}:{test['command'][:200]}"
        for test in tests
    ]
    collisions = Counter(base_keys)
    ids: list[str] = []
    for test, base_key in zip(tests, base_keys):
        identity = base_key
        if collisions[base_key] > 1:
            command_hash = sha256(test["command"].encode("utf-8")).hexdigest()
            identity = f"{base_key}:{command_hash}"
        ids.append(str(uuid.uuid5(_TEST_ID_NAMESPACE, identity)))
    return ids


@router.get("")
async def list_sources(db: AsyncSession = Depends(get_db)):
    registry = get_registry()
    sources = []

    for ingestor in registry.get_all():
        count = await db.scalar(
            select(func.count())
            .select_from(PreventionTest)
            .where(PreventionTest.source == ingestor.source_id)
        )
        sources.append({
            "id": ingestor.source_id,
            "name": ingestor.display_name,
            "description": ingestor.description,
            "repo_url": ingestor.repo_url,
            "platform": ingestor.platform,
            "test_count": count or 0,
        })

    return {"sources": sources}


@router.post("/{source_id}/sync")
async def sync_source(source_id: str, db: AsyncSession = Depends(get_db)):
    registry = get_registry()
    ingestor = registry.get(source_id)

    if not ingestor:
        return JSONResponse(status_code=404, content={"error": f"Source '{source_id}' not found"})

    # Fetch source data (git clone/pull)
    try:
        await ingestor.fetch()
    except RuntimeError as e:
        return JSONResponse(status_code=502, content={"error": f"Failed to fetch source: {e}"})

    # Parse tests from source data
    tests = await ingestor.parse()

    if not tests:
        return {"source": source_id, "tests_persisted": 0, "techniques_updated": 0}

    # Load MITRE data for technique enrichment
    mitre = await get_mitre_client()

    # Collect per-technique platforms from the actual tests
    technique_platforms: dict[str, set[str]] = {}
    for test_dict in tests:
        tid = test_dict.get("technique_id", "")
        if not tid:
            continue
        for p in test_dict.get("platforms", []):
            technique_platforms.setdefault(tid, set()).add(p.lower())

    # Upsert techniques referenced by parsed tests
    technique_ids_seen = set()
    for test_dict in tests:
        tid = test_dict.get("technique_id", "")
        if not tid or tid in technique_ids_seen:
            continue
        technique_ids_seen.add(tid)

        existing = await db.get(Technique, tid)
        tech_info = mitre.get_technique(tid) or {}
        # Merge platforms from MITRE data AND from actual tests
        mitre_platforms = set(p.lower() for p in tech_info.get("platforms", []))
        test_plats = technique_platforms.get(tid, set())
        merged_platforms = sorted(mitre_platforms | test_plats)

        if existing:
            # Update sources list to include this source
            sources_list = existing.sources or []
            if ingestor.source_id not in sources_list:
                existing.sources = sources_list + [ingestor.source_id]
            # Merge platforms from tests into existing technique
            existing_plats = set(p.lower() for p in (existing.platforms or []))
            existing.platforms = sorted(existing_plats | set(merged_platforms))
            # Enrich bare-bones techniques that were previously created without
            # MITRE metadata (name == id means it was never enriched)
            if tech_info and existing.name == existing.id:
                existing.name = tech_info.get("name", existing.name)
                existing.description = tech_info.get("description", "") or existing.description
                existing.tactics = tech_info.get("tactics", []) or existing.tactics
                existing.url = tech_info.get("url", "") or existing.url
        else:
            db.add(Technique(
                id=tid,
                name=tech_info.get("name", tid),
                description=tech_info.get("description", ""),
                tactics=tech_info.get("tactics", []),
                platforms=merged_platforms,
                sources=[ingestor.source_id],
                url=tech_info.get("url", ""),
            ))

    # Build the set of new test IDs, then remove stale tests for this source
    parsed_test_ids = _build_test_ids(ingestor.source_id, tests)
    new_test_ids = set()
    for test_dict, test_id in zip(tests, parsed_test_ids):
        tid = test_dict.get("technique_id", "")
        if not tid:
            continue
        new_test_ids.add(test_id)

    # Delete old tests from this source that are no longer in the parsed set
    if new_test_ids:
        stale_query = (
            delete(PreventionTest)
            .where(PreventionTest.source == ingestor.source_id)
            .where(PreventionTest.id.not_in(new_test_ids))
        )
        stale_result = await db.execute(stale_query)
        stale_count = stale_result.rowcount
        if stale_count:
            logger.info(f"Removed {stale_count} stale tests for {source_id}")

    # Upsert prevention tests
    tests_persisted = 0
    persisted_ids: set[str] = set()
    for test_dict, test_id in zip(tests, parsed_test_ids):
        tid = test_dict.get("technique_id", "")
        if not tid:
            continue

        existing_test = await db.get(PreventionTest, test_id)
        if existing_test:
            # Update mutable fields
            existing_test.command = test_dict["command"]
            existing_test.description = test_dict.get("description", "")
            existing_test.executor = test_dict.get("executor", "cmd")
            existing_test.cleanup_command = test_dict.get("cleanup_command")
            existing_test.elevation_required = test_dict.get("elevation_required", False)
            existing_test.binary_path = test_dict.get("binary_path")
            existing_test.risk_level = test_dict.get("risk_level", "medium")
            existing_test.platforms = test_dict.get("platforms", [])
            existing_test.metadata_ = test_dict.get("metadata", {})
        else:
            db.add(PreventionTest(
                id=test_id,
                technique_id=tid,
                source=ingestor.source_id,
                name=test_dict["name"],
                description=test_dict.get("description", ""),
                command=test_dict["command"],
                executor=test_dict.get("executor", "cmd"),
                cleanup_command=test_dict.get("cleanup_command"),
                elevation_required=test_dict.get("elevation_required", False),
                binary_path=test_dict.get("binary_path"),
                risk_level=test_dict.get("risk_level", "medium"),
                platforms=test_dict.get("platforms", []),
                metadata_=test_dict.get("metadata", {}),
            ))
        persisted_ids.add(test_id)

    tests_persisted = len(persisted_ids)

    # Source updates can legitimately remove or split test IDs. Keep saved
    # playbooks internally consistent instead of exporting references that no
    # longer exist after a sync.
    await db.flush()
    valid_test_rows = await db.execute(
        select(PreventionTest.id, PreventionTest.technique_id)
    )
    technique_by_test_id = {row.id: row.technique_id for row in valid_test_rows}
    playbook_rows = await db.execute(select(Playbook))
    playbooks_repaired = 0
    for playbook in playbook_rows.scalars().all():
        filtered_ids = [
            test_id for test_id in (playbook.test_ids or [])
            if test_id in technique_by_test_id
        ]
        if filtered_ids != (playbook.test_ids or []):
            playbook.test_ids = filtered_ids
            playbook.technique_ids = list(dict.fromkeys(
                technique_by_test_id[test_id] for test_id in filtered_ids
            ))
            playbooks_repaired += 1

    await db.commit()
    logger.info(f"Synced {source_id}: {tests_persisted} tests, {len(technique_ids_seen)} techniques")

    return {
        "source": source_id,
        "tests_persisted": tests_persisted,
        "techniques_updated": len(technique_ids_seen),
        "playbooks_repaired": playbooks_repaired,
    }
