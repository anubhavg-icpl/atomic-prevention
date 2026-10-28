from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import inspect, text

from backend.app.core.config import settings

engine = create_async_engine(settings.database_url, echo=settings.debug)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with async_session() as session:
        yield session


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _apply_lightweight_migrations(conn)


async def _apply_lightweight_migrations(conn) -> None:
    """Apply additive column migrations for existing SQLite deployments.

    ``create_all`` does not alter existing tables. The production image uses a
    persistent SQLite volume, so additive columns introduced after the first
    deployment must be added here. Only nullable/add-default columns are
    supported; destructive schema changes require a real migration tool.
    """
    additions = {
        "test_results": {
            "stdout": "TEXT",
            "stderr": "TEXT",
            "agent_logs": "JSON",
            "execution_completed_at": "DATETIME",
            "uec_match_status": "VARCHAR",
            "uec_matches": "JSON",
        },
        "playbook_runs": {
            "platform": "VARCHAR",
            "os_version": "TEXT",
            "agent_name": "VARCHAR",
            "agent_version": "VARCHAR",
            "sensor_logs": "JSON",
            "debug_logs": "JSON",
            "performance": "JSON",
            "uec_match_status": "VARCHAR",
            "uec_device_id": "VARCHAR",
        },
        "gitlab_issues": {
            "marker": "VARCHAR",
        },
    }

    def _missing_columns(connection) -> dict[str, set[str]]:
        inspector = inspect(connection)
        return {
            table: {column["name"] for column in inspector.get_columns(table)}
            for table in additions
            if inspector.has_table(table)
        }

    existing = await conn.run_sync(_missing_columns)
    for table, columns in additions.items():
        if table not in existing:
            continue
        existing_columns = existing.get(table, set())
        for column, ddl in columns.items():
            if column not in existing_columns:
                await conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {column} {ddl}'))
