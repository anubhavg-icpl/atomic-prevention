from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.db.database import get_db


async def get_session(db: AsyncSession = Depends(get_db)):
    return db
