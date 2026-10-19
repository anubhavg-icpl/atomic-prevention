from sqlalchemy import Column, String, JSON
from sqlalchemy.orm import relationship

from backend.app.db.database import Base


class Technique(Base):
    __tablename__ = "techniques"

    id = Column(String, primary_key=True)  # e.g. "T1218.010"
    name = Column(String, nullable=False)
    description = Column(String, default="")
    tactics = Column(JSON, default=list)  # ["stealth", "execution"]
    platforms = Column(JSON, default=list)  # ["windows"]
    sources = Column(JSON, default=list)  # ["lolbas", "atomic-red-team"]
    url = Column(String, default="")

    tests = relationship("PreventionTest", back_populates="technique")
