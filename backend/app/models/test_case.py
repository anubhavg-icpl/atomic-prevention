from sqlalchemy import Column, String, Boolean, ForeignKey, JSON
from sqlalchemy.orm import relationship

from backend.app.db.database import Base


class PreventionTest(Base):
    __tablename__ = "prevention_tests"

    id = Column(String, primary_key=True)  # UUID
    technique_id = Column(String, ForeignKey("techniques.id"), nullable=False)
    source = Column(String, nullable=False)  # "lolbas", "loldrivers", "lolrmm", "atomic-red-team"
    name = Column(String, nullable=False)
    description = Column(String, default="")
    command = Column(String, nullable=False)
    executor = Column(String, default="cmd")  # "cmd" | "powershell" | "bash" | "manual"
    cleanup_command = Column(String, nullable=True)
    elevation_required = Column(Boolean, default=False)
    binary_path = Column(String, nullable=True)
    risk_level = Column(String, default="medium")  # "low" | "medium" | "high"
    platforms = Column(JSON, default=list)  # ["windows"]
    metadata_ = Column("metadata", JSON, default=dict)

    technique = relationship("Technique", back_populates="tests")
    results = relationship("TestResult", back_populates="test")
