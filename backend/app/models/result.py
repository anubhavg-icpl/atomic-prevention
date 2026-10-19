from sqlalchemy import Column, String, Integer, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from backend.app.db.database import Base


class TestResult(Base):
    __tablename__ = "test_results"

    id = Column(String, primary_key=True)
    run_id = Column(String, ForeignKey("playbook_runs.id"), nullable=False)
    test_id = Column(String, ForeignKey("prevention_tests.id"), nullable=False)
    verdict = Column(String, nullable=False)  # "blocked" | "allowed" | "error"
    exit_code = Column(Integer, nullable=True)
    error_message = Column(String, nullable=True)
    execution_time_ms = Column(Integer, default=0)
    executed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    run = relationship("PlaybookRun", back_populates="results")
    test = relationship("PreventionTest", back_populates="results")
