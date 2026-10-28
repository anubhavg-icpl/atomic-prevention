from sqlalchemy import Column, String, JSON, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from backend.app.db.database import Base


class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String, default="")
    adversary_group_id = Column(String, nullable=True)  # e.g. "G0016"
    adversary_group_name = Column(String, nullable=True)  # e.g. "APT29"
    technique_ids = Column(JSON, default=list)
    test_ids = Column(JSON, default=list)
    metadata_ = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    runs = relationship("PlaybookRun", back_populates="playbook")


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"

    id = Column(String, primary_key=True)
    playbook_id = Column(String, ForeignKey("playbooks.id"), nullable=False)
    hostname = Column(String, default="")
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    summary = Column(JSON, default=dict)  # blocked/detected/allowed/error counts
    platform = Column(String, default="")
    os_version = Column(Text, default="")
    agent_name = Column(String, default="")
    agent_version = Column(String, default="")
    sensor_logs = Column(JSON, default=list)
    debug_logs = Column(JSON, default=list)
    performance = Column(JSON, default=dict)
    uec_match_status = Column(String, default="not_evaluated")
    uec_device_id = Column(String, nullable=True)

    playbook = relationship("Playbook", back_populates="runs")
    results = relationship("TestResult", back_populates="run")
