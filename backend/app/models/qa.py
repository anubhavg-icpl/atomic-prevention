from sqlalchemy import Column, String, JSON, DateTime, Text
from datetime import datetime, timezone

from backend.app.db.database import Base


class QaAnalysis(Base):
    """Persisted AI/QA result associated with a playbook run."""

    __tablename__ = "qa_analyses"

    id = Column(String, primary_key=True)
    run_id = Column(String, nullable=False, index=True)
    provider = Column(String, default="rules")
    model = Column(String, default="")
    summary = Column(Text, default="")
    result = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class GitlabIssue(Base):
    """Idempotent record of a GitLab issue created from a run."""

    __tablename__ = "gitlab_issues"

    id = Column(String, primary_key=True)
    run_id = Column(String, nullable=False, index=True)
    project_id = Column(String, nullable=False)
    project_path = Column(String, default="")
    iid = Column(String, nullable=False)
    title = Column(String, nullable=False)
    web_url = Column(String, default="")
    created = Column(String, default="created")  # created | existing
    marker = Column(String, nullable=False, unique=True, index=True)
    metadata_ = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
