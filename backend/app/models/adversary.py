from sqlalchemy import Column, String, JSON

from backend.app.db.database import Base


class AdversaryGroup(Base):
    __tablename__ = "adversary_groups"

    id = Column(String, primary_key=True)  # e.g. "G0016"
    name = Column(String, nullable=False)  # e.g. "APT29"
    description = Column(String, default="")
    aliases = Column(JSON, default=list)
    technique_ids = Column(JSON, default=list)  # ["T1218", "T1059.001", ...]
    url = Column(String, default="")
