from datetime import datetime
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
    Float,
    JSON,
    Boolean,
)
from sqlalchemy.orm import relationship

from src.database import Base


class SuricataEvent(Base):
    __tablename__ = "suricata_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String, index=True, unique=True)
    timestamp = Column(DateTime, index=True)
    src_ip = Column(String, index=True)
    src_port = Column(Integer)
    dest_ip = Column(String, index=True)
    dest_port = Column(Integer)
    proto = Column(String)
    alert_signature = Column(String)
    alert_category = Column(String)
    alert_severity = Column(Integer)
    raw_event = Column(JSON)
    processed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    cves = relationship(
        "SuricataCVE", back_populates="event", cascade="all, delete-orphan"
    )
    alert = relationship("Alert", back_populates="event", uselist=False)

    def __repr__(self):
        return f"<SuricataEvent(id={self.id}, signature='{self.alert_signature}')>"


class SuricataCVE(Base):
    __tablename__ = "suricata_cves"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(
        Integer, ForeignKey("suricata_events.id", ondelete="CASCADE"), index=True
    )
    cve_id = Column(String, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    event = relationship("SuricataEvent", back_populates="cves")

    def __repr__(self):
        return f"<SuricataCVE(id={self.id}, cve_id='{self.cve_id}')>"
