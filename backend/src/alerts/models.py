from datetime import datetime
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Float,
    ForeignKey,
    Enum,
    Text,
    Boolean,
    JSON,
)
from sqlalchemy.orm import relationship
import enum

from src.database import Base


class AlertStatus(enum.Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AlertPriority(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(
        Integer,
        ForeignKey("suricata_events.id", ondelete="CASCADE"),
        unique=True,
        index=True,
    )
    cve_id = Column(String, index=True)
    epss_score = Column(Float)
    epss_percentile = Column(Float)
    priority = Column(Enum(AlertPriority), index=True)
    status = Column(Enum(AlertStatus), default=AlertStatus.NEW, index=True)
    notes = Column(Text, nullable=True)
    http_metadata = Column(JSON, nullable=True)
    email_sent = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    event = relationship("SuricataEvent", back_populates="alert")

    def __repr__(self):
        return f"<Alert(id={self.id}, cve='{self.cve_id}', priority={self.priority})>"
