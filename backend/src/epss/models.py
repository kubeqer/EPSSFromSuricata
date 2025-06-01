from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean, ForeignKey
from sqlalchemy.orm import relationship

from src.database import Base


class CVEScore(Base):
    __tablename__ = "cve_scores"
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, index=True, unique=True)
    epss_score = Column(Float)
    epss_percentile = Column(Float)
    last_updated = Column(DateTime, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<CVEScore(cve_id='{self.cve_id}', score={self.epss_score})>"
