from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from src.alerts.models import AlertStatus, AlertPriority
from src.suricata.schemas import SuricataEventOut


class AlertBase(BaseModel):
    cve_id: str
    epss_score: float
    epss_percentile: float
    priority: AlertPriority


class AlertCreate(AlertBase):
    event_id: int
    status: AlertStatus = AlertStatus.NEW
    notes: Optional[str] = None
    email_sent: bool = False


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    priority: Optional[AlertPriority] = None
    notes: Optional[str] = None
    email_sent: Optional[bool] = None


class AlertInDB(AlertBase):
    id: int
    event_id: int
    status: AlertStatus
    notes: Optional[str]
    email_sent: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class AlertOut(AlertInDB):
    event: Optional[SuricataEventOut] = None

    # Formatted fields for display
    formatted_epss: str = None
    formatted_percentile: str = None

    class Config:
        orm_mode = True


class AlertFilter(BaseModel):
    status: Optional[List[AlertStatus]] = None
    priority: Optional[List[AlertPriority]] = None
    cve_id: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None


class AlertStats(BaseModel):
    total: int
    by_status: Dict[AlertStatus, int]
    by_priority: Dict[AlertPriority, int]
    recent_alerts: int = Field(..., description="Alerts in the last 24 hours")
