from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator

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
        from_attributes = True


class AlertOut(AlertInDB):
    event: Optional[SuricataEventOut] = None
    is_synthetic: bool = False
    detection_type: str = "Suricata Alert"

    @field_validator("is_synthetic", mode="after")
    @classmethod
    def set_is_synthetic(cls, v, info):
        values = info.data
        event = values.get("event")
        if event and hasattr(event, "raw_event") and isinstance(event.raw_event, dict):
            return event.raw_event.get("synthetic", False)
        return False

    @field_validator("detection_type", mode="after")
    @classmethod
    def set_detection_type(cls, v, info):
        values = info.data
        event = values.get("event")
        cve_id = values.get("cve_id", "")

        if event and hasattr(event, "raw_event") and isinstance(event.raw_event, dict):
            if event.raw_event.get("synthetic", False):
                return "Synthetic Security Alert"
            elif cve_id == "N/A":
                return "Security Alert (No CVE)"
            else:
                return "Suricata Alert"
        return "Suricata Alert"

    class Config:
        from_attributes = True


class AlertFilter(BaseModel):
    status: Optional[List[AlertStatus]] = None
    priority: Optional[List[AlertPriority]] = None
    cve_id: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    is_synthetic: Optional[bool] = None  # New filter for synthetic alerts


class AlertStats(BaseModel):
    total: int
    by_status: Dict[AlertStatus, int]
    by_priority: Dict[AlertPriority, int]
    recent_alerts: int = Field(..., description="Alerts in the last 24 hours")
    synthetic_alerts: int = Field(..., description="Number of synthetic alerts")
    cve_alerts: int = Field(..., description="Number of alerts with CVEs")


class AlertSummary(BaseModel):
    """Summary information about an alert for dashboard display"""

    id: int
    priority: AlertPriority
    status: AlertStatus
    alert_signature: str
    cve_id: Optional[str]
    epss_percentile: Optional[float]
    src_ip: str
    dest_ip: str
    timestamp: datetime
    is_synthetic: bool

    class Config:
        from_attributes = True
