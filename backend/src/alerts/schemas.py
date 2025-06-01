from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, computed_field
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
    http_metadata: Optional[Dict[str, Any]] = None
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
    http_metadata: Optional[Dict[str, Any]]
    email_sent: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AlertOut(AlertInDB):
    event: Optional[SuricataEventOut] = None

    @computed_field
    @property
    def is_synthetic(self) -> bool:
        """Determine if this is a synthetic alert"""
        if not self.event:
            return False
        if hasattr(self.event, "raw_event") and isinstance(self.event.raw_event, dict):
            if self.event.raw_event.get("synthetic", False):
                return True
        if hasattr(self.event, "alert_signature") and self.event.alert_signature:
            if self.event.alert_signature.startswith("SYNTHETIC:"):
                return True
        return False

    @computed_field
    @property
    def detection_type(self) -> str:
        """Determine the detection type based on alert characteristics"""
        if self.is_synthetic:
            return "Synthetic Security Alert"
        else:
            return "Suricata Alert"

    @computed_field
    @property
    def http_details(self) -> Optional[Dict[str, Any]]:
        """Get HTTP details from metadata or raw event"""
        if self.http_metadata:
            return self.http_metadata
        if (
            self.event
            and hasattr(self.event, "raw_event")
            and isinstance(self.event.raw_event, dict)
        ):
            http_data = self.event.raw_event.get("http", {})
            if http_data:
                return {
                    "url": http_data.get("url"),
                    "method": http_data.get("http_method"),
                    "status": http_data.get("status"),
                    "user_agent": http_data.get("http_user_agent"),
                    "hostname": http_data.get("hostname"),
                    "referrer": http_data.get("http_refer"),
                    "content_type": http_data.get("http_content_type"),
                }
        return None

    class Config:
        from_attributes = True


class AlertFilter(BaseModel):
    status: Optional[List[AlertStatus]] = None
    priority: Optional[List[AlertPriority]] = None
    cve_id: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    is_synthetic: Optional[bool] = None


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
