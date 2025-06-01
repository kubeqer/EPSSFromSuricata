from datetime import datetime
from typing import Dict, List, Any
from pydantic import BaseModel


class CVEBase(BaseModel):
    cve_id: str

    class Config:
        from_attributes = True


class SuricataEventBase(BaseModel):
    event_id: str
    timestamp: datetime
    src_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    proto: str
    alert_signature: str
    alert_category: str
    alert_severity: int


class SuricataEventCreate(SuricataEventBase):
    raw_event: Dict[str, Any]
    cves: List[str] = []


class SuricataEventInDB(SuricataEventBase):
    id: int
    raw_event: Dict[str, Any]
    processed: bool
    created_at: datetime

    class Config:
        from_attributes = True


class SuricataEventOut(SuricataEventBase):
    id: int
    cves: List[CVEBase] = []

    class Config:
        from_attributes = True


class SuricataCVEOut(CVEBase):
    id: int
    event_id: int
    created_at: datetime
