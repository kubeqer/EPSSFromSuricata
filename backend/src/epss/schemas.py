from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class CVEScoreBase(BaseModel):
    cve_id: str
    epss_score: float = Field(..., description="Raw EPSS score (0-1)")
    epss_percentile: float = Field(..., description="EPSS percentile (0-100)")


class CVEScoreCreate(CVEScoreBase):
    pass


class CVEScoreUpdate(BaseModel):
    epss_score: float
    epss_percentile: float
    last_updated: datetime


class CVEScoreInDB(CVEScoreBase):
    id: int
    last_updated: datetime
    created_at: datetime

    class Config:
        from_attributes = True


class CVEScoreOut(CVEScoreBase):
    id: int
    last_updated: datetime
    formatted_percentile: str = "0.00%"

    @field_validator("formatted_percentile", mode="after")
    @classmethod
    def set_formatted_percentile(cls, v, info):
        values = info.data
        percentile = values.get("epss_percentile", 0)
        if percentile is None:
            return "0.00%"
        return f"{percentile:.2f}%"

    class Config:
        from_attributes = True
