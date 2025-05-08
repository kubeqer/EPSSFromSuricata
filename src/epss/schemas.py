from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, validator


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
        orm_mode = True


class CVEScoreOut(CVEScoreBase):
    id: int
    last_updated: datetime

    # Format percentile as string with % for display
    formatted_percentile: str = None

    @validator("formatted_percentile", always=True)
    def set_formatted_percentile(cls, v, values):
        percentile = values.get("epss_percentile", 0)
        return f"{percentile:.2f}%"

    class Config:
        orm_mode = True
