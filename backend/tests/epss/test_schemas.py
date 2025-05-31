from datetime import datetime
from src.epss.schemas import (
    CVEScoreBase,
    CVEScoreCreate,
    CVEScoreUpdate,
    CVEScoreInDB,
    CVEScoreOut
)

def test_cve_score_base():
    data = {
        "cve_id": "CVE-2023-1234",
        "epss_score": 0.5,
        "epss_percentile": 99.5
    }
    score = CVEScoreBase(**data)
    assert score.cve_id == "CVE-2023-1234"
    assert score.epss_score == 0.5
    assert score.epss_percentile == 99.5
