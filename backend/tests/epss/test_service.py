import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock
from sqlalchemy.orm import Session

from src.epss.service import EPSSService
from src.epss.models import CVEScore
from src.epss.exceptions import CVEScoreNotFoundException

@pytest.mark.asyncio
async def test_update_scores_for_cves(db_session: Session, mock_epss_client):
    mock_epss_client.get_scores.return_value = {
        "CVE-2023-1234": (0.5, 99.5),
        "CVE-2023-5678": (0.2, 85.0)
    }

    service = EPSSService(db_session, mock_epss_client)
    result = await service.update_scores_for_cves(["CVE-2023-1234", "CVE-2023-5678"])

    assert len(result) == 2
    assert "CVE-2023-1234" in result
    assert "CVE-2023-5678" in result
    assert db_session.query(CVEScore).count() == 2

@pytest.mark.asyncio
async def test_ensure_scores_exist(db_session: Session, mock_epss_client):
    # Add an existing score
    existing_score = CVEScore(
        cve_id="CVE-2023-1234",
        epss_score=0.1,
        epss_percentile=50.0,
        last_updated=datetime.now(timezone.utc)
    )
    db_session.add(existing_score)
    db_session.commit()

    mock_epss_client.get_scores.return_value = {
        "CVE-2023-5678": (0.2, 85.0)
    }

    service = EPSSService(db_session, mock_epss_client)
    result = await service.ensure_scores_exist(["CVE-2023-1234", "CVE-2023-5678"])

    assert len(result) == 2
    assert result["CVE-2023-1234"].epss_score == 0.1  # Existing score
    assert result["CVE-2023-5678"].epss_score == 0.2  # New score

def test_get_score_by_cve_id(db_session: Session):
    score = CVEScore(
        cve_id="CVE-2023-1234",
        epss_score=0.5,
        epss_percentile=99.5,
        last_updated=datetime.now(timezone.utc)
    )
    db_session.add(score)
    db_session.commit()

    service = EPSSService(db_session)
    result = service.get_score_by_cve_id("CVE-2023-1234")
    assert result.cve_id == "CVE-2023-1234"

    with pytest.raises(CVEScoreNotFoundException):
        service.get_score_by_cve_id("CVE-2023-9999")

def test_get_scores_by_cve_ids(db_session: Session):
    score1 = CVEScore(cve_id="CVE-2023-1234", epss_score=0.5, last_updated=datetime.now(timezone.utc))
    score2 = CVEScore(cve_id="CVE-2023-5678", epss_score=0.2, last_updated=datetime.now(timezone.utc))
    db_session.add_all([score1, score2])
    db_session.commit()

    service = EPSSService(db_session)
    result = service.get_scores_by_cve_ids(["CVE-2023-1234", "CVE-2023-5678", "CVE-2023-9999"])
    assert len(result) == 2
    assert "CVE-2023-1234" in result
    assert "CVE-2023-5678" in result
    assert "CVE-2023-9999" not in result