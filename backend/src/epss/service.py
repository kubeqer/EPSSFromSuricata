import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from sqlalchemy.orm import Session

from src.epss.client import EPSSClient
from src.epss.models import CVEScore
from src.epss.schemas import CVEScoreCreate, CVEScoreUpdate
from src.epss.exceptions import CVEScoreNotFoundException

logger = logging.getLogger(__name__)


class EPSSService:
    """Service for handling EPSS scores"""

    def __init__(self, db: Session, client: Optional[EPSSClient] = None):
        self.db = db
        self.client = client or EPSSClient()

    async def update_scores_for_cves(self, cve_ids: List[str]) -> Dict[str, CVEScore]:
        """
        Update EPSS scores for a list of CVE IDs
        Creates new records or updates existing ones
        Returns a dictionary mapping CVE IDs to CVEScore objects
        """
        if not cve_ids:
            return {}
        scores = await self.client.get_scores(cve_ids)
        result = {}
        for cve_id, (score, percentile) in scores.items():
            db_score = self.db.query(CVEScore).filter_by(cve_id=cve_id).first()

            if db_score:
                update_data = CVEScoreUpdate(
                    epss_score=score,
                    epss_percentile=percentile,
                    last_updated=datetime.utcnow(),
                )

                for key, value in update_data.dict().items():
                    setattr(db_score, key, value)
            else:
                db_score = CVEScore(
                    cve_id=cve_id,
                    epss_score=score,
                    epss_percentile=percentile,
                    last_updated=datetime.now(timezone.utc),
                )
                self.db.add(db_score)

            result[cve_id] = db_score

        self.db.commit()
        for cve_id, score in result.items():
            self.db.refresh(score)

        logger.info(f"Updated EPSS scores for {len(result)} CVEs")
        return result

    def get_score_by_cve_id(self, cve_id: str) -> CVEScore:
        """Get EPSS score by CVE ID"""
        score = self.db.query(CVEScore).filter_by(cve_id=cve_id).first()
        if not score:
            raise CVEScoreNotFoundException(f"EPSS score for {cve_id} not found")
        return score

    def get_scores_by_cve_ids(self, cve_ids: List[str]) -> Dict[str, CVEScore]:
        """Get multiple EPSS scores by CVE IDs"""
        if not cve_ids:
            return {}

        scores = self.db.query(CVEScore).filter(CVEScore.cve_id.in_(cve_ids)).all()
        return {score.cve_id: score for score in scores}

    async def ensure_scores_exist(self, cve_ids: List[str]) -> Dict[str, CVEScore]:
        """
        Ensure EPSS scores exist for all CVE IDs
        Fetches scores for any missing records
        Returns a dictionary mapping CVE IDs to CVEScore objects
        """
        if not cve_ids:
            return {}
        existing_scores = self.get_scores_by_cve_ids(cve_ids)
        missing_cves = [cve_id for cve_id in cve_ids if cve_id not in existing_scores]

        if missing_cves:
            new_scores = await self.update_scores_for_cves(missing_cves)
            existing_scores.update(new_scores)

        return existing_scores
