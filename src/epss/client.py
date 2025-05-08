import csv
import httpx
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from src.epss.config import (
    EPSS_API_URL,
    EPSS_OFFLINE_CSV_PATH,
    EPSS_USE_OFFLINE,
    EPSS_REQUEST_TIMEOUT,
    EPSS_CSV_CVE_COLUMN,
    EPSS_CSV_SCORE_COLUMN,
    EPSS_CSV_PERCENTILE_COLUMN,
    DEFAULT_EPSS_SCORE,
    DEFAULT_EPSS_PERCENTILE,
)
from src.epss.exceptions import (
    EPSSAPIException,
    EPSSOfflineFileNotFound,
    EPSSOfflineParsingError,
)

logger = logging.getLogger(__name__)


class EPSSClient:
    """Client for fetching EPSS (Exploit Prediction Scoring System) data"""

    def __init__(self):
        self.api_url = EPSS_API_URL
        self.offline_path = EPSS_OFFLINE_CSV_PATH
        self.use_offline = EPSS_USE_OFFLINE

    async def get_scores(self, cve_ids: List[str]) -> Dict[str, Tuple[float, float]]:
        """
        Get EPSS scores for a list of CVE IDs
        Returns a dictionary mapping CVE IDs to (score, percentile) tuples
        """
        if not cve_ids:
            return {}

        if self.use_offline:
            return self._get_scores_offline(cve_ids)
        else:
            return await self._get_scores_api(cve_ids)

    async def _get_scores_api(
        self, cve_ids: List[str]
    ) -> Dict[str, Tuple[float, float]]:
        """Get EPSS scores from the API"""
        result = {}

        try:
            cve_param = ",".join(cve_ids)

            async with httpx.AsyncClient() as client:
                response = await client.get(
                    self.api_url,
                    params={"cve": cve_param},
                    timeout=EPSS_REQUEST_TIMEOUT,
                )

                if response.status_code != 200:
                    logger.error(
                        f"EPSS API error: {response.status_code} - {response.text}"
                    )
                    raise EPSSAPIException(
                        f"EPSS API returned status {response.status_code}"
                    )

                data = response.json()
                for item in data.get("data", []):
                    cve_id = item.get("cve")
                    if cve_id:
                        score = float(item.get("epss", DEFAULT_EPSS_SCORE))
                        percentile = float(
                            item.get("percentile", DEFAULT_EPSS_PERCENTILE)
                        )
                        result[cve_id] = (score, percentile)
                for cve_id in cve_ids:
                    if cve_id not in result:
                        result[cve_id] = (DEFAULT_EPSS_SCORE, DEFAULT_EPSS_PERCENTILE)
                        logger.warning(
                            f"No EPSS data found for {cve_id}, using defaults"
                        )

        except (httpx.RequestError, httpx.TimeoutException) as e:
            logger.error(f"EPSS API connection error: {str(e)}")
            raise EPSSAPIException(f"Error connecting to EPSS API: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error querying EPSS API: {str(e)}")
            raise EPSSAPIException(f"Error processing EPSS API response: {str(e)}")

        return result

    def _get_scores_offline(self, cve_ids: List[str]) -> Dict[str, Tuple[float, float]]:
        """Get EPSS scores from offline CSV file"""
        result = {}

        if not self.offline_path or not os.path.exists(self.offline_path):
            logger.error(f"EPSS offline file not found: {self.offline_path}")
            raise EPSSOfflineFileNotFound()

        try:
            cve_set = set(cve_ids)

            with open(self.offline_path, "r", newline="") as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    cve_id = row.get(EPSS_CSV_CVE_COLUMN)
                    if not cve_id or cve_id not in cve_set:
                        continue

                    try:
                        score = float(
                            row.get(EPSS_CSV_SCORE_COLUMN, DEFAULT_EPSS_SCORE)
                        )
                        percentile = float(
                            row.get(EPSS_CSV_PERCENTILE_COLUMN, DEFAULT_EPSS_PERCENTILE)
                        )
                        result[cve_id] = (score, percentile)
                    except (ValueError, TypeError) as e:
                        logger.warning(
                            f"Error parsing EPSS data for {cve_id}: {str(e)}"
                        )
            for cve_id in cve_ids:
                if cve_id not in result:
                    result[cve_id] = (DEFAULT_EPSS_SCORE, DEFAULT_EPSS_PERCENTILE)
                    logger.warning(
                        f"No EPSS data found for {cve_id} in offline file, using defaults"
                    )

        except Exception as e:
            logger.error(f"Error reading EPSS offline file: {str(e)}")
            raise EPSSOfflineParsingError(f"Error parsing EPSS offline file: {str(e)}")
