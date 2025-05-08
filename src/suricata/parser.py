import json
import re
import logging
import os
from datetime import datetime
from typing import Dict, List, Set, Generator, Any

from src.config import settings
from src.suricata.constants import EVENT_TYPE_ALERT, CVE_PATTERN
from src.suricata.exceptions import EveFileNotFound, EveFileParsingError

logger = logging.getLogger(__name__)


class SuricataParser:
    """Parser for Suricata eve.json log file"""

    def __init__(self, eve_path: str = None):
        self.eve_path = eve_path or settings.SURICATA_EVE_PATH
        self._last_position = 0
        self._cve_pattern = re.compile(CVE_PATTERN)

        # Initialize last position if file exists
        if os.path.exists(self.eve_path):
            self._last_position = os.path.getsize(self.eve_path)
        else:
            logger.warning(f"Eve file not found at {self.eve_path}")

    def get_new_events(self) -> Generator[Dict[str, Any], None, None]:
        """
        Read new events from eve.json since last read
        Returns a generator of new alert events
        """
        if not os.path.exists(self.eve_path):
            raise EveFileNotFound(f"Eve file not found at {self.eve_path}")

        current_size = os.path.getsize(self.eve_path)

        # If file was rotated (size decreased), start from beginning
        if current_size < self._last_position:
            logger.info(
                "Eve file appears to have been rotated, starting from beginning"
            )
            self._last_position = 0

        # If no new data, return empty generator
        if current_size == self._last_position:
            return

        try:
            with open(self.eve_path, "r") as f:
                f.seek(self._last_position)
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        # Only process alert events
                        if event.get("event_type") == EVENT_TYPE_ALERT:
                            yield event
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse JSON line: {line.strip()}")

                # Update position for next read
                self._last_position = f.tell()
        except Exception as e:
            raise EveFileParsingError(f"Error reading eve.json: {str(e)}")

    def extract_cves(self, event: Dict[str, Any]) -> Set[str]:
        """Extract CVE IDs from an event"""
        cves = set()

        # Check alert signature
        if "alert" in event and "signature" in event["alert"]:
            signature = event["alert"]["signature"]
            cves.update(self._cve_pattern.findall(signature))

        # Check metadata if available
        if "alert" in event and "metadata" in event["alert"]:
            metadata = event["alert"]["metadata"]
            if isinstance(metadata, dict):
                for key, value in metadata.items():
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, str):
                                cves.update(self._cve_pattern.findall(item))
                    elif isinstance(value, str):
                        cves.update(self._cve_pattern.findall(value))

        return cves

    def parse_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a Suricata event into a standardized format"""
        timestamp = event.get("timestamp", datetime.utcnow().isoformat())
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.utcnow()

        alert_data = event.get("alert", {})
        src_ip = event.get("src_ip", "")
        dest_ip = event.get("dest_ip", "")

        return {
            "event_id": event.get("event_id", ""),
            "timestamp": timestamp,
            "src_ip": src_ip,
            "src_port": event.get("src_port", 0),
            "dest_ip": dest_ip,
            "dest_port": event.get("dest_port", 0),
            "proto": event.get("proto", ""),
            "alert_signature": alert_data.get("signature", ""),
            "alert_category": alert_data.get("category", ""),
            "alert_severity": alert_data.get("severity", 3),
            "cves": list(self.extract_cves(event)),
            "raw_event": event,
        }
