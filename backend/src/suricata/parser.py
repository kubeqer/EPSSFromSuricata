import json
import re
import logging
import os
from datetime import datetime, timezone
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
        self._suspicious_patterns = {
            "shellshock": re.compile(
                r"\(\)\s*\{\s*[^}]*\}\s*;\s*[^;]*;", re.IGNORECASE
            ),
            "path_traversal": re.compile(r"(\.\.+[/\\]|[/\\]\.\.+)"),
            "directory_scanning": re.compile(
                r"(?:^|/)(admin|backup|wp-admin|phpmyadmin|manager|login|dashboard|panel|control|config|\.env|\.git|\.svn)(?:/|\.|\b)",
                re.IGNORECASE,
            ),
            "file_extension_scanning": re.compile(
                r"\.(?:war|tar|zip|gz|sql|jks|cer|pem|dump)(?:\?|$)", re.IGNORECASE
            ),
            "common_exploits": re.compile(
                r"(?:wp-config|phpinfo|wp-content|wp-includes|eval\(|base64_decode|system\()",
                re.IGNORECASE,
            ),
            "sql_injection": re.compile(
                r"(?:union.*select|select.*from|drop\s+table|delete\s+from|or\s+1=1)",
                re.IGNORECASE,
            ),
            "xss_attempt": re.compile(
                r"<script|<img.*onerror|javascript:|eval\(", re.IGNORECASE
            ),
            "suspicious_user_agents": re.compile(
                r"(?:sqlmap|nikto|nmap|w3af|metasploit|curl|wget|python-requests|bot)",
                re.IGNORECASE,
            ),
            "numeric_file_access": re.compile(
                r"^/\d+\.(war|tar|zip|gz|sql|jks|cer|pem|dump)$", re.IGNORECASE
            ),
            "backup_files": re.compile(
                r"(?:backup|dump|archive).*\.(zip|tar|gz|sql|war|tgz)", re.IGNORECASE
            ),
        }
        if os.path.exists(self.eve_path):
            self._last_position = 0
        else:
            logger.warning(f"Eve file not found at {self.eve_path}")

    def get_new_events(self) -> Generator[Dict[str, Any], None, None]:
        """
        Read new events from eve.json since last read
        Returns a generator of new alert events and suspicious HTTP events
        """
        if not os.path.exists(self.eve_path):
            raise EveFileNotFound(f"Eve file not found at {self.eve_path}")

        current_size = os.path.getsize(self.eve_path)
        if current_size < self._last_position:
            logger.info(
                "Eve file appears to have been rotated, starting from beginning"
            )
            self._last_position = 0
        if current_size == self._last_position:
            logger.debug("No new data in eve.json")
            return

        logger.info(
            f"Processing eve.json from position {self._last_position} to {current_size}"
        )

        try:
            processed_events = 0
            suspicious_events = 0

            with open(self.eve_path, "r") as f:
                f.seek(self._last_position)
                for line_num, line in enumerate(f):
                    try:
                        event = json.loads(line.strip())
                        event_type = event.get("event_type")
                        processed_events += 1
                        if event_type == EVENT_TYPE_ALERT:
                            yield event
                        elif event_type == "http":
                            suspicious_event = self._analyze_http_event(event)
                            if suspicious_event:
                                suspicious_events += 1
                                yield suspicious_event

                    except json.JSONDecodeError as e:
                        logger.warning(
                            f"Failed to parse JSON line {line_num}: {line.strip()[:100]}... Error: {e}"
                        )
                    except Exception as e:
                        logger.error(f"Error processing line {line_num}: {e}")
                self._last_position = f.tell()

            logger.info(
                f"Processed {processed_events} events, found {suspicious_events} suspicious HTTP events"
            )

        except Exception as e:
            logger.error(f"Error reading eve.json: {str(e)}")
            raise EveFileParsingError(f"Error reading eve.json: {str(e)}")

    def _analyze_http_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze HTTP event for suspicious patterns
        Returns a synthesized alert event if suspicious activity is detected
        """
        http_data = event.get("http", {})
        fields_to_check = {
            "url": http_data.get("url", ""),
            "http_user_agent": http_data.get("http_user_agent", ""),
            "http_refer": http_data.get("http_refer", ""),
            "http_method": http_data.get("http_method", ""),
            "hostname": http_data.get("hostname", ""),
        }

        detected_threats = []
        for pattern_name, pattern in self._suspicious_patterns.items():
            for field_name, field_value in fields_to_check.items():
                if field_value and pattern.search(str(field_value)):
                    detected_threats.append(
                        f"{pattern_name} in {field_name}: {field_value}"
                    )
        url = fields_to_check.get("url", "")
        status = http_data.get("status", 0)
        if status == 404 and url:
            sensitive_files = [
                ".war",
                ".tar",
                ".zip",
                ".sql",
                ".jks",
                ".cer",
                ".pem",
                "..",
            ]
            if any(pattern in url for pattern in sensitive_files):
                detected_threats.append(f"404_sensitive_file_access: {url}")
        if status == 400 and url:
            if any(
                exploit in url for exploit in ["/etc/shadow", "/etc/passwd", "../../"]
            ):
                detected_threats.append(f"400_exploit_attempt: {url}")
        if detected_threats:
            flow_id = event.get("flow_id", "unknown")
            timestamp = event.get("timestamp", datetime.utcnow().isoformat())
            event_id = f"synthetic-http-{flow_id}-{timestamp.replace(':', '').replace('.', '')}"
            threat_summary = []
            for threat in detected_threats:
                threat_parts = threat.split(": ", 1)
                threat_summary.append(threat_parts[0])

            alert_signature = f"SYNTHETIC: Suspicious HTTP Activity - {', '.join(set(threat_summary))}"
            severity = 3
            if any(
                "shellshock" in threat or "sql_injection" in threat
                for threat in detected_threats
            ):
                severity = 1
            elif any(
                "path_traversal" in threat or "file_extension_scanning" in threat
                for threat in detected_threats
            ):
                severity = 2
            synthetic_alert = {
                "timestamp": timestamp,
                "event_type": "alert",
                "src_ip": event.get("src_ip"),
                "src_port": event.get("src_port"),
                "dest_ip": event.get("dest_ip"),
                "dest_port": event.get("dest_port"),
                "proto": event.get("proto"),
                "flow_id": flow_id,
                "in_iface": event.get("in_iface"),
                "event_id": event_id,
                "alert": {
                    "action": "allowed",
                    "gid": 9999,
                    "signature_id": 999999,
                    "rev": 1,
                    "signature": alert_signature,
                    "category": "Potentially Bad Traffic",
                    "severity": severity,
                    "metadata": {
                        "original_event_type": "http",
                        "detected_patterns": detected_threats,
                        "http_url": http_data.get("url"),
                        "http_user_agent": http_data.get("http_user_agent"),
                        "http_status": http_data.get("status"),
                        "http_method": http_data.get("http_method"),
                        "synthetic_alert": True,
                        "alert_type": "HTTP_SUSPICIOUS_ACTIVITY",
                    },
                },
                "http": http_data,
                "synthetic": True,
            }
            return synthetic_alert
        return None

    def extract_cves(self, event: Dict[str, Any]) -> Set[str]:
        """Extract CVE IDs from an event"""
        cves = set()
        if "alert" in event and "signature" in event["alert"]:
            signature = event["alert"]["signature"]
            cves.update(self._cve_pattern.findall(signature))
        if "http" in event:
            http_data = event["http"]
            if "url" in http_data:
                cves.update(self._cve_pattern.findall(http_data["url"]))
            if "http_user_agent" in http_data:
                cves.update(self._cve_pattern.findall(http_data["http_user_agent"]))
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
        timestamp = event.get("timestamp", datetime.now(timezone.utc).isoformat())
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.utcnow()
        alert_data = event.get("alert", {})
        src_ip = event.get("src_ip", "")
        dest_ip = event.get("dest_ip", "")
        event_id = event.get("event_id")
        if not event_id:
            event_id = f"synthetic-{timestamp.strftime('%Y%m%d%H%M%S')}-{event.get('flow_id', '')}"

        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "src_port": event.get("src_port", 0),
            "dest_ip": dest_ip,
            "dest_port": event.get("dest_port", 0),
            "proto": event.get("proto", ""),
            "alert_signature": alert_data.get("signature", "Unknown Alert"),
            "alert_category": alert_data.get("category", "Unknown"),
            "alert_severity": alert_data.get("severity", 3),
            "cves": list(self.extract_cves(event)),
            "raw_event": event,
            "is_synthetic": event.get("synthetic", False),
        }
