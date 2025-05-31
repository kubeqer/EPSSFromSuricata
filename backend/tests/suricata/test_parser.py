import pytest
import json
import os
from unittest.mock import patch, mock_open
from datetime import datetime
from src.suricata.parser import SuricataParser
from src.suricata.exceptions import EveFileNotFound, EveFileParsingError

@pytest.fixture
def sample_alert_event():
    return {
        "timestamp": "2023-01-01T12:00:00.123456Z",
        "event_type": "alert",
        "src_ip": "192.168.1.1",
        "src_port": 54321,
        "dest_ip": "10.0.0.1",
        "dest_port": 80,
        "proto": "tcp",
        "alert": {
            "signature": "ET EXPLOIT CVE-2023-1234 Test Exploit",
            "category": "Attempted Administrator Privilege Gain",
            "severity": 1
        }
    }

@pytest.fixture
def sample_http_event():
    return {
        "timestamp": "2023-01-01T12:01:00.123456Z",
        "event_type": "http",
        "src_ip": "192.168.1.2",
        "dest_ip": "10.0.0.2",
        "http": {
            "hostname": "example.com",
            "url": "/wp-admin.php",
            "http_user_agent": "sqlmap/1.6",
            "http_method": "GET",
            "status": 200
        }
    }

def test_get_new_events_file_not_found():
    parser = SuricataParser("/nonexistent/path")
    with pytest.raises(EveFileNotFound):
        list(parser.get_new_events())

@patch("os.path.exists", return_value=True)
@patch("os.path.getsize", return_value=100)
def test_get_new_events_no_new_data(mock_exists, mock_getsize):
    parser = SuricataParser()
    parser._last_position = 100
    assert list(parser.get_new_events()) == []

def test_extract_cves_from_alert(sample_alert_event):
    parser = SuricataParser()
    cves = parser.extract_cves(sample_alert_event)
    assert "CVE-2023-1234" in cves

def test_parse_event(sample_alert_event):
    parser = SuricataParser()
    parsed = parser.parse_event(sample_alert_event)
    assert parsed["event_id"] is not None
    assert parsed["alert_signature"] == "ET EXPLOIT CVE-2023-1234 Test Exploit"
    assert "CVE-2023-1234" in parsed["cves"]