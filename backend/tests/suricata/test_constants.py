import pytest
from src.suricata.constants import (
    EVENT_TYPE_ALERT,
    SEVERITY_HIGH,
    SEVERITY_NAMES,
    CVE_PATTERN,
    EVE_JSON_DEFAULT_PATH
)

def test_event_type_constants():
    assert EVENT_TYPE_ALERT == "alert"

def test_severity_constants():
    assert SEVERITY_HIGH == 1
    assert SEVERITY_NAMES[SEVERITY_HIGH] == "High"

def test_cve_pattern():
    assert CVE_PATTERN == r"CVE-\d{4}-\d{4,}"

def test_default_eve_path():
    assert EVE_JSON_DEFAULT_PATH == "/var/log/suricata/eve.json"