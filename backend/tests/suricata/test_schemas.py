import pytest
from datetime import datetime, timezone
from src.suricata.schemas import (
    CVEBase,
    SuricataEventBase,
    SuricataEventCreate,
    SuricataEventOut,
)


def test_cve_base_schema():
    cve = CVEBase(cve_id="CVE-2023-1234")
    assert cve.cve_id == "CVE-2023-1234"


def test_suricata_event_base_schema():
    event = SuricataEventBase(
        event_id="test123",
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.1",
        src_port=1234,
        dest_ip="10.0.0.1",
        dest_port=80,
        proto="tcp",
        alert_signature="Test Signature",
        alert_category="Test Category",
        alert_severity=1,
    )
    assert event.event_id == "test123"
    assert event.alert_severity == 1


def test_suricata_event_create_schema():
    raw_event = {"test": "data"}
    event = SuricataEventCreate(
        event_id="test456",
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.2",
        dest_ip="10.0.0.2",
        alert_signature="Test with CVE",
        alert_category="Test",
        alert_severity=2,
        src_port=0,
        dest_port=0,
        proto="",
        raw_event=raw_event,
        cves=["CVE-2023-1234"],
    )
    assert event.cves == ["CVE-2023-1234"]
    assert event.raw_event == raw_event
