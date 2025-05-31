from datetime import datetime, timezone
from src.alerts.schemas import (
    AlertBase,
    AlertCreate,
    AlertUpdate,
    AlertOut,
    AlertFilter,
    AlertStats
)
from src.alerts.models import AlertStatus, AlertPriority

def test_alert_base_schema():
    data = {
        "cve_id": "CVE-2023-1234",
        "epss_score": 0.5,
        "epss_percentile": 99.5,
        "priority": AlertPriority.CRITICAL
    }
    schema = AlertBase(**data)
    assert schema.cve_id == "CVE-2023-1234"
    assert schema.epss_score == 0.5
    assert schema.epss_percentile == 99.5
    assert schema.priority == AlertPriority.CRITICAL

def test_alert_create_schema():
    data = {
        "event_id": 1,
        "cve_id": "CVE-2023-1234",
        "epss_score": 0.5,
        "epss_percentile": 99.5,
        "priority": AlertPriority.CRITICAL,
        "status": AlertStatus.NEW,
        "notes": "Test note"
    }
    schema = AlertCreate(**data)
    assert schema.event_id == 1
    assert schema.email_sent is False

def test_alert_update_schema():
    data = {
        "status": AlertStatus.ACKNOWLEDGED,
        "notes": "Updated note"
    }
    schema = AlertUpdate(**data)
    assert schema.status == AlertStatus.ACKNOWLEDGED
    assert schema.notes == "Updated note"
    assert schema.priority is None

def test_alert_filter_schema():
    data = {
        "status": [AlertStatus.NEW, AlertStatus.ACKNOWLEDGED],
        "priority": [AlertPriority.CRITICAL],
        "start_date": datetime.now(timezone.utc),
        "is_synthetic": False
    }
    schema = AlertFilter(**data)
    assert len(schema.status) == 2
    assert schema.priority == [AlertPriority.CRITICAL]
    assert schema.is_synthetic is False

def test_alert_stats_schema():
    data = {
        "total": 10,
        "by_status": {AlertStatus.NEW: 5, AlertStatus.ACKNOWLEDGED: 3},
        "by_priority": {AlertPriority.CRITICAL: 2, AlertPriority.HIGH: 4},
        "recent_alerts": 3,
        "synthetic_alerts": 1,
        "cve_alerts": 8
    }
    schema = AlertStats(**data)
    assert schema.total == 10
    assert schema.by_status[AlertStatus.NEW] == 5
    assert schema.recent_alerts == 3