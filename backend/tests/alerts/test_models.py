from datetime import datetime, timezone
from src.alerts.models import Alert, AlertStatus, AlertPriority


def test_alert_model():
    alert = Alert(
        event_id=1,
        cve_id="CVE-2023-1234",
        epss_score=0.5,
        epss_percentile=99.5,
        priority=AlertPriority.CRITICAL,
        status=AlertStatus.NEW,
        created_at=datetime.now(timezone.utc),
    )

    assert alert.event_id == 1
    assert alert.cve_id == "CVE-2023-1234"
    assert alert.epss_score == 0.5
    assert alert.epss_percentile == 99.5
    assert alert.priority == AlertPriority.CRITICAL
    assert alert.status == AlertStatus.NEW
    assert isinstance(alert.created_at, datetime)


def test_alert_repr():
    alert = Alert(id=1, cve_id="CVE-2023-1234", priority=AlertPriority.HIGH)
    assert (
        repr(alert) == "<Alert(id=1, cve='CVE-2023-1234', priority=AlertPriority.HIGH)>"
    )
