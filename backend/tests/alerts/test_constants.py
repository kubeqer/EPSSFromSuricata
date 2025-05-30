from src.alerts.constants import (
    EPSS_PRIORITY_THRESHOLDS,
    EMAIL_SUBJECT_TEMPLATE,
    EMAIL_PRIORITY_COLORS,
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE
)

def test_epss_priority_thresholds():
    assert EPSS_PRIORITY_THRESHOLDS == {
        "critical": 99.0,
        "high": 95.0,
        "medium": 75.0,
        "low": 0.0
    }

def test_email_subject_template():
    assert EMAIL_SUBJECT_TEMPLATE == "Security Alert: {alert_count} new Suricata alerts"

def test_email_priority_colors():
    assert EMAIL_PRIORITY_COLORS == {
        "critical": "#ff0000",
        "high": "#ff7700",
        "medium": "#ffcc00",
        "low": "#00cc00"
    }

def test_pagination_constants():
    assert DEFAULT_PAGE_SIZE == 50
    assert MAX_PAGE_SIZE == 100