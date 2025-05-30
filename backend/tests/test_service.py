import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
from fastapi import BackgroundTasks

from src.alerts.service import AlertService
from src.alerts.models import Alert, AlertStatus, AlertPriority
from src.alerts.schemas import AlertCreate, AlertUpdate
from src.alerts.exceptions import (
    AlertNotFoundException,
    InvalidAlertStatusTransition
)
from src.suricata.models import SuricataEvent
from src.epss.models import CVEScore


def test_create_alert(db_session, test_event):
    service = AlertService(db_session)
    alert_data = AlertCreate(
        event_id=test_event.id,
        cve_id="CVE-2023-1234",
        epss_score=0.5,
        epss_percentile=99.5,
        priority=AlertPriority.CRITICAL
    )

    alert = service.create_alert(alert_data)
    assert alert.id is not None
    assert alert.event_id == test_event.id
    assert alert.cve_id == "CVE-2023-1234"
    assert alert.priority == AlertPriority.CRITICAL
    assert alert.status == AlertStatus.NEW


def test_get_alert_by_id(db_session, test_alert):
    service = AlertService(db_session)
    alert = service.get_alert_by_id(test_alert.id)
    assert alert.id == test_alert.id


def test_get_alert_by_id_not_found(db_session):
    service = AlertService(db_session)
    with pytest.raises(AlertNotFoundException):
        service.get_alert_by_id(999)


def test_update_alert(db_session, test_alert):
    service = AlertService(db_session)
    update_data = AlertUpdate(
        status=AlertStatus.ACKNOWLEDGED,
        notes="Updated note"
    )

    updated_alert = service.update_alert(test_alert.id, update_data)
    assert updated_alert.status == AlertStatus.ACKNOWLEDGED
    assert updated_alert.notes == "Updated note"


def test_invalid_status_transition(db_session, test_alert):
    service = AlertService(db_session)
    # First update to ACKNOWLEDGED
    service.update_alert(test_alert.id, AlertUpdate(status=AlertStatus.ACKNOWLEDGED))

    # Then try invalid transition back to NEW
    with pytest.raises(InvalidAlertStatusTransition):
        service.update_alert(test_alert.id, AlertUpdate(status=AlertStatus.NEW))


@patch('src.alerts.service.EPSSService')
@patch('src.alerts.service.SuricataService')
def test_process_new_events(mock_suricata, mock_epss, db_session):
    # Setup mocks
    mock_suricata_instance = mock_suricata.return_value
    mock_epss_instance = mock_epss.return_value

    # Create test event
    test_event = SuricataEvent(
        timestamp=datetime.utcnow(),
        src_ip="192.168.1.1",
        dest_ip="10.0.0.1",
        alert_signature="ET EXPLOIT Test Exploit",
        alert_severity=1,
        raw_event={"test": "data"}
    )
    db_session.add(test_event)
    db_session.commit()

    # Configure mocks
    mock_suricata_instance.process_new_events.return_value = [test_event]
    mock_epss_instance.ensure_scores_exist.return_value = {
        "CVE-2023-1234": MagicMock(epss_score=0.5, epss_percentile=99.5)
    }

    # Test
    service = AlertService(db_session)
    alerts = service.process_new_events(BackgroundTasks())

    assert len(alerts) == 1
    assert alerts[0].cve_id == "CVE-2023-1234"
    assert alerts[0].priority == AlertPriority.CRITICAL


def test_determine_priority():
    service = AlertService(None)

    # Test EPSS-based priorities
    assert service._determine_priority(99.5) == AlertPriority.CRITICAL
    assert service._determine_priority(96.0) == AlertPriority.HIGH
    assert service._determine_priority(80.0) == AlertPriority.MEDIUM
    assert service._determine_priority(50.0) == AlertPriority.LOW

    # Test severity-based priorities
    assert service._determine_priority_from_severity(1) == AlertPriority.HIGH
    assert service._determine_priority_from_severity(2) == AlertPriority.MEDIUM
    assert service._determine_priority_from_severity(3) == AlertPriority.LOW