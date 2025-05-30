import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from src.alerts.dependencies import (
    get_alert_by_id,
    get_pagination,
    validate_status_transition
)
from src.alerts.models import AlertStatus
from src.alerts.exceptions import AlertNotFoundException


def test_get_alert_by_id(db_session, test_alert):
    alert = get_alert_by_id(test_alert.id, db_session)
    assert alert.id == test_alert.id
    assert alert.event_id == test_alert.event_id


def test_get_alert_by_id_not_found(db_session):
    with pytest.raises(AlertNotFoundException):
        get_alert_by_id(999, db_session)


def test_get_pagination():
    pagination = get_pagination(page=2, limit=20)
    assert pagination.page == 2
    assert pagination.limit == 20


def test_validate_status_transition():
    # Valid transitions
    assert validate_status_transition(AlertStatus.NEW, AlertStatus.ACKNOWLEDGED)
    assert validate_status_transition(AlertStatus.NEW, AlertStatus.IN_PROGRESS)
    assert validate_status_transition(AlertStatus.ACKNOWLEDGED, AlertStatus.IN_PROGRESS)
    assert validate_status_transition(AlertStatus.IN_PROGRESS, AlertStatus.RESOLVED)

    # Invalid transitions
    assert not validate_status_transition(AlertStatus.RESOLVED, AlertStatus.NEW)
    assert not validate_status_transition(AlertStatus.FALSE_POSITIVE, AlertStatus.ACKNOWLEDGED)

    # Same status
    assert validate_status_transition(AlertStatus.NEW, AlertStatus.NEW)