from fastapi import Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import Optional

from src.database import get_db
from src.alerts.models import Alert, AlertStatus
from src.alerts.exceptions import AlertNotFoundException
from src.pagination import PaginationParams


def get_alert_by_id(alert_id: int, db: Session = Depends(get_db)) -> Alert:
    """Dependency to get an alert by ID"""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        raise AlertNotFoundException(f"Alert with ID {alert_id} not found")
    return alert


def get_pagination(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=100, description="Items per page"),
) -> PaginationParams:
    """Dependency for pagination parameters"""
    return PaginationParams(page=page, limit=limit)


def validate_status_transition(
    current_status: AlertStatus, new_status: AlertStatus
) -> bool:
    """
    Validate if a status transition is allowed
    Returns True if valid, False otherwise

    Allowed transitions:
    - NEW -> any status
    - ACKNOWLEDGED -> IN_PROGRESS, RESOLVED, FALSE_POSITIVE
    - IN_PROGRESS -> RESOLVED, FALSE_POSITIVE
    - RESOLVED, FALSE_POSITIVE -> (no transitions allowed)
    """
    if current_status == new_status:
        return True
    allowed_transitions = {
        AlertStatus.NEW: [
            AlertStatus.ACKNOWLEDGED,
            AlertStatus.IN_PROGRESS,
            AlertStatus.RESOLVED,
            AlertStatus.FALSE_POSITIVE,
        ],
        AlertStatus.ACKNOWLEDGED: [
            AlertStatus.IN_PROGRESS,
            AlertStatus.RESOLVED,
            AlertStatus.FALSE_POSITIVE,
        ],
        AlertStatus.IN_PROGRESS: [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE],
        AlertStatus.RESOLVED: [],
        AlertStatus.FALSE_POSITIVE: [],
    }

    return new_status in allowed_transitions.get(current_status, [])
