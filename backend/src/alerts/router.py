from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    BackgroundTasks,
    Query,
)
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

from src.database import get_db
from src.alerts.models import Alert, AlertStatus, AlertPriority
from src.alerts.schemas import AlertOut, AlertUpdate, AlertFilter, AlertStats
from src.alerts.dependencies import get_alert_by_id, get_pagination
from src.alerts.service import AlertService
from src.pagination import PaginationParams, Page

router = APIRouter(prefix="/alerts", tags=["alerts"])

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    BackgroundTasks,
    Query,
    Request,
)
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

from src.database import get_db
from src.alerts.models import Alert, AlertStatus, AlertPriority
from src.alerts.schemas import AlertOut, AlertUpdate, AlertFilter, AlertStats
from src.alerts.dependencies import get_alert_by_id, get_pagination
from src.alerts.service import AlertService
from src.pagination import PaginationParams, Page

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("/", response_model=Page[AlertOut])
async def get_alerts(
        request: Request,
        cve_id: Optional[str] = Query(None, description="Filter by CVE ID"),
        start_date: Optional[datetime] = Query(None, description="Filter by start date"),
        end_date: Optional[datetime] = Query(None, description="Filter by end date"),
        is_synthetic: Optional[bool] = Query(
            None, description="Filter for synthetic alerts"
        ),
        pagination: PaginationParams = Depends(get_pagination),
        db: Session = Depends(get_db),
):
    """Get alerts with filtering and pagination"""

    # Parse query parameters manually to handle both formats: status=resolved and status[]=resolved
    query_params = dict(request.query_params)

    # Handle status parameters
    status_enums = None
    status_values = []

    # Check for status[] format
    for key, value in query_params.items():
        if key.startswith('status[') or key == 'status':
            if isinstance(value, str):
                status_values.append(value)
            elif isinstance(value, list):
                status_values.extend(value)

    # Also check if status appears multiple times in URL
    if 'status' in query_params:
        raw_status = query_params['status']
        if isinstance(raw_status, str):
            status_values.append(raw_status)
        elif isinstance(raw_status, list):
            status_values.extend(raw_status)

    # Convert to enum values
    if status_values:
        status_enums = []
        for s in status_values:
            try:
                status_enums.append(AlertStatus(s))
            except ValueError:
                print(f"Invalid status value: {s}")
                pass

    # Handle priority parameters
    priority_enums = None
    priority_values = []

    # Check for priority[] format
    for key, value in query_params.items():
        if key.startswith('priority[') or key == 'priority':
            if isinstance(value, str):
                priority_values.append(value)
            elif isinstance(value, list):
                priority_values.extend(value)

    # Also check if priority appears multiple times in URL
    if 'priority' in query_params:
        raw_priority = query_params['priority']
        if isinstance(raw_priority, str):
            priority_values.append(raw_priority)
        elif isinstance(raw_priority, list):
            priority_values.extend(raw_priority)

    # Convert to enum values
    if priority_values:
        priority_enums = []
        for p in priority_values:
            try:
                priority_enums.append(AlertPriority(p))
            except ValueError:
                print(f"Invalid priority value: {p}")
                pass

    filter_params = AlertFilter(
        status=status_enums,
        priority=priority_enums,
        cve_id=cve_id,
        start_date=start_date,
        end_date=end_date,
        is_synthetic=is_synthetic,
    )

    service = AlertService(db)
    items, total = service.get_alerts(filter_params, pagination)

    return Page.create(items, total, pagination)


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(alert: Alert = Depends(get_alert_by_id)):
    """Get a specific alert by ID"""
    return alert


@router.patch("/{alert_id}", response_model=AlertOut)
async def update_alert(
        update_data: AlertUpdate, alert_id: int, db: Session = Depends(get_db)
):
    """Update an alert's status, priority or notes"""
    service = AlertService(db)
    updated_alert = service.update_alert(alert_id, update_data)
    return updated_alert


@router.get("/stats/summary", response_model=AlertStats)
async def get_alert_stats(db: Session = Depends(get_db)):
    """Get alert statistics summary"""
    total = db.query(Alert).count()

    by_status = {}
    for status in AlertStatus:
        count = db.query(Alert).filter(Alert.status == status).count()
        by_status[status] = count

    by_priority = {}
    for priority in AlertPriority:
        count = db.query(Alert).filter(Alert.priority == priority).count()
        by_priority[priority] = count

    recent_time = datetime.utcnow() - timedelta(hours=24)
    recent_alerts = db.query(Alert).filter(Alert.created_at >= recent_time).count()

    synthetic_alerts = (
        db.query(Alert)
        .join(Alert.event)
        .filter(text("raw_event::json->>'synthetic' = 'true'"))
        .count()
    )

    cve_alerts = (
        db.query(Alert).filter(Alert.cve_id != "N/A", Alert.cve_id.isnot(None)).count()
    )

    return AlertStats(
        total=total,
        by_status=by_status,
        by_priority=by_priority,
        recent_alerts=recent_alerts,
        synthetic_alerts=synthetic_alerts,
        cve_alerts=cve_alerts,
    )


@router.post("/process", response_model=List[AlertOut])
async def process_new_alerts(
        background_tasks: BackgroundTasks, db: Session = Depends(get_db)
):
    """Manually trigger processing of new Suricata events"""
    service = AlertService(db)
    new_alerts = await service.process_new_events(background_tasks)
    alert_responses = [AlertOut.from_orm(alert) for alert in new_alerts]
    return alert_responses