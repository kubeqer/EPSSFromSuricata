from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    WebSocket,
    WebSocketDisconnect,
    BackgroundTasks,
    Query,
)
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Dict, List, Optional, Set, Any
from datetime import datetime, timedelta

from src.database import get_db
from src.alerts.models import Alert, AlertStatus, AlertPriority
from src.alerts.schemas import AlertOut, AlertUpdate, AlertFilter, AlertStats
from src.alerts.dependencies import get_alert_by_id, get_pagination
from src.alerts.service import AlertService
from src.alerts.constants import TOPIC_NEW_ALERT, TOPIC_ALERT_UPDATE
from src.pagination import PaginationParams, Page

router = APIRouter(prefix="/alerts", tags=["alerts"])

active_connections: Set[WebSocket] = set()


@router.get("/", response_model=Page[AlertOut])
async def get_alerts(
    status: Optional[List[AlertStatus]] = Query(None),
    priority: Optional[List[AlertPriority]] = Query(None),
    cve_id: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    is_synthetic: Optional[bool] = Query(
        None, description="Filter for synthetic alerts"
    ),
    pagination: PaginationParams = Depends(get_pagination),
    db: Session = Depends(get_db),
):
    """Get alerts with filtering and pagination"""
    filter_params = AlertFilter(
        status=status,
        priority=priority,
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
    await broadcast_update(
        TOPIC_ALERT_UPDATE,
        {"alert_id": alert_id, "data": AlertOut.from_orm(updated_alert).dict()},
    )

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
    for alert in alert_responses:
        await broadcast_update(
            TOPIC_NEW_ALERT, {"alert_id": alert.id, "data": alert.dict()}
        )

    return alert_responses


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time alert updates"""
    await websocket.accept()
    active_connections.add(websocket)

    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)


async def broadcast_update(topic: str, data: Dict[str, Any]):
    """Send update to all connected WebSocket clients"""
    message = {"topic": topic, "timestamp": datetime.utcnow().isoformat(), "data": data}

    for connection in active_connections:
        await connection.send_json(message)
