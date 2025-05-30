import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from src.alerts.models import AlertStatus, AlertPriority
from src.alerts.schemas import AlertOut, AlertUpdate

def test_get_alerts(client, test_alert):
    response = client.get("/alerts/")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert any(alert["id"] == test_alert.id for alert in data["items"])

def test_get_alert_by_id(client, test_alert):
    response = client.get(f"/alerts/{test_alert.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == test_alert.id
    assert data["cve_id"] == test_alert.cve_id

def test_get_alert_not_found(client):
    response = client.get("/alerts/999")
    assert response.status_code == 404

def test_update_alert(client, test_alert):
    update_data = {
        "status": "acknowledged",
        "notes": "Updated via API"
    }
    response = client.patch(f"/alerts/{test_alert.id}", json=update_data)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "acknowledged"
    assert data["notes"] == "Updated via API"

def test_get_alert_stats(client, test_alert):
    response = client.get("/alerts/stats/summary")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert data["by_status"]["new"] >= 0
    assert data["by_priority"]["critical"] >= 0

@patch('src.alerts.service.AlertService.process_new_events')
def test_process_new_alerts(mock_process, client):
    mock_process.return_value = []
    response = client.post("/alerts/process")
    assert response.status_code == 200
    mock_process.assert_called_once()