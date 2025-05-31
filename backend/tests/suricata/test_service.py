import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime
from sqlalchemy.orm import Session
from src.suricata.service import SuricataService
from src.suricata.models import SuricataEvent
from src.suricata.schemas import SuricataEventCreate
from src.suricata.exceptions import EventNotFoundException


@pytest.fixture
def mock_db_session():
    session = MagicMock(spec=Session)
    session.query.return_value.filter.return_value.first.return_value = None
    session.query.return_value.filter.return_value.all.return_value = []
    return session


@pytest.fixture
def sample_event_data():
    return SuricataEventCreate(
        event_id="test123",
        timestamp=datetime.utcnow(),
        src_ip="192.168.1.1",
        src_port=1234,
        dest_ip="10.0.0.1",
        dest_port=80,
        proto="tcp",
        alert_signature="Test Signature",
        alert_category="Test Category",
        alert_severity=1,
        raw_event={"test": "data"},
        cves=["CVE-2023-1234"]
    )

def test_get_event_by_id_not_found(mock_db_session):
    service = SuricataService(mock_db_session)
    with pytest.raises(EventNotFoundException):
        service.get_event_by_id(999)


def test_get_unprocessed_events(mock_db_session):
    # Setup mock to return some unprocessed events
    mock_events = [
        SuricataEvent(id=1, processed=False),
        SuricataEvent(id=2, processed=False)
    ]
    mock_db_session.query.return_value.filter.return_value.all.return_value = mock_events

    service = SuricataService(mock_db_session)
    events = service.get_unprocessed_events()
    assert len(events) == 2
