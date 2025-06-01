import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.suricata.models import SuricataEvent, SuricataCVE, Base


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_suricata_event_model(db_session):
    event = SuricataEvent(
        event_id="test123",
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.1",
        src_port=1234,
        dest_ip="10.0.0.1",
        dest_port=80,
        proto="tcp",
        alert_signature="Test Signature",
        alert_category="Test Category",
        alert_severity=1,
    )
    db_session.add(event)
    db_session.commit()

    assert event.id is not None
    assert event.event_id == "test123"
    assert "SuricataEvent" in repr(event)


def test_suricata_cve_relationship(db_session):
    event = SuricataEvent(
        event_id="test456",
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.2",
        dest_ip="10.0.0.2",
        dest_port=80,
        proto="tcp",
        alert_signature="Test Signature",
        alert_category="Test Category",
        alert_severity=1,
    )
    cve = SuricataCVE(cve_id="CVE-2023-1234")
    event.cves.append(cve)

    db_session.add(event)
    db_session.commit()

    assert len(event.cves) == 1
    assert event.cves[0].cve_id == "CVE-2023-1234"
    assert "SuricataCVE" in repr(cve)
