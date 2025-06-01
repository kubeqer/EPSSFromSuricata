import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient

from src.database import Base, get_db
from src.main import app
from src.alerts.models import Alert, AlertStatus, AlertPriority
from src.suricata.models import SuricataEvent
from src.epss.models import CVEScore

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="module")
def test_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session(test_db):
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    yield session
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    from fastapi.testclient import TestClient
    from src.main import app
    from src.alerts.router import router  # Add this import

    # Include the router if not already done
    app.include_router(router)

    def override_get_db():
        try:
            yield db_session
        finally:
            db_session.close()

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def test_event(db_session):
    event = SuricataEvent(
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.1",
        dest_ip="10.0.0.1",
        alert_signature="ET EXPLOIT Test Exploit",
        alert_severity=1,
        raw_event={"test": "data"},
    )
    db_session.add(event)
    db_session.commit()
    return event


@pytest.fixture
def test_cve_score(db_session):
    score = CVEScore(
        cve="CVE-2023-1234",
        epss=0.5,
        percentile=99.5,
        date=ddatetime.now(timezone.utc).date(),
    )
    db_session.add(score)
    db_session.commit()
    return score


@pytest.fixture
def test_alert(db_session, test_event):
    alert = Alert(
        event_id=test_event.id,
        cve_id="CVE-2023-1234",
        epss_score=0.5,
        epss_percentile=99.5,
        priority=AlertPriority.CRITICAL,
        status=AlertStatus.NEW,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(alert)
    db_session.commit()
    return alert
