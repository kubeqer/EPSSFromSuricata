import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.epss.models import CVEScore, Base

@pytest.fixture
def test_cve_score():
    return CVEScore(
        cve_id="CVE-2023-1234",
        epss_score=0.5,
        epss_percentile=99.5,
        last_updated=datetime.now(timezone.utc)
    )

@pytest.fixture(scope="module")
def db_engine():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)

@pytest.fixture
def db_session(db_engine):
    connection = db_engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection)
    session = Session()
    yield session
    session.close()
    transaction.rollback()
    connection.close()

@pytest.fixture
def mock_epss_client():
    client = MagicMock()
    client.get_scores = AsyncMock()
    return client