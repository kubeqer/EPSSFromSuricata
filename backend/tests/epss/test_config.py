from src.epss.config import (
    EPSS_API_URL,
    EPSS_OFFLINE_CSV_PATH,
    EPSS_USE_OFFLINE,
    EPSS_BATCH_SIZE,
    EPSS_REQUEST_TIMEOUT,
    EPSS_CSV_CVE_COLUMN,
    EPSS_CSV_SCORE_COLUMN,
    EPSS_CSV_PERCENTILE_COLUMN,
    DEFAULT_EPSS_SCORE,
    DEFAULT_EPSS_PERCENTILE,
    EPSS_CACHE_TTL
)

def test_config_values():
    assert isinstance(EPSS_API_URL, str)
    assert isinstance(EPSS_OFFLINE_CSV_PATH, (str, type(None)))
    assert isinstance(EPSS_USE_OFFLINE, bool)
    assert isinstance(EPSS_BATCH_SIZE, int)
    assert isinstance(EPSS_REQUEST_TIMEOUT, int)
    assert EPSS_CSV_CVE_COLUMN == "cve"
    assert EPSS_CSV_SCORE_COLUMN == "epss"
    assert EPSS_CSV_PERCENTILE_COLUMN == "percentile"
    assert DEFAULT_EPSS_SCORE == 0.0
    assert DEFAULT_EPSS_PERCENTILE == 0.0
    assert isinstance(EPSS_CACHE_TTL, int)