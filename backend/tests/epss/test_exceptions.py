from src.epss.exceptions import (
    EPSSException,
    EPSSAPIException,
    EPSSOfflineFileNotFound,
    EPSSOfflineParsingError,
    CVEScoreNotFoundException,
)


def test_epss_exception():
    exc = EPSSException()
    assert exc.detail == "An error occurred in the EPSS module"


def test_epss_api_exception():
    exc = EPSSAPIException()
    assert exc.detail == "Error communicating with EPSS API"
    assert isinstance(exc, EPSSException)


def test_epss_offline_file_not_found():
    exc = EPSSOfflineFileNotFound()
    assert exc.detail == "EPSS offline data file not found"
    assert isinstance(exc, EPSSException)


def test_epss_offline_parsing_error():
    exc = EPSSOfflineParsingError()
    assert exc.detail == "Error parsing EPSS offline data file"
    assert isinstance(exc, EPSSException)
