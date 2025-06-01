import pytest
from src.suricata.exceptions import (
    SuricataException,
    EveFileNotFound,
    EveFileParsingError,
    EventNotFoundException,
)
from src.exceptions import NotFoundException


def test_suricata_exception_inheritance():
    assert issubclass(SuricataException, BaseException)


def test_event_not_found_inheritance():
    assert issubclass(EventNotFoundException, NotFoundException)
