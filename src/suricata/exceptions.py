from src.exceptions import BaseAppException, NotFoundException


class SuricataException(BaseAppException):
    """Base exception for Suricata module"""

    detail = "An error occurred in the Suricata module"


class EveFileNotFound(SuricataException):
    """Exception for when eve.json file is not found"""

    detail = "Suricata eve.json file not found"


class EveFileParsingError(SuricataException):
    """Exception for errors when parsing eve.json"""

    detail = "Error parsing Suricata eve.json file"


class EventNotFoundException(NotFoundException):
    """Exception for when a Suricata event is not found"""

    detail = "Suricata event not found"
