from src.exceptions import BaseAppException, NotFoundException


class EPSSException(BaseAppException):
    """Base exception for EPSS module"""

    detail = "An error occurred in the EPSS module"


class EPSSAPIException(EPSSException):
    """Exception for EPSS API errors"""

    detail = "Error communicating with EPSS API"


class EPSSOfflineFileNotFound(EPSSException):
    """Exception for when offline EPSS data file is not found"""

    detail = "EPSS offline data file not found"


class EPSSOfflineParsingError(EPSSException):
    """Exception for errors when parsing offline EPSS data"""

    detail = "Error parsing EPSS offline data file"


class CVEScoreNotFoundException(NotFoundException):
    """Exception for when a CVE score is not found"""

    detail = "CVE score not found"
