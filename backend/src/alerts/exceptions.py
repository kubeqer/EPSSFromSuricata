from src.exceptions import BaseAppException, NotFoundException


class AlertException(BaseAppException):
    """Base exception for Alert module"""

    detail = "An error occurred in the Alert module"


class AlertNotFoundException(NotFoundException):
    """Exception for when an alert is not found"""

    detail = "Alert not found"


class InvalidAlertStatusTransition(AlertException):
    """Exception for invalid alert status transitions"""

    detail = "Invalid status transition for alert"


class EmailSendingError(AlertException):
    """Exception for errors when sending alert emails"""

    detail = "Error sending alert email"
