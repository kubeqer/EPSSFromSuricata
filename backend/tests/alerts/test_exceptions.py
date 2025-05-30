from src.alerts.exceptions import (
    AlertException,
    AlertNotFoundException,
    InvalidAlertStatusTransition,
    EmailSendingError
)

def test_alert_exception():
    exc = AlertException()
    assert exc.detail == "An error occurred in the Alert module"

def test_alert_not_found_exception():
    exc = AlertNotFoundException()
    assert exc.detail == "Alert not found"
    assert isinstance(exc, AlertException)

def test_invalid_alert_status_transition():
    exc = InvalidAlertStatusTransition()
    assert exc.detail == "Invalid status transition for alert"
    assert isinstance(exc, AlertException)

def test_email_sending_error():
    exc = EmailSendingError()
    assert exc.detail == "Error sending alert email"
    assert isinstance(exc, AlertException)