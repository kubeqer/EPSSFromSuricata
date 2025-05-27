EPSS_PRIORITY_THRESHOLDS = {
    "critical": 99.0,
    "high": 95.0,
    "medium": 75.0,
    "low": 0.0,
}
EMAIL_SUBJECT_TEMPLATE = "Security Alert: {alert_count} new Suricata alerts"
EMAIL_PRIORITY_COLORS = {
    "critical": "#ff0000",  # Red
    "high": "#ff7700",  # Orange
    "medium": "#ffcc00",  # Yellow
    "low": "#00cc00",  # Green
}
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100
TOPIC_NEW_ALERT = "new_alert"
TOPIC_ALERT_UPDATE = "alert_update"
MAX_REQUESTS_PER_MINUTE = 100
