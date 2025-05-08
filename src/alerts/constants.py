# Alert priority thresholds based on EPSS percentile
EPSS_PRIORITY_THRESHOLDS = {
    "critical": 99.0,  # Top 1% of exploitability
    "high": 95.0,  # Top 5% of exploitability
    "medium": 75.0,  # Top 25% of exploitability
    "low": 0.0,  # Anything else
}

# Email settings
EMAIL_SUBJECT_TEMPLATE = "Security Alert: {alert_count} new Suricata alerts"
EMAIL_PRIORITY_COLORS = {
    "critical": "#ff0000",  # Red
    "high": "#ff7700",  # Orange
    "medium": "#ffcc00",  # Yellow
    "low": "#00cc00",  # Green
}

# Pagination defaults
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100

# WebSocket topics
TOPIC_NEW_ALERT = "new_alert"
TOPIC_ALERT_UPDATE = "alert_update"

# Rate limiting
MAX_REQUESTS_PER_MINUTE = 100
