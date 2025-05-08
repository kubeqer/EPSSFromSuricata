from src.config import settings

# EPSS API configuration
EPSS_API_URL = settings.EPSS_API_URL
EPSS_OFFLINE_CSV_PATH = settings.EPSS_OFFLINE_CSV_PATH
EPSS_USE_OFFLINE = settings.EPSS_USE_OFFLINE

# API request parameters
EPSS_BATCH_SIZE = 100  # Number of CVEs to request in a single API call
EPSS_REQUEST_TIMEOUT = 30  # Timeout for API requests in seconds

# CSV file columns
EPSS_CSV_CVE_COLUMN = "cve"
EPSS_CSV_SCORE_COLUMN = "epss"
EPSS_CSV_PERCENTILE_COLUMN = "percentile"

# Default values if EPSS data is not available
DEFAULT_EPSS_SCORE = 0.0
DEFAULT_EPSS_PERCENTILE = 0.0

# Cache settings
EPSS_CACHE_TTL = 86400  # 24 hours in seconds
