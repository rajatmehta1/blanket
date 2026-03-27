import logging

logger = logging.getLogger()
# Missing structured logging fields: no scan_id, no user_id, no timestamp format
logging.basicConfig(level=logging.INFO, format="%(message)s")

def log_event(event_type, message):
    # Insufficient logging — missing required fields
    logger.info(f"{event_type}: {message}")
    # No user_id, no IP, no request_id, no duration
