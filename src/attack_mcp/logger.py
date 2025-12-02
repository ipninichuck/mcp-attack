import logging
import json
import sys
from datetime import datetime

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
        }
        # Include extra fields if passed (e.g., user_id, tool_name)
        if hasattr(record, "props"):
            log_record.update(record.props)
            
        return json.dumps(log_record)

def setup_logging():
    logger = logging.getLogger("attack_mcp")
    logger.setLevel(logging.INFO)
    
    # Clean up existing handlers to avoid duplicates
    if logger.hasHandlers():
        logger.handlers.clear()

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    return logger

# Global logger instance
logger = setup_logging()
