import logging
import logging.handlers
import os

def setup_logger():
    # Create logs directory if it doesn't exist
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            # Console handler
            logging.StreamHandler(),
            # File handler with rotation
            logging.handlers.RotatingFileHandler(
                os.path.join(log_dir, 'incident_server.log'),
                maxBytes=1024*1024,  # 1MB
                backupCount=5
            )
        ]
    )
    
    return logging.getLogger('incident_server')

# Create and export logger instance
logger = setup_logger()