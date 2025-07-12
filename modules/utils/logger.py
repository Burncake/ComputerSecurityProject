import logging
import os

log_dir = "data/logs"
os.makedirs(log_dir, exist_ok=True)

logger = logging.getLogger("SecurityLogger")
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(os.path.join(log_dir, "security.log"))
formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
file_handler.setFormatter(formatter)

if not logger.hasHandlers():
    logger.addHandler(file_handler)

def log_info(msg):
    logger.info(msg)

def log_warning(msg):
    logger.warning(msg)

def log_error(msg):
    logger.error(msg)
