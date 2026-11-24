"""
Unified Logging Configuration for CyberSentinel.
"""
import logging
import sys
from pathlib import Path

def setup_logger(name: str = "CyberSentinel", level: int = logging.INFO) -> logging.Logger:
    """Configures and returns a consistent logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(level)
        formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)
    return logger

logger = setup_logger()
