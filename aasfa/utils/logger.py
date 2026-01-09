"""
Logging utilities for AASFA Scanner
"""
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class AASFALogger:
    """Кастомный логгер для AASFA Scanner"""
    
    def __init__(self, verbose: bool = False, log_file: Optional[str] = None):
        self.verbose = verbose
        self.log_file = log_file
        self._setup_logger()
    
    def _setup_logger(self):
        """Настройка логгера"""
        self.logger = logging.getLogger("AASFA")
        self.logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        if self.log_file:
            log_path = Path(self.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def info(self, message: str):
        """Info сообщение"""
        self.logger.info(message)
    
    def debug(self, message: str):
        """Debug сообщение"""
        self.logger.debug(message)
    
    def warning(self, message: str):
        """Warning сообщение"""
        self.logger.warning(message)
    
    def error(self, message: str):
        """Error сообщение"""
        self.logger.error(message)
    
    def critical(self, message: str):
        """Critical сообщение"""
        self.logger.critical(message)


_global_logger: Optional[AASFALogger] = None


def init_logger(verbose: bool = False, log_file: Optional[str] = None) -> AASFALogger:
    """Инициализация глобального логгера"""
    global _global_logger
    _global_logger = AASFALogger(verbose, log_file)
    return _global_logger


def get_logger() -> AASFALogger:
    """Получение глобального логгера"""
    global _global_logger
    if _global_logger is None:
        _global_logger = AASFALogger()
    return _global_logger
