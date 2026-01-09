"""
Base connector with retry logic and timeout handling
"""
from abc import ABC, abstractmethod
from typing import Optional, Any
import time
from ..utils.logger import get_logger


class BaseConnector(ABC):
    """Базовый класс для всех коннекторов"""
    
    def __init__(self, host: str, port: int, timeout: int = 30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.logger = get_logger()
        self.connected = False
    
    @abstractmethod
    def connect(self) -> bool:
        """Установка соединения"""
        pass
    
    @abstractmethod
    def disconnect(self):
        """Закрытие соединения"""
        pass
    
    @abstractmethod
    def execute(self, command: str) -> tuple[bool, str]:
        """Выполнение команды"""
        pass
    
    def retry_execute(self, command: str, retries: int = 3, delay: int = 1) -> tuple[bool, str]:
        """Выполнение команды с повторными попытками"""
        for attempt in range(retries):
            success, result = self.execute(command)
            if success:
                return True, result
            
            if attempt < retries - 1:
                self.logger.debug(f"Retry {attempt + 1}/{retries} for command: {command}")
                time.sleep(delay)
        
        return False, "Max retries exceeded"
    
    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()
