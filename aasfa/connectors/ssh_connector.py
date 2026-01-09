"""
SSH connector for remote command execution
"""
import socket
from typing import Optional, List
from .base_connector import BaseConnector


class SSHConnector(BaseConnector):
    """SSH коннектор"""
    
    def __init__(self, host: str, port: int = 22, username: str = "root", 
                 password: Optional[str] = None, timeout: int = 30):
        super().__init__(host, port, timeout)
        self.username = username
        self.password = password
        self.client = None
    
    def connect(self) -> bool:
        """Подключение к SSH"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.host, self.port))
            
            if result == 0:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                if 'SSH' in banner:
                    self.connected = True
                    return True
            
            sock.close()
            return False
        
        except Exception as e:
            self.logger.debug(f"SSH connection failed: {e}")
            return False
    
    def disconnect(self):
        """Отключение SSH"""
        if self.client:
            try:
                self.client.close()
            except:
                pass
        self.connected = False
    
    def execute(self, command: str) -> tuple[bool, str]:
        """Выполнение SSH команды"""
        return False, "SSH command execution requires paramiko library"
    
    def get_ssh_version(self) -> Optional[str]:
        """Получение версии SSH сервера"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            if 'SSH' in banner:
                return banner.strip()
            return None
        
        except Exception as e:
            self.logger.debug(f"Failed to get SSH version: {e}")
            return None
    
    def check_weak_ciphers(self) -> List[str]:
        """Проверка слабых шифров SSH"""
        weak_ciphers = []
        
        known_weak = [
            'arcfour',
            'arcfour128',
            'arcfour256',
            '3des-cbc',
            'aes128-cbc',
            'aes192-cbc',
            'aes256-cbc',
            'blowfish-cbc',
            'cast128-cbc',
        ]
        
        return weak_ciphers
