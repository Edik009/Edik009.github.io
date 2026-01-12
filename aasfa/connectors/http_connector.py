"""
HTTP/HTTPS connector for web service checks
"""
import urllib.request
import urllib.error
import ssl
import socket
from typing import Optional, Dict
from .base_connector import BaseConnector


class HTTPResponse:
    """Simple HTTP response object with status_code and content attributes"""
    def __init__(self, status_code: int, content: str, headers: Optional[Dict[str, str]] = None):
        self.status_code = status_code
        self.content = content
        self.text = content
        self.headers = headers or {}


class HTTPConnector(BaseConnector):
    """HTTP/HTTPS коннектор"""
    
    def __init__(self, host: str, port: int = 80, use_ssl: bool = False, timeout: int = 30):
        super().__init__(host, port, timeout)
        self.use_ssl = use_ssl
        self.protocol = "https" if use_ssl else "http"
        self.base_url = f"{self.protocol}://{host}:{port}"
    
    def connect(self) -> bool:
        """Проверка доступности HTTP сервиса"""
        try:
            response = self.get("/")
            self.connected = response is not None
            return self.connected
        except Exception as e:
            self.logger.debug(f"HTTP connection failed: {e}")
            return False
    
    def disconnect(self):
        """HTTP не требует явного disconnect"""
        self.connected = False
    
    def execute(self, command: str) -> tuple[bool, str]:
        """HTTP не поддерживает команды"""
        return False, "Not supported for HTTP"
    
    def get(self, path: str, headers: Optional[Dict[str, str]] = None, timeout: Optional[int] = None) -> Optional[HTTPResponse]:
        """HTTP GET запрос"""
        try:
            url = f"{self.base_url}{path}"
            req = urllib.request.Request(url)
            
            if headers:
                for key, value in headers.items():
                    req.add_header(key, value)
            
            context = ssl._create_unverified_context() if self.use_ssl else None
            
            # Use provided timeout or fall back to self.timeout
            request_timeout = timeout or self.timeout
            
            with urllib.request.urlopen(req, timeout=request_timeout, context=context) as response:
                content = response.read().decode('utf-8', errors='ignore')
                return HTTPResponse(response.status, content, dict(response.headers))
        
        except urllib.error.HTTPError as e:
            self.logger.debug(f"HTTP error {e.code}: {e.reason}")
            return None  # Return None for HTTP errors (like 404, 500, etc.)
        except Exception as e:
            self.logger.debug(f"HTTP request failed: {e}")
            return None
    
    def request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None, timeout: Optional[int] = None) -> Optional[HTTPResponse]:
        """HTTP request with custom method"""
        return self.get(url, headers, timeout)
    
    def get_headers(self, path: str = "/") -> Optional[Dict[str, str]]:
        """Получение HTTP заголовков"""
        try:
            url = f"{self.base_url}{path}"
            req = urllib.request.Request(url, method='HEAD')
            context = ssl._create_unverified_context() if self.use_ssl else None
            
            with urllib.request.urlopen(req, timeout=self.timeout, context=context) as response:
                return dict(response.headers)
        
        except Exception as e:
            self.logger.debug(f"Failed to get headers: {e}")
            return None
    
    def check_hsts(self) -> bool:
        """Проверка наличия HSTS заголовка"""
        headers = self.get_headers()
        if headers:
            return 'Strict-Transport-Security' in headers or 'strict-transport-security' in headers
        return False
    
    def check_ssl_cert(self) -> Optional[Dict]:
        """Проверка SSL сертификата"""
        if not self.use_ssl:
            return None
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    return cert
        except Exception as e:
            self.logger.debug(f"SSL cert check failed: {e}")
            return None
