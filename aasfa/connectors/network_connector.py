"""
Network connector for raw socket operations
"""
import socket
import struct
import threading
from typing import Dict, List, Optional, Tuple

from .base_connector import BaseConnector


class NetworkConnector(BaseConnector):
    """Сетевой коннектор для низкоуровневых операций"""

    # Shared caches across all connector instances (per process)
    _tcp_scan_cache: Dict[Tuple[str, int, float], bool] = {}
    _udp_probe_cache: Dict[Tuple[str, int, float], bool] = {}
    _banner_cache: Dict[Tuple[str, int, float], Optional[str]] = {}
    _cache_lock = threading.Lock()

    def __init__(self, host: str, timeout: int = 30):
        super().__init__(host, 0, timeout)
        self.socket = None
    
    def connect(self) -> bool:
        """Network connector не требует явного connect"""
        self.connected = True
        return True
    
    def disconnect(self):
        """Закрытие сокета"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.connected = False
    
    def execute(self, command: str) -> tuple[bool, str]:
        """Not supported for network connector"""
        return False, "Not supported"
    
    def scan_port(self, port: int, timeout: Optional[float] = None, use_cache: bool = True) -> bool:
        """Сканирование одного TCP порта.

        По умолчанию используется быстрый режим (1s) для предотвращения "зависания".
        """
        effective_timeout = float(timeout) if timeout is not None else min(float(self.timeout), 1.0)
        cache_key = (self.host, int(port), effective_timeout)

        if use_cache:
            with self._cache_lock:
                cached = self._tcp_scan_cache.get(cache_key)
            if cached is not None:
                return cached

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(effective_timeout)
            result = sock.connect_ex((self.host, port))
            sock.close()
            is_open = result == 0
        except Exception as e:
            self.logger.debug(f"Port scan error on {port}: {e}")
            is_open = False

        if use_cache:
            with self._cache_lock:
                self._tcp_scan_cache[cache_key] = is_open

        return is_open

    def scan_port_fast(self, port: int, use_cache: bool = True) -> bool:
        """Быстрое сканирование порта (timeout=1s)."""
        return self.scan_port(port, timeout=1.0, use_cache=use_cache)

    def scan_port_detailed(self, port: int, use_cache: bool = True) -> bool:
        """Детальное сканирование порта (timeout=3s)."""
        return self.scan_port(port, timeout=min(float(self.timeout), 3.0), use_cache=use_cache)

    def scan_ports(self, ports: List[int], timeout: Optional[float] = None) -> List[int]:
        """Сканирование нескольких TCP портов"""
        open_ports = []
        for port in ports:
            if self.scan_port(port, timeout=timeout):
                open_ports.append(port)
        return open_ports
    
    def get_service_banner(
        self,
        port: int,
        timeout: Optional[float] = None,
        use_cache: bool = True,
    ) -> Optional[str]:
        """Получение баннера сервиса (TCP)."""
        effective_timeout = float(timeout) if timeout is not None else min(float(self.timeout), 3.0)
        cache_key = (self.host, int(port), effective_timeout)

        if use_cache:
            with self._cache_lock:
                if cache_key in self._banner_cache:
                    return self._banner_cache[cache_key]

        try:
            with socket.create_connection((self.host, port), timeout=effective_timeout) as sock:
                sock.settimeout(effective_timeout)
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()

            banner_value = banner or None
        except Exception as e:
            self.logger.debug(f"Banner grab failed on {port}: {e}")
            banner_value = None

        if use_cache:
            with self._cache_lock:
                self._banner_cache[cache_key] = banner_value

        return banner_value
    
    def check_udp_port(
        self,
        port: int,
        timeout: Optional[float] = None,
        use_cache: bool = True,
        payload: bytes = b"test",
    ) -> bool:
        """Проверка UDP порта (отправка datagram + ожидание ответа)."""
        effective_timeout = float(timeout) if timeout is not None else min(float(self.timeout), 1.0)
        cache_key = (self.host, int(port), effective_timeout)

        if use_cache:
            with self._cache_lock:
                cached = self._udp_probe_cache.get(cache_key)
            if cached is not None:
                return cached

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(effective_timeout)

            sock.sendto(payload, (self.host, port))

            try:
                sock.recvfrom(1024)
                is_open = True
            except socket.timeout:
                is_open = False
            finally:
                sock.close()

        except Exception as e:
            self.logger.debug(f"UDP check failed on {port}: {e}")
            is_open = False

        if use_cache:
            with self._cache_lock:
                self._udp_probe_cache[cache_key] = is_open

        return is_open
    
    def ping(self) -> bool:
        """ICMP ping проверка"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(self.timeout)
            
            packet = self._create_icmp_packet()
            sock.sendto(packet, (self.host, 0))
            
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                return True
            except socket.timeout:
                sock.close()
                return False
        
        except PermissionError:
            return self._tcp_ping()
        except Exception as e:
            self.logger.debug(f"Ping failed: {e}")
            return False
    
    def _tcp_ping(self) -> bool:
        """TCP ping как альтернатива ICMP."""
        common_ports = [80, 443, 22, 8080]
        for port in common_ports:
            if self.scan_port_fast(port):
                return True
        return False
    
    def _create_icmp_packet(self) -> bytes:
        """Создание ICMP пакета"""
        icmp_type = 8
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = 1
        icmp_seq = 1
        
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        data = b'AASFA'
        
        icmp_checksum = self._calculate_checksum(header + data)
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        
        return header + data
    
    def _calculate_checksum(self, data: bytes) -> int:
        """Расчет checksum для ICMP"""
        s = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                s += (data[i] << 8) + data[i + 1]
            else:
                s += data[i] << 8
        
        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s
