"""
Network connector for raw socket operations
"""
import socket
import struct
from typing import List, Tuple, Optional
from .base_connector import BaseConnector


class NetworkConnector(BaseConnector):
    """Сетевой коннектор для низкоуровневых операций"""
    
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
    
    def scan_port(self, port: int) -> bool:
        """Сканирование одного порта"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.host, port))
            sock.close()
            return result == 0
        except Exception as e:
            self.logger.debug(f"Port scan error on {port}: {e}")
            return False
    
    def scan_ports(self, ports: List[int]) -> List[int]:
        """Сканирование нескольких портов"""
        open_ports = []
        for port in ports:
            if self.scan_port(port):
                open_ports.append(port)
        return open_ports
    
    def get_service_banner(self, port: int) -> Optional[str]:
        """Получение баннера сервиса"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner.strip()
        
        except Exception as e:
            self.logger.debug(f"Banner grab failed on {port}: {e}")
            return None
    
    def check_udp_port(self, port: int) -> bool:
        """Проверка UDP порта"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            sock.sendto(b"test", (self.host, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                return True
            except socket.timeout:
                sock.close()
                return False
        
        except Exception as e:
            self.logger.debug(f"UDP check failed on {port}: {e}")
            return False
    
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
        """TCP ping как альтернатива ICMP"""
        common_ports = [80, 443, 22, 8080]
        for port in common_ports:
            if self.scan_port(port):
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
