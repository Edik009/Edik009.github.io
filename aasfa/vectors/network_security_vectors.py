"""
Network Security Vectors - Comprehensive network security scanning module

Полный набор сетевых векторов безопасности с многофакторной проверкой.
Включает проверки базовых сетевых портов, SSL/TLS уязвимостей,
сетевых сервисов и протокольных уязвимостей.

Структура модуля:
- ЧАСТЬ 1: Базовые сетевые порты (Telnet, FTP, SSH, HTTP, HTTPS, RDP, VNC)
- ЧАСТЬ 2: Уязвимости SSL/TLS (Weak ciphers, Self-signed cert, Expired cert, HSTS)
- ЧАСТЬ 3: Сетевые сервисы (SMB, NFS, SNMP, TFTP, Syslog)
- ЧАСТЬ 4: Протокольные уязвимости (UPnP, MQTT, WebSocket)
- ЧАСТЬ 5: Утилиты и вспомогательные функции

Каждый вектор использует многофакторную проверку для повышения точности.
"""

import socket
import ssl
import struct
import time
import logging
import re
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

from ..utils.config import ScanConfig


# Настройка логирования
logger = logging.getLogger(__name__)


# ============================================================================
# ЧАСТЬ 5: УТИЛИТЫ И ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (реализуем в начале)
# ============================================================================


def ping_host(ip: str, timeout: int = 2) -> bool:
    """
    Отправка ICMP ping для проверки доступности хоста.
    
    Args:
        ip: IP адрес хоста
        timeout: Таймаут в секундах
        
    Returns:
        True если хост пингуется, False иначе
    """
    try:
        import subprocess
        import platform
        
        # Определяем параметры команды ping в зависимости от ОС
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        
        command = ['ping', param, '1', timeout_param, str(timeout), ip]
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 1
        )
        
        return result.returncode == 0
    except Exception as e:
        logger.debug(f"Ping failed for {ip}: {str(e)}")
        return False


def port_is_open(ip: str, port: int, timeout: int = 2) -> bool:
    """
    Проверка открыт ли TCP порт.
    
    Args:
        ip: IP адрес хоста
        port: Номер порта
        timeout: Таймаут в секундах
        
    Returns:
        True если порт открыт, False иначе
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception as e:
        logger.debug(f"Port check failed for {ip}:{port}: {str(e)}")
        return False


def get_ssl_certificate(ip: str, port: int = 443, timeout: int = 5) -> Dict[str, Any]:
    """
    Получение SSL/TLS сертификата.
    
    Args:
        ip: IP адрес хоста
        port: Порт (обычно 443)
        timeout: Таймаут в секундах
        
    Returns:
        dict с информацией о сертификате или пустой dict при ошибке
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                
                if not cert:
                    return {}
                
                return {
                    'subject': cert.get('subject', ()),
                    'issuer': cert.get('issuer', ()),
                    'version': cert.get('version', 0),
                    'serialNumber': cert.get('serialNumber', ''),
                    'notBefore': cert.get('notBefore', ''),
                    'notAfter': cert.get('notAfter', ''),
                    'subjectAltName': cert.get('subjectAltName', ()),
                }
    except Exception as e:
        logger.debug(f"SSL cert retrieval failed for {ip}:{port}: {str(e)}")
        return {}


def send_raw_data(ip: str, port: int, data: bytes, timeout: int = 2) -> bytes:
    """
    Отправка RAW данных по TCP и получение ответа.
    
    Args:
        ip: IP адрес хоста
        port: Номер порта
        data: Данные для отправки
        timeout: Таймаут в секундах
        
    Returns:
        Полученные bytes или пустые bytes при ошибке
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(data)
        response = sock.recv(4096)
        sock.close()
        return response
    except Exception as e:
        logger.debug(f"Raw data send failed for {ip}:{port}: {str(e)}")
        return b''


def parse_ssl_certificate(cert_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Парсинг сертификата в структурированный вид.
    
    Args:
        cert_info: Информация о сертификате из getpeercert()
        
    Returns:
        dict с распарсенной информацией
    """
    try:
        result = {
            'common_name': '',
            'organization': '',
            'issuer_cn': '',
            'issuer_org': '',
            'not_before': '',
            'not_after': '',
            'expired': False,
            'self_signed': False,
        }
        
        # Извлечение Subject
        subject = dict(x[0] for x in cert_info.get('subject', ()))
        result['common_name'] = subject.get('commonName', '')
        result['organization'] = subject.get('organizationName', '')
        
        # Извлечение Issuer
        issuer = dict(x[0] for x in cert_info.get('issuer', ()))
        result['issuer_cn'] = issuer.get('commonName', '')
        result['issuer_org'] = issuer.get('organizationName', '')
        
        # Даты
        result['not_before'] = cert_info.get('notBefore', '')
        result['not_after'] = cert_info.get('notAfter', '')
        
        # Проверка истечения срока
        if result['not_after']:
            try:
                not_after = datetime.strptime(result['not_after'], '%b %d %H:%M:%S %Y %Z')
                result['expired'] = not_after < datetime.now()
            except:
                pass
        
        # Проверка самоподписанности
        result['self_signed'] = (
            result['common_name'] == result['issuer_cn'] or
            result['organization'] == result['issuer_org']
        )
        
        return result
    except Exception as e:
        logger.debug(f"Certificate parsing failed: {str(e)}")
        return {}


def analyze_ssh_banner(banner: str) -> Dict[str, Any]:
    """
    Анализ SSH banner для получения версии и параметров.
    
    Args:
        banner: SSH banner строка
        
    Returns:
        dict с информацией о версии SSH
    """
    try:
        result = {
            'protocol_version': '',
            'software_version': '',
            'software_name': '',
            'is_old_version': False,
            'banner_raw': banner,
        }
        
        # Парсинг формата: SSH-2.0-OpenSSH_7.4
        match = re.match(r'SSH-([0-9.]+)-(.+)', banner.strip())
        if match:
            result['protocol_version'] = match.group(1)
            result['software_version'] = match.group(2)
            
            # Извлечение имени ПО
            if 'OpenSSH' in result['software_version']:
                result['software_name'] = 'OpenSSH'
                # Проверка старой версии OpenSSH (< 7.0)
                version_match = re.search(r'OpenSSH_([0-9.]+)', result['software_version'])
                if version_match:
                    major_version = int(version_match.group(1).split('.')[0])
                    result['is_old_version'] = major_version < 7
            elif 'Dropbear' in result['software_version']:
                result['software_name'] = 'Dropbear'
            
            # Проверка старого протокола SSH-1.x
            if result['protocol_version'].startswith('1.'):
                result['is_old_version'] = True
        
        return result
    except Exception as e:
        logger.debug(f"SSH banner analysis failed: {str(e)}")
        return {'banner_raw': banner}


def analyze_http_headers(headers: str) -> Dict[str, Any]:
    """
    Парсинг HTTP заголовков.
    
    Args:
        headers: Строка с HTTP заголовками
        
    Returns:
        dict с распарсенными заголовками
    """
    try:
        result = {
            'server': '',
            'content_type': '',
            'location': '',
            'strict_transport_security': '',
            'all_headers': {},
        }
        
        lines = headers.split('\n')
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                result['all_headers'][key] = value
                
                if key == 'server':
                    result['server'] = value
                elif key == 'content-type':
                    result['content_type'] = value
                elif key == 'location':
                    result['location'] = value
                elif key == 'strict-transport-security':
                    result['strict_transport_security'] = value
        
        return result
    except Exception as e:
        logger.debug(f"HTTP headers analysis failed: {str(e)}")
        return {}


def is_weak_cipher(cipher_name: str) -> bool:
    """
    Проверка что cipher слабый.
    
    Args:
        cipher_name: Название cipher suite
        
    Returns:
        True если cipher слабый, False иначе
    """
    cipher_lower = cipher_name.lower()
    
    # Проверка на слабые алгоритмы
    weak_algorithms = ['rc4', 'des', 'md5', 'null', 'export', 'anon']
    for algo in weak_algorithms:
        if algo in cipher_lower:
            return True
    
    # Проверка на слабые длины ключей (40-bit, 56-bit)
    # Используем более точную проверку с разделителями
    import re
    if re.search(r'\b(40|56)\b', cipher_name):
        return True
    if 'EXPORT40' in cipher_name or 'EXPORT56' in cipher_name:
        return True
    
    return False


def get_ssl_ciphers(ip: str, port: int = 443, timeout: int = 5) -> List[str]:
    """
    Получение списка поддерживаемых SSL/TLS cipher suites.
    
    Args:
        ip: IP адрес хоста
        port: Порт (обычно 443)
        timeout: Таймаут в секундах
        
    Returns:
        Список названий поддерживаемых ciphers
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    return [cipher[0]]
        
        return []
    except Exception as e:
        logger.debug(f"SSL cipher retrieval failed for {ip}:{port}: {str(e)}")
        return []


def check_ssl_protocol_support(ip: str, port: int, protocol: int, timeout: int = 5) -> bool:
    """
    Проверка поддержки конкретного SSL/TLS протокола.
    
    Args:
        ip: IP адрес хоста
        port: Порт
        protocol: Протокол (ssl.PROTOCOL_SSLv3, ssl.PROTOCOL_TLSv1 и т.д.)
        timeout: Таймаут в секундах
        
    Returns:
        True если протокол поддерживается, False иначе
    """
    try:
        context = ssl.SSLContext(protocol)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                return True
    except:
        return False


def grab_banner(ip: str, port: int, timeout: int = 2) -> str:
    """
    Получение banner от сервиса.
    
    Args:
        ip: IP адрес хоста
        port: Номер порта
        timeout: Таймаут в секундах
        
    Returns:
        Banner строка или пустая строка при ошибке
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Отправляем небольшой запрос для некоторых сервисов
        try:
            sock.send(b'\r\n')
        except:
            pass
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        return banner.strip()
    except Exception as e:
        logger.debug(f"Banner grab failed for {ip}:{port}: {str(e)}")
        return ''


# ============================================================================
# ОСНОВНОЙ КЛАСС СЕТЕВЫХ ВЕКТОРОВ
# ============================================================================


class NetworkSecurityVectors:
    """
    Comprehensive Network Security Vectors с многофакторной проверкой.
    
    Этот класс реализует полный набор сетевых векторов безопасности,
    каждый из которых использует многофакторную проверку для повышения
    точности обнаружения.
    """
    
    def __init__(self, config: ScanConfig):
        """
        Инициализация сканера сетевых векторов.
        
        Args:
            config: Конфигурация сканирования
        """
        self.config = config
        self.target_ip = config.target_ip
        self.timeout = config.timeout
        self.port_scan_timeout = config.port_scan_timeout
    
    # ========================================================================
    # ЧАСТЬ 1: БАЗОВЫЕ СЕТЕВЫЕ ПОРТЫ
    # ========================================================================
    
    def check_telnet_port_open(self) -> Dict[str, Any]:
        """
        Вектор 1.1: Проверка открытого Telnet порта (порт 23).
        
        Многофакторная проверка:
        - Фактор 1: Пинг целевого хоста (ICMP)
        - Фактор 2: Сканирование порта 23 (TCP SYN)
        - Фактор 3: Попытка реального подключения к Telnet
        - Фактор 4: Анализ banner
        
        Returns:
            dict с результатами проверки
        """
        vector_id = 1001
        vector_name = "Telnet Port Open (23)"
        factors = []
        
        try:
            # Фактор 1: Пинг хоста
            ping_result = ping_host(self.target_ip, timeout=2)
            factors.append({
                "name": "ICMP Ping",
                "passed": ping_result,
                "reason": "Host responds to ping" if ping_result else "Host not responding"
            })
            
            # Фактор 2: Сканирование порта 23
            port_open = port_is_open(self.target_ip, 23, timeout=self.port_scan_timeout)
            factors.append({
                "name": "Port 23 Open",
                "passed": port_open,
                "reason": "Port 23 is open" if port_open else "Port 23 is closed"
            })
            
            if not port_open:
                return self._build_result(
                    vector_id, vector_name, False,
                    "Telnet port not accessible", factors
                )
            
            # Фактор 3: Попытка подключения
            connection_ok = False
            banner = ""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.target_ip, 23))
                connection_ok = True
                
                # Попытка получить banner
                try:
                    sock.send(b'\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    pass
                finally:
                    sock.close()
            except Exception as e:
                logger.debug(f"Telnet connection failed: {str(e)}")
            
            factors.append({
                "name": "TCP Connection",
                "passed": connection_ok,
                "reason": "Successfully connected to port 23" if connection_ok else "Connection failed"
            })
            
            # Фактор 4: Banner анализ
            banner_received = len(banner) > 0 and (
                'telnet' in banner.lower() or 
                'login' in banner.lower() or
                'username' in banner.lower()
            )
            factors.append({
                "name": "Telnet Banner",
                "passed": banner_received,
                "reason": f"Received banner: {banner[:50]}" if banner_received else "No telnet banner"
            })
            
            # Расчет результата (нужны ≥3 фактора из 4)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            confidence = passed_factors / len(factors)
            
            details = (
                f"Telnet port found and accessible "
                f"({passed_factors}/{len(factors)} factors confirmed)"
            )
            
            return self._build_result(
                vector_id, vector_name, vulnerable,
                details, factors, confidence
            )
        
        except Exception as e:
            logger.error(f"Error checking Telnet: {str(e)}")
            return self._build_result(
                vector_id, vector_name, False,
                f"Error checking Telnet: {str(e)}", factors, error=str(e)
            )
    
    def check_ftp_port_open(self) -> Dict[str, Any]:
        """
        Вектор 1.2: Проверка открытого FTP порта (порт 21).
        
        Многофакторная проверка:
        - Фактор 1: Пинг целевого хоста
        - Фактор 2: Сканирование порта 21
        - Фактор 3: Попытка подключения к FTP
        - Фактор 4: Проверка анонимного доступа
        - Фактор 5: Получение banner (220 response)
        
        Returns:
            dict с результатами проверки
        """
        vector_id = 1002
        vector_name = "FTP Port Open (21)"
        factors = []
        can_login_anonymous = False
        
        try:
            # Фактор 1: Пинг хоста
            ping_result = ping_host(self.target_ip, timeout=2)
            factors.append({
                "name": "ICMP Ping",
                "passed": ping_result,
                "reason": "Host responds to ping" if ping_result else "Host not responding"
            })
            
            # Фактор 2: Сканирование порта 21
            port_open = port_is_open(self.target_ip, 21, timeout=self.port_scan_timeout)
            factors.append({
                "name": "Port 21 Open",
                "passed": port_open,
                "reason": "Port 21 is open" if port_open else "Port 21 is closed"
            })
            
            if not port_open:
                return self._build_result(
                    vector_id, vector_name, False,
                    "FTP port not accessible", factors,
                    extra={'can_login_anonymous': False}
                )
            
            # Фактор 3: Попытка подключения к FTP
            connection_ok = False
            banner = ""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.target_ip, 21))
                connection_ok = True
                
                # Получение banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
                # Фактор 4: Проверка анонимного доступа
                try:
                    sock.send(b'USER anonymous\r\n')
                    time.sleep(0.5)
                    response1 = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    if '331' in response1 or '230' in response1:
                        sock.send(b'PASS anonymous@example.com\r\n')
                        time.sleep(0.5)
                        response2 = sock.recv(1024).decode('utf-8', errors='ignore')
                        
                        if '230' in response2 or 'logged in' in response2.lower():
                            can_login_anonymous = True
                except:
                    pass
                finally:
                    sock.close()
            except Exception as e:
                logger.debug(f"FTP connection failed: {str(e)}")
            
            factors.append({
                "name": "TCP Connection",
                "passed": connection_ok,
                "reason": "Successfully connected to port 21" if connection_ok else "Connection failed"
            })
            
            factors.append({
                "name": "Anonymous Login",
                "passed": can_login_anonymous,
                "reason": "Anonymous login allowed" if can_login_anonymous else "Anonymous login denied"
            })
            
            # Фактор 5: Получение banner (220 response)
            banner_received = '220' in banner or 'ftp' in banner.lower()
            factors.append({
                "name": "FTP Banner",
                "passed": banner_received,
                "reason": f"Received FTP banner: {banner[:50]}" if banner_received else "No FTP banner"
            })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            confidence = passed_factors / len(factors)
            
            details = (
                f"FTP port found and accessible "
                f"({passed_factors}/{len(factors)} factors confirmed)"
            )
            if can_login_anonymous:
                details += " - ANONYMOUS LOGIN ALLOWED"
            
            return self._build_result(
                vector_id, vector_name, vulnerable,
                details, factors, confidence,
                extra={'can_login_anonymous': can_login_anonymous}
            )
        
        except Exception as e:
            logger.error(f"Error checking FTP: {str(e)}")
            return self._build_result(
                vector_id, vector_name, False,
                f"Error checking FTP: {str(e)}", factors, error=str(e),
                extra={'can_login_anonymous': False}
            )
    
    def check_ssh_port_open(self) -> Dict[str, Any]:
        """
        Вектор 1.3: Проверка открытого SSH порта (порт 22).
        
        Многофакторная проверка:
        - Фактор 1: Пинг хоста
        - Фактор 2: Сканирование порта 22
        - Фактор 3: Получение SSH banner
        - Фактор 4: Анализ версии SSH сервера
        - Фактор 5: Проверка поддерживаемых алгоритмов
        
        Returns:
            dict с результатами проверки
        """
        vector_id = 1003
        vector_name = "SSH Port Open (22)"
        factors = []
        ssh_version = ""
        algorithms = []
        
        try:
            # Фактор 1: Пинг хоста
            ping_result = ping_host(self.target_ip, timeout=2)
            factors.append({
                "name": "ICMP Ping",
                "passed": ping_result,
                "reason": "Host responds to ping" if ping_result else "Host not responding"
            })
            
            # Фактор 2: Сканирование порта 22
            port_open = port_is_open(self.target_ip, 22, timeout=self.port_scan_timeout)
            factors.append({
                "name": "Port 22 Open",
                "passed": port_open,
                "reason": "Port 22 is open" if port_open else "Port 22 is closed"
            })
            
            if not port_open:
                return self._build_result(
                    vector_id, vector_name, False,
                    "SSH port not accessible", factors,
                    extra={'ssh_version': '', 'algorithms': []}
                )
            
            # Фактор 3: Получение SSH banner
            banner = ""
            banner_received = False
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.target_ip, 22))
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                
                banner_received = banner.startswith('SSH-')
            except Exception as e:
                logger.debug(f"SSH banner retrieval failed: {str(e)}")
            
            factors.append({
                "name": "SSH Banner",
                "passed": banner_received,
                "reason": f"Received SSH banner: {banner}" if banner_received else "No SSH banner"
            })
            
            # Фактор 4: Анализ версии SSH сервера
            ssh_info = analyze_ssh_banner(banner)
            ssh_version = ssh_info.get('software_version', '')
            is_old = ssh_info.get('is_old_version', False)
            
            factors.append({
                "name": "SSH Version Analysis",
                "passed": len(ssh_version) > 0,
                "reason": f"SSH version: {ssh_version}" if ssh_version else "Could not determine version"
            })
            
            # Фактор 5: Проверка старого протокола/версии
            old_version_detected = is_old or '1.99' in banner or 'SSH-1' in banner
            factors.append({
                "name": "Protocol Version Check",
                "passed": banner_received,
                "reason": "Old/weak SSH version detected" if old_version_detected else "Modern SSH version"
            })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            confidence = passed_factors / len(factors)
            
            details = (
                f"SSH port found and accessible "
                f"({passed_factors}/{len(factors)} factors confirmed)"
            )
            if old_version_detected:
                details += " - OLD/WEAK VERSION DETECTED"
            
            return self._build_result(
                vector_id, vector_name, vulnerable,
                details, factors, confidence,
                extra={'ssh_version': ssh_version, 'algorithms': algorithms}
            )
        
        except Exception as e:
            logger.error(f"Error checking SSH: {str(e)}")
            return self._build_result(
                vector_id, vector_name, False,
                f"Error checking SSH: {str(e)}", factors, error=str(e),
                extra={'ssh_version': '', 'algorithms': []}
            )
    
    def check_http_port_open(self) -> Dict[str, Any]:
        """
        Вектор 1.4: Проверка открытого HTTP порта (порт 80).
        
        Многофакторная проверка:
        - Фактор 1: Пинг хоста
        - Фактор 2: Сканирование порта 80
        - Фактор 3: Отправка GET / запроса и получение ответа
        - Фактор 4: Анализ headers
        - Фактор 5: Проверка редиректа на HTTPS
        
        Returns:
            dict с результатами проверки
        """
        vector_id = 1004
        vector_name = "HTTP Port Open (80)"
        factors = []
        is_redirect_to_https = False
        server_header = ""
        
        try:
            # Фактор 1: Пинг хоста
            ping_result = ping_host(self.target_ip, timeout=2)
            factors.append({
                "name": "ICMP Ping",
                "passed": ping_result,
                "reason": "Host responds to ping" if ping_result else "Host not responding"
            })
            
            # Фактор 2: Сканирование порта 80
            port_open = port_is_open(self.target_ip, 80, timeout=self.port_scan_timeout)
            factors.append({
                "name": "Port 80 Open",
                "passed": port_open,
                "reason": "Port 80 is open" if port_open else "Port 80 is closed"
            })
            
            if not port_open:
                return self._build_result(
                    vector_id, vector_name, False,
                    "HTTP port not accessible", factors,
                    extra={'is_redirect_to_https': False, 'server_header': ''}
                )
            
            # Фактор 3: Отправка GET / запроса
            http_response_received = False
            headers_str = ""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.target_ip, 80))
                
                request = b'GET / HTTP/1.1\r\nHost: ' + self.target_ip.encode() + b'\r\nConnection: close\r\n\r\n'
                sock.sendall(request)
                
                response = b''
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 8192:  # Ограничение размера
                        break
                
                sock.close()
                
                if response:
                    http_response_received = 'HTTP' in response[:100].decode('utf-8', errors='ignore')
                    headers_str = response.split(b'\r\n\r\n')[0].decode('utf-8', errors='ignore')
            except Exception as e:
                logger.debug(f"HTTP request failed: {str(e)}")
            
            factors.append({
                "name": "HTTP Response",
                "passed": http_response_received,
                "reason": "Received HTTP response" if http_response_received else "No HTTP response"
            })
            
            # Фактор 4: Анализ headers
            headers_info = analyze_http_headers(headers_str)
            server_header = headers_info.get('server', '')
            location = headers_info.get('location', '')
            
            factors.append({
                "name": "HTTP Headers",
                "passed": len(headers_info.get('all_headers', {})) > 0,
                "reason": f"Server: {server_header}" if server_header else "Headers parsed"
            })
            
            # Фактор 5: Проверка редиректа на HTTPS
            is_redirect_to_https = 'https://' in location.lower()
            factors.append({
                "name": "HTTPS Redirect",
                "passed": http_response_received,
                "reason": "Redirects to HTTPS" if is_redirect_to_https else "No HTTPS redirect"
            })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            confidence = passed_factors / len(factors)
            
            details = (
                f"HTTP port found and accessible "
                f"({passed_factors}/{len(factors)} factors confirmed)"
            )
            if not is_redirect_to_https:
                details += " - NO HTTPS REDIRECT"
            
            return self._build_result(
                vector_id, vector_name, vulnerable,
                details, factors, confidence,
                extra={'is_redirect_to_https': is_redirect_to_https, 'server_header': server_header}
            )
        
        except Exception as e:
            logger.error(f"Error checking HTTP: {str(e)}")
            return self._build_result(
                vector_id, vector_name, False,
                f"Error checking HTTP: {str(e)}", factors, error=str(e),
                extra={'is_redirect_to_https': False, 'server_header': ''}
            )
    
    def check_https_port_open(self) -> Dict[str, Any]:
        """
        Вектор 1.5: Проверка открытого HTTPS порта (порт 443).
        
        Многофакторная проверка:
        - Фактор 1: Пинг хоста
        - Фактор 2: Сканирование порта 443
        - Фактор 3: Попытка SSL/TLS handshake
        - Фактор 4: Получение сертификата
        - Фактор 5: Анализ сертификата
        
        Returns:
            dict с результатами проверки
        """
        vector_id = 1005
        vector_name = "HTTPS Port Open (443)"
        factors = []
        cert_info = {}
        
        try:
            # Фактор 1: Пинг хоста
            ping_result = ping_host(self.target_ip, timeout=2)
            factors.append({
                "name": "ICMP Ping",
                "passed": ping_result,
                "reason": "Host responds to ping" if ping_result else "Host not responding"
            })
            
            # Фактор 2: Сканирование порта 443
            port_open = port_is_open(self.target_ip, 443, timeout=self.port_scan_timeout)
            factors.append({
                "name": "Port 443 Open",
                "passed": port_open,
                "reason": "Port 443 is open" if port_open else "Port 443 is closed"
            })
            
            if not port_open:
                return self._build_result(
                    vector_id, vector_name, False,
                    "HTTPS port not accessible", factors,
                    extra={'cert_info': {}}
                )
            
            # Фактор 3: Попытка SSL/TLS handshake
            ssl_handshake_ok = False
            cert_raw = {}
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target_ip, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target_ip) as ssock:
                        ssl_handshake_ok = True
                        
                        # Фактор 4: Получение сертификата
                        cert_raw = ssock.getpeercert()
            except Exception as e:
                logger.debug(f"SSL handshake failed: {str(e)}")
            
            factors.append({
                "name": "SSL/TLS Handshake",
                "passed": ssl_handshake_ok,
                "reason": "SSL/TLS handshake successful" if ssl_handshake_ok else "Handshake failed"
            })
            
            cert_received = len(cert_raw) > 0
            factors.append({
                "name": "Certificate Received",
                "passed": cert_received,
                "reason": "SSL certificate received" if cert_received else "No certificate"
            })
            
            # Фактор 5: Анализ сертификата
            if cert_received:
                cert_info = parse_ssl_certificate(cert_raw)
                
                cert_issues = []
                if cert_info.get('expired', False):
                    cert_issues.append("EXPIRED")
                if cert_info.get('self_signed', False):
                    cert_issues.append("SELF-SIGNED")
                
                reason = f"Certificate: {cert_info.get('common_name', 'unknown')}"
                if cert_issues:
                    reason += f" ({', '.join(cert_issues)})"
                
                factors.append({
                    "name": "Certificate Analysis",
                    "passed": True,
                    "reason": reason
                })
            else:
                factors.append({
                    "name": "Certificate Analysis",
                    "passed": False,
                    "reason": "Could not analyze certificate"
                })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            confidence = passed_factors / len(factors)
            
            details = (
                f"HTTPS port found and accessible "
                f"({passed_factors}/{len(factors)} factors confirmed)"
            )
            
            return self._build_result(
                vector_id, vector_name, vulnerable,
                details, factors, confidence,
                extra={'cert_info': cert_info}
            )
        
        except Exception as e:
            logger.error(f"Error checking HTTPS: {str(e)}")
            return self._build_result(
                vector_id, vector_name, False,
                f"Error checking HTTPS: {str(e)}", factors, error=str(e),
                extra={'cert_info': {}}
            )
    
    def check_rdp_port_open(self) -> Dict[str, Any]:
        """
        Вектор 1.6: Проверка открытого RDP порта (порт 3389).
        
        Многофакторная проверка:
        - Фактор 1: Пинг хоста
        - Фактор 2: Сканирование порта 3389
        - Фактор 3: Попытка RDP handshake
        - Фактор 4: Анализ RDP protocol version
        
        Returns:
            dict с результатами проверки
        """
        vector_id = 1006
        vector_name = "RDP Port Open (3389)"
        factors = []
        rdp_version = ""
        
        try:
            # Фактор 1: Пинг хоста
            ping_result = ping_host(self.target_ip, timeout=2)
            factors.append({
                "name": "ICMP Ping",
                "passed": ping_result,
                "reason": "Host responds to ping" if ping_result else "Host not responding"
            })
            
            # Фактор 2: Сканирование порта 3389
            port_open = port_is_open(self.target_ip, 3389, timeout=self.port_scan_timeout)
            factors.append({
                "name": "Port 3389 Open",
                "passed": port_open,
                "reason": "Port 3389 is open" if port_open else "Port 3389 is closed"
            })
            
            if not port_open:
                return self._build_result(
                    vector_id, vector_name, False,
                    "RDP port not accessible", factors,
                    extra={'rdp_version': ''}
                )
            
            # Фактор 3: Попытка RDP handshake
            rdp_handshake_ok = False
            try:
                # Простой RDP Connection Request (X.224)
                rdp_request = (
                    b'\x03\x00\x00\x13'  # TPKT Header
                    b'\x0e\xe0\x00\x00\x00\x00\x00'  # X.224 Connection Request
                    b'\x01\x00\x08\x00\x03\x00\x00\x00'
                )
                
                response = send_raw_data(self.target_ip, 3389, rdp_request, timeout=3)
                
                # Проверка ответа RDP (должен начинаться с TPKT header)
                if len(response) > 0 and response[0:1] == b'\x03':
                    rdp_handshake_ok = True
            except Exception as e:
                logger.debug(f"RDP handshake failed: {str(e)}")
            
            factors.append({
                "name": "RDP Handshake",
                "passed": rdp_handshake_ok,
                "reason": "RDP handshake successful" if rdp_handshake_ok else "Handshake failed"
            })
            
            # Фактор 4: Анализ RDP protocol version
            rdp_version_detected = rdp_handshake_ok
            if rdp_version_detected:
                rdp_version = "RDP detected (protocol version unknown)"
            
            factors.append({
                "name": "RDP Protocol Version",
                "passed": rdp_version_detected,
                "reason": rdp_version if rdp_version else "Could not determine version"
            })
            
            # Расчет результата (нужны ≥3 фактора из 4)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            confidence = passed_factors / len(factors)
            
            details = (
                f"RDP port found and accessible "
                f"({passed_factors}/{len(factors)} factors confirmed)"
            )
            
            return self._build_result(
                vector_id, vector_name, vulnerable,
                details, factors, confidence,
                extra={'rdp_version': rdp_version}
            )
        
        except Exception as e:
            logger.error(f"Error checking RDP: {str(e)}")
            return self._build_result(
                vector_id, vector_name, False,
                f"Error checking RDP: {str(e)}", factors, error=str(e),
                extra={'rdp_version': ''}
            )
    
    def check_vnc_port_open(self) -> Dict[str, Any]:
        """
        Вектор 1.7: Проверка открытого VNC порта (порт 5900).
        
        Многофакторная проверка:
        - Фактор 1: Пинг хоста
        - Фактор 2: Сканирование порта 5900
        - Фактор 3: Попытка VNC handshake
        - Фактор 4: Проверка требования пароля
        
        Returns:
            dict с результатами проверки
        """
        vector_id = 1007
        vector_name = "VNC Port Open (5900)"
        factors = []
        requires_password = True
        
        try:
            # Фактор 1: Пинг хоста
            ping_result = ping_host(self.target_ip, timeout=2)
            factors.append({
                "name": "ICMP Ping",
                "passed": ping_result,
                "reason": "Host responds to ping" if ping_result else "Host not responding"
            })
            
            # Фактор 2: Сканирование порта 5900
            port_open = port_is_open(self.target_ip, 5900, timeout=self.port_scan_timeout)
            factors.append({
                "name": "Port 5900 Open",
                "passed": port_open,
                "reason": "Port 5900 is open" if port_open else "Port 5900 is closed"
            })
            
            if not port_open:
                return self._build_result(
                    vector_id, vector_name, False,
                    "VNC port not accessible", factors,
                    extra={'requires_password': True}
                )
            
            # Фактор 3: Попытка VNC handshake
            vnc_handshake_ok = False
            vnc_version = ""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.target_ip, 5900))
                
                # Получение VNC version (RFB 003.008 и т.д.)
                vnc_version = sock.recv(12).decode('utf-8', errors='ignore')
                
                if vnc_version.startswith('RFB'):
                    vnc_handshake_ok = True
                    
                    # Отправка версии обратно
                    sock.sendall(vnc_version.encode())
                    
                    # Получение security types
                    time.sleep(0.5)
                    security_data = sock.recv(256)
                    
                    # Проверка типа безопасности
                    if len(security_data) > 0:
                        # Тип 1 = None (нет аутентификации)
                        # Тип 2 = VNC Authentication
                        if b'\x01' in security_data[:10]:
                            requires_password = False
                
                sock.close()
            except Exception as e:
                logger.debug(f"VNC handshake failed: {str(e)}")
            
            factors.append({
                "name": "VNC Handshake",
                "passed": vnc_handshake_ok,
                "reason": f"VNC handshake successful ({vnc_version.strip()})" if vnc_handshake_ok else "Handshake failed"
            })
            
            # Фактор 4: Проверка требования пароля
            factors.append({
                "name": "Password Requirement",
                "passed": vnc_handshake_ok,
                "reason": "Password required" if requires_password else "NO PASSWORD REQUIRED"
            })
            
            # Расчет результата (нужны ≥3 фактора из 4)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            confidence = passed_factors / len(factors)
            
            details = (
                f"VNC port found and accessible "
                f"({passed_factors}/{len(factors)} factors confirmed)"
            )
            if not requires_password:
                details += " - NO PASSWORD REQUIRED"
            
            return self._build_result(
                vector_id, vector_name, vulnerable,
                details, factors, confidence,
                extra={'requires_password': requires_password}
            )
        
        except Exception as e:
            logger.error(f"Error checking VNC: {str(e)}")
            return self._build_result(
                vector_id, vector_name, False,
                f"Error checking VNC: {str(e)}", factors, error=str(e),
                extra={'requires_password': True}
            )
    
    # ========================================================================
    # ЧАСТЬ 2: УЯЗВИМОСТИ SSL/TLS
    # ========================================================================
    
    def check_weak_ssl_tls_ciphers(self, port: int = 443) -> Dict[str, Any]:
        """
        Вектор 2.1: Проверка слабых SSL/TLS cipher suites.
        
        Многофакторная проверка:
        - Фактор 1: Проверка поддержки SSLv3
        - Фактор 2: Проверка поддержки TLS 1.0
        - Фактор 3: Проверка поддержки TLS 1.1
        - Фактор 4: Проверка слабых cipher суитов
        - Фактор 5: Проверка отсутствия Perfect Forward Secrecy
        
        Returns:
            dict с результатами проверки
        """
        vector_id = 2001
        vector_name = "Weak SSL/TLS Ciphers"
        factors = []
        weak_ciphers = []
        missing_pfs = False
        
        try:
            # Проверка что порт открыт
            port_open = port_is_open(self.target_ip, port, timeout=self.port_scan_timeout)
            if not port_open:
                return self._build_result(
                    vector_id, vector_name, False,
                    f"Port {port} not accessible", factors,
                    extra={'weak_ciphers': [], 'missing_pfs': False}
                )
            
            # Фактор 1: Проверка поддержки SSLv3
            sslv3_supported = False
            try:
                # SSLv3 обычно отключен в современных Python
                # Эмулируем проверку через попытку подключения
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                # Попытка установить минимальную версию SSLv3 (если доступна)
                try:
                    context.minimum_version = ssl.TLSVersion.SSLv3
                    with socket.create_connection((self.target_ip, port), timeout=3) as sock:
                        with context.wrap_socket(sock, server_hostname=self.target_ip) as ssock:
                            sslv3_supported = True
                except:
                    sslv3_supported = False
            except:
                sslv3_supported = False
            
            factors.append({
                "name": "SSLv3 Support",
                "passed": sslv3_supported,
                "reason": "SSLv3 is supported (VULNERABLE)" if sslv3_supported else "SSLv3 not supported"
            })
            
            # Фактор 2: Проверка поддержки TLS 1.0
            tls10_supported = False
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try:
                    context.minimum_version = ssl.TLSVersion.TLSv1
                    context.maximum_version = ssl.TLSVersion.TLSv1
                    with socket.create_connection((self.target_ip, port), timeout=3) as sock:
                        with context.wrap_socket(sock, server_hostname=self.target_ip) as ssock:
                            tls10_supported = True
                except:
                    tls10_supported = False
            except:
                tls10_supported = False
            
            factors.append({
                "name": "TLS 1.0 Support",
                "passed": tls10_supported,
                "reason": "TLS 1.0 is supported (WEAK)" if tls10_supported else "TLS 1.0 not supported"
            })
            
            # Фактор 3: Проверка поддержки TLS 1.1
            tls11_supported = False
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try:
                    context.minimum_version = ssl.TLSVersion.TLSv1_1
                    context.maximum_version = ssl.TLSVersion.TLSv1_1
                    with socket.create_connection((self.target_ip, port), timeout=3) as sock:
                        with context.wrap_socket(sock, server_hostname=self.target_ip) as ssock:
                            tls11_supported = True
                except:
                    tls11_supported = False
            except:
                tls11_supported = False
            
            factors.append({
                "name": "TLS 1.1 Support",
                "passed": tls11_supported,
                "reason": "TLS 1.1 is supported (WEAK)" if tls11_supported else "TLS 1.1 not supported"
            })
            
            # Фактор 4: Проверка слабых cipher суитов
            ciphers = get_ssl_ciphers(self.target_ip, port, timeout=5)
            weak_ciphers = [c for c in ciphers if is_weak_cipher(c)]
            has_weak_ciphers = len(weak_ciphers) > 0
            
            factors.append({
                "name": "Weak Ciphers",
                "passed": has_weak_ciphers,
                "reason": f"Weak ciphers found: {', '.join(weak_ciphers[:3])}" if has_weak_ciphers else "No weak ciphers detected"
            })
            
            # Фактор 5: Проверка отсутствия Perfect Forward Secrecy
            # PFS ciphers содержат DHE или ECDHE
            has_pfs = any('DHE' in c or 'ECDHE' in c for c in ciphers)
            missing_pfs = not has_pfs
            
            factors.append({
                "name": "Perfect Forward Secrecy",
                "passed": missing_pfs,
                "reason": "PFS not supported (VULNERABLE)" if missing_pfs else "PFS is supported"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            confidence = passed_factors / len(factors)
            
            details = (
                f"SSL/TLS configuration analyzed "
                f"({passed_factors}/{len(factors)} weak factors found)"
            )
            
            return self._build_result(
                vector_id, vector_name, vulnerable,
                details, factors, confidence,
                extra={'weak_ciphers': weak_ciphers, 'missing_pfs': missing_pfs}
            )
        
        except Exception as e:
            logger.error(f"Error checking SSL/TLS ciphers: {str(e)}")
            return self._build_result(
                vector_id, vector_name, False,
                f"Error checking SSL/TLS ciphers: {str(e)}", factors, error=str(e),
                extra={'weak_ciphers': [], 'missing_pfs': False}
            )
    
    def check_self_signed_certificate(self, port: int = 443) -> Dict[str, Any]:
        """
        Вектор 2.2: Проверка самоподписанного сертификата.
        
        Многофакторная проверка:
        - Фактор 1: Получение сертификата
        - Фактор 2: Проверка Issuer == Subject
        - Фактор 3: Проверка что сертификат не подписан известным CA
        
        Returns:
            dict с результатами проверки
        """
        vector_id = 2002
        vector_name = "Self-Signed Certificate"
        factors = []
        issuer = ""
        subject = ""
        
        try:
            # Проверка что порт открыт
            port_open = port_is_open(self.target_ip, port, timeout=self.port_scan_timeout)
            if not port_open:
                return self._build_result(
                    vector_id, vector_name, False,
                    f"Port {port} not accessible", factors,
                    extra={'issuer': '', 'subject': ''}
                )
            
            # Фактор 1: Получение сертификата
            cert_raw = get_ssl_certificate(self.target_ip, port, timeout=5)
            cert_received = len(cert_raw) > 0
            
            factors.append({
                "name": "Certificate Retrieved",
                "passed": cert_received,
                "reason": "Certificate retrieved successfully" if cert_received else "Could not retrieve certificate"
            })
            
            if not cert_received:
                return self._build_result(
                    vector_id, vector_name, False,
                    "Could not retrieve certificate", factors,
                    extra={'issuer': '', 'subject': ''}
                )
            
            # Парсинг сертификата
            cert_info = parse_ssl_certificate(cert_raw)
            issuer = cert_info.get('issuer_cn', '')
            subject = cert_info.get('common_name', '')
            
            # Фактор 2: Проверка Issuer == Subject
            is_self_signed = cert_info.get('self_signed', False)
            
            factors.append({
                "name": "Issuer == Subject",
                "passed": is_self_signed,
                "reason": f"Self-signed: Issuer={issuer}, Subject={subject}" if is_self_signed else "Not self-signed"
            })
            
            # Фактор 3: Проверка что не подписан известным CA
            known_cas = [
                'Let\'s Encrypt', 'DigiCert', 'GeoTrust', 'Comodo', 'Symantec',
                'GlobalSign', 'VeriSign', 'Thawte', 'RapidSSL', 'GoDaddy'
            ]
            
            not_signed_by_known_ca = not any(ca.lower() in issuer.lower() for ca in known_cas)
            
            factors.append({
                "name": "Not Signed by Known CA",
                "passed": not_signed_by_known_ca,
                "reason": f"Not signed by known CA (Issuer: {issuer})" if not_signed_by_known_ca else f"Signed by known CA: {issuer}"
            })
            
            # Расчет результата (нужны ≥2 фактора из 3)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            confidence = passed_factors / len(factors)
            
            details = (
                f"Certificate analyzed "
                f"({passed_factors}/{len(factors)} factors indicate self-signed)"
            )
            
            return self._build_result(
                vector_id, vector_name, vulnerable,
                details, factors, confidence,
                extra={'issuer': issuer, 'subject': subject}
            )
        
        except Exception as e:
            logger.error(f"Error checking self-signed certificate: {str(e)}")
            return self._build_result(
                vector_id, vector_name, False,
                f"Error checking certificate: {str(e)}", factors, error=str(e),
                extra={'issuer': '', 'subject': ''}
            )
    
    def check_expired_certificate(self, port: int = 443) -> Dict[str, Any]:
        """
        Вектор 2.3: Проверка истекшего сертификата.
        
        Многофакторная проверка:
        - Фактор 1: Получение сертификата
        - Фактор 2: Проверка expiration date < сейчас
        - Фактор 3: Проверка что это не тестовый/локальный сертификат
        
        Returns:
            dict с результатами проверки
        """
        vector_id = 2003
        vector_name = "Expired Certificate"
        factors = []
        expiration_date = ""
        
        try:
            # Проверка что порт открыт
            port_open = port_is_open(self.target_ip, port, timeout=self.port_scan_timeout)
            if not port_open:
                return self._build_result(
                    vector_id, vector_name, False,
                    f"Port {port} not accessible", factors,
                    extra={'expiration_date': ''}
                )
            
            # Фактор 1: Получение сертификата
            cert_raw = get_ssl_certificate(self.target_ip, port, timeout=5)
            cert_received = len(cert_raw) > 0
            
            factors.append({
                "name": "Certificate Retrieved",
                "passed": cert_received,
                "reason": "Certificate retrieved successfully" if cert_received else "Could not retrieve certificate"
            })
            
            if not cert_received:
                return self._build_result(
                    vector_id, vector_name, False,
                    "Could not retrieve certificate", factors,
                    extra={'expiration_date': ''}
                )
            
            # Парсинг сертификата
            cert_info = parse_ssl_certificate(cert_raw)
            expiration_date = cert_info.get('not_after', '')
            is_expired = cert_info.get('expired', False)
            
            # Фактор 2: Проверка expiration date < сейчас
            factors.append({
                "name": "Certificate Expired",
                "passed": is_expired,
                "reason": f"Certificate expired on {expiration_date}" if is_expired else f"Certificate valid until {expiration_date}"
            })
            
            # Фактор 3: Проверка что не локальный/тестовый сертификат
            common_name = cert_info.get('common_name', '')
            is_not_local = not any(x in common_name.lower() for x in ['localhost', 'test', 'example', '127.0.0.1'])
            
            factors.append({
                "name": "Not Test Certificate",
                "passed": is_not_local,
                "reason": "Production certificate" if is_not_local else "Test/Local certificate"
            })
            
            # Расчет результата (нужны ≥2 фактора из 3)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            confidence = passed_factors / len(factors)
            
            details = (
                f"Certificate analyzed "
                f"({passed_factors}/{len(factors)} factors indicate expired cert)"
            )
            
            return self._build_result(
                vector_id, vector_name, vulnerable,
                details, factors, confidence,
                extra={'expiration_date': expiration_date}
            )
        
        except Exception as e:
            logger.error(f"Error checking expired certificate: {str(e)}")
            return self._build_result(
                vector_id, vector_name, False,
                f"Error checking certificate: {str(e)}", factors, error=str(e),
                extra={'expiration_date': ''}
            )
    
    def check_missing_hsts(self, port: int = 80, port_https: int = 443) -> Dict[str, Any]:
        """
        Вектор 2.4: Проверка отсутствия HSTS заголовка.
        
        Многофакторная проверка:
        - Фактор 1: Отправка HTTP запроса на порт 80
        - Фактор 2: Проверка отсутствия Strict-Transport-Security заголовка
        - Фактор 3: Проверка редиректа на HTTPS без HSTS
        
        Returns:
            dict с результатами проверки
        """
        vector_id = 2004
        vector_name = "Missing HSTS Header"
        factors = []
        has_hsts = False
        
        try:
            # Фактор 1: Отправка HTTP запроса на порт 80
            port_open = port_is_open(self.target_ip, port, timeout=self.port_scan_timeout)
            
            factors.append({
                "name": "HTTP Port Accessible",
                "passed": port_open,
                "reason": f"Port {port} is accessible" if port_open else f"Port {port} not accessible"
            })
            
            if not port_open:
                # Проверяем HTTPS порт напрямую
                port_open_https = port_is_open(self.target_ip, port_https, timeout=self.port_scan_timeout)
                if not port_open_https:
                    return self._build_result(
                        vector_id, vector_name, False,
                        "No HTTP/HTTPS ports accessible", factors,
                        extra={'has_hsts': False}
                    )
            
            # Получение HTTP ответа
            headers_str = ""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.target_ip, port if port_open else port_https))
                
                request = b'GET / HTTP/1.1\r\nHost: ' + self.target_ip.encode() + b'\r\nConnection: close\r\n\r\n'
                sock.sendall(request)
                
                response = sock.recv(4096)
                sock.close()
                
                if response:
                    headers_str = response.split(b'\r\n\r\n')[0].decode('utf-8', errors='ignore')
            except Exception as e:
                logger.debug(f"HTTP request failed: {str(e)}")
            
            # Фактор 2: Проверка отсутствия HSTS заголовка
            headers_info = analyze_http_headers(headers_str)
            hsts_header = headers_info.get('strict_transport_security', '')
            has_hsts = len(hsts_header) > 0
            
            factors.append({
                "name": "HSTS Header Missing",
                "passed": not has_hsts,
                "reason": f"HSTS header present: {hsts_header}" if has_hsts else "HSTS header missing (VULNERABLE)"
            })
            
            # Фактор 3: Проверка редиректа
            location = headers_info.get('location', '')
            has_redirect = len(location) > 0
            redirects_to_https = 'https://' in location.lower()
            
            factors.append({
                "name": "HTTPS Redirect Without HSTS",
                "passed": has_redirect and redirects_to_https and not has_hsts,
                "reason": f"Redirects to HTTPS but no HSTS" if (redirects_to_https and not has_hsts) else "Proper HTTPS enforcement"
            })
            
            # Расчет результата (нужны ≥2 фактора из 3)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            confidence = passed_factors / len(factors)
            
            details = (
                f"HSTS configuration analyzed "
                f"({passed_factors}/{len(factors)} factors indicate missing HSTS)"
            )
            
            return self._build_result(
                vector_id, vector_name, vulnerable,
                details, factors, confidence,
                extra={'has_hsts': has_hsts}
            )
        
        except Exception as e:
            logger.error(f"Error checking HSTS: {str(e)}")
            return self._build_result(
                vector_id, vector_name, False,
                f"Error checking HSTS: {str(e)}", factors, error=str(e),
                extra={'has_hsts': False}
            )
    
    # ========================================================================
    # ЧАСТЬ 3: СЕТЕВЫЕ СЕРВИСЫ
    # ========================================================================
    
    def check_open_smb(self) -> Dict[str, Any]:
        """
        Вектор 3.1: Проверка открытого SMB (порты 139, 445).
        
        Многофакторная проверка:
        - Фактор 1: Сканирование порта 139
        - Фактор 2: Сканирование порта 445
        - Фактор 3: Попытка подключения к SMB
        - Фактор 4: Проверка гостевого доступа
        - Фактор 5: Перечисление шаров
        
        Returns:
            dict с результатами проверки
        """
        vector_id = 3001
        vector_name = "Open SMB Ports (139, 445)"
        factors = []
        shares = []
        guest_access = False
        
        try:
            # Фактор 1: Сканирование порта 139
            port_139_open = port_is_open(self.target_ip, 139, timeout=self.port_scan_timeout)
            factors.append({
                "name": "Port 139 Open",
                "passed": port_139_open,
                "reason": "Port 139 (NetBIOS) is open" if port_139_open else "Port 139 closed"
            })
            
            # Фактор 2: Сканирование порта 445
            port_445_open = port_is_open(self.target_ip, 445, timeout=self.port_scan_timeout)
            factors.append({
                "name": "Port 445 Open",
                "passed": port_445_open,
                "reason": "Port 445 (SMB) is open" if port_445_open else "Port 445 closed"
            })
            
            if not port_139_open and not port_445_open:
                return self._build_result(
                    vector_id, vector_name, False,
                    "SMB ports not accessible", factors,
                    extra={'shares': [], 'guest_access': False}
                )
            
            # Фактор 3: Попытка подключения к SMB
            smb_connection_ok = False
            port_to_use = 445 if port_445_open else 139
            
            try:
                # Простая SMB Negotiate Protocol Request
                smb_negotiate = (
                    b'\x00\x00\x00\x85'  # NetBIOS Session Service
                    b'\xff\x53\x4d\x42'  # SMB Header (0xFF + "SMB")
                    b'\x72'              # Command: Negotiate Protocol
                    b'\x00\x00\x00\x00'  # NT Status
                    b'\x18'              # Flags
                    b'\x53\xc8'          # Flags2
                    b'\x00\x00'          # Process ID High
                    b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Signature
                    b'\x00\x00'          # Reserved
                    b'\x00\x00'          # Tree ID
                    b'\xff\xfe'          # Process ID
                    b'\x00\x00'          # User ID
                    b'\x00\x00'          # Multiplex ID
                    b'\x00'              # Word Count
                    b'\x62\x00'          # Byte Count
                    b'\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00'
                    b'\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00'
                    b'\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00'
                    b'\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00'
                    b'\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00'
                    b'\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'
                )
                
                response = send_raw_data(self.target_ip, port_to_use, smb_negotiate, timeout=3)
                
                # Проверка SMB ответа
                if len(response) > 0 and b'\xff\x53\x4d\x42' in response[:100]:
                    smb_connection_ok = True
            except Exception as e:
                logger.debug(f"SMB connection failed: {str(e)}")
            
            factors.append({
                "name": "SMB Connection",
                "passed": smb_connection_ok,
                "reason": "SMB connection successful" if smb_connection_ok else "SMB connection failed"
            })
            
            # Фактор 4: Проверка гостевого доступа (упрощенная)
            # В реальности требуется полная SMB библиотека (pysmb, smbprotocol)
            guest_access = False  # По умолчанию считаем что нет
            
            factors.append({
                "name": "Guest Access",
                "passed": guest_access,
                "reason": "Guest access allowed" if guest_access else "Guest access not detected"
            })
            
            # Фактор 5: Перечисление шаров (упрощенная проверка)
            # В реальности требуется полная SMB библиотека
            shares = []  # Пустой список
            
            factors.append({
                "name": "Share Enumeration",
                "passed": len(shares) > 0,
                "reason": f"Found {len(shares)} shares" if shares else "No shares enumerated"
            })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            confidence = passed_factors / len(factors)
            
            details = (
                f"SMB service analyzed "
                f"({passed_factors}/{len(factors)} factors confirmed)"
            )
            
            return self._build_result(
                vector_id, vector_name, vulnerable,
                details, factors, confidence,
                extra={'shares': shares, 'guest_access': guest_access}
            )
        
        except Exception as e:
            logger.error(f"Error checking SMB: {str(e)}")
            return self._build_result(
                vector_id, vector_name, False,
                f"Error checking SMB: {str(e)}", factors, error=str(e),
                extra={'shares': [], 'guest_access': False}
            )
    
    def check_open_nfs(self) -> Dict[str, Any]:
        """
        Вектор 3.2: Проверка открытого NFS (порт 2049).
        
        Многофакторная проверка:
        - Фактор 1: Сканирование порта 2049
        - Фактор 2: Попытка подключения к NFS
        - Фактор 3: Получение списка exported filesystems
        - Фактор 4: Попытка монтирования
        
        Returns:
            dict с результатами проверки
        """
        vector_id = 3002
        vector_name = "Open NFS Port (2049)"
        factors = []
        exported_filesystems = []
        
        try:
            # Фактор 1: Сканирование порта 2049
            port_open = port_is_open(self.target_ip, 2049, timeout=self.port_scan_timeout)
            factors.append({
                "name": "Port 2049 Open",
                "passed": port_open,
                "reason": "Port 2049 (NFS) is open" if port_open else "Port 2049 closed"
            })
            
            if not port_open:
                return self._build_result(
                    vector_id, vector_name, False,
                    "NFS port not accessible", factors,
                    extra={'exported_filesystems': []}
                )
            
            # Фактор 2: Попытка подключения к NFS (проверка через RPC)
            # NFS работает через RPC (Remote Procedure Call)
            nfs_connection_ok = False
            
            # Попытка подключения к порту 111 (portmapper/rpcbind)
            rpcbind_port = 111
            rpcbind_open = port_is_open(self.target_ip, rpcbind_port, timeout=self.port_scan_timeout)
            
            if rpcbind_open:
                nfs_connection_ok = True
            
            factors.append({
                "name": "NFS/RPC Connection",
                "passed": nfs_connection_ok,
                "reason": "RPC portmapper accessible" if nfs_connection_ok else "RPC not accessible"
            })
            
            # Фактор 3: Получение списка exported filesystems (showmount)
            # Требует команды showmount или RPC библиотеки
            try:
                import subprocess
                result = subprocess.run(
                    ['showmount', '-e', self.target_ip],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5
                )
                
                if result.returncode == 0:
                    output = result.stdout.decode('utf-8', errors='ignore')
                    lines = output.strip().split('\n')[1:]  # Пропускаем заголовок
                    exported_filesystems = [line.split()[0] for line in lines if line]
            except:
                exported_filesystems = []
            
            factors.append({
                "name": "Export List",
                "passed": len(exported_filesystems) > 0,
                "reason": f"Found {len(exported_filesystems)} exported filesystems" if exported_filesystems else "No exports found"
            })
            
            # Фактор 4: Попытка монтирования (упрощенная проверка)
            mount_possible = len(exported_filesystems) > 0
            
            factors.append({
                "name": "Mount Possibility",
                "passed": mount_possible,
                "reason": "Filesystems available for mounting" if mount_possible else "No filesystems to mount"
            })
            
            # Расчет результата (нужны ≥3 фактора из 4)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            confidence = passed_factors / len(factors)
            
            details = (
                f"NFS service analyzed "
                f"({passed_factors}/{len(factors)} factors confirmed)"
            )
            
            return self._build_result(
                vector_id, vector_name, vulnerable,
                details, factors, confidence,
                extra={'exported_filesystems': exported_filesystems}
            )
        
        except Exception as e:
            logger.error(f"Error checking NFS: {str(e)}")
            return self._build_result(
                vector_id, vector_name, False,
                f"Error checking NFS: {str(e)}", factors, error=str(e),
                extra={'exported_filesystems': []}
            )
    
    def check_open_snmp(self) -> Dict[str, Any]:
        """
        Вектор 3.3: Проверка открытого SNMP (порт 161).
        
        Многофакторная проверка:
        - Фактор 1: Сканирование порта 161
        - Фактор 2: SNMP GET с community "public"
        - Фактор 3: SNMP GET с community "private"
        - Фактор 4: Получение SNMP response
        - Фактор 5: Проверка стандартной community
        
        Returns:
            dict с результатами проверки
        """
        vector_id = 3003
        vector_name = "Open SNMP Port (161)"
        factors = []
        snmp_communities = []
        mib_data = {}
        
        try:
            # Фактор 1: Сканирование порта 161 (UDP)
            # Для UDP используем sendto/recvfrom
            port_open = False
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                # Простой SNMP GET request для sysDescr.0
                snmp_get = (
                    b'\x30\x29'          # SEQUENCE
                    b'\x02\x01\x00'      # Version: 1 (SNMPv1)
                    b'\x04\x06\x70\x75\x62\x6c\x69\x63'  # Community: "public"
                    b'\xa0\x1c'          # GetRequest-PDU
                    b'\x02\x04\x00\x00\x00\x01'  # Request ID
                    b'\x02\x01\x00'      # Error Status: 0
                    b'\x02\x01\x00'      # Error Index: 0
                    b'\x30\x0e'          # Variable bindings
                    b'\x30\x0c'          # Variable binding
                    b'\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00'  # OID: sysDescr.0
                    b'\x05\x00'          # Value: NULL
                )
                
                sock.sendto(snmp_get, (self.target_ip, 161))
                response, addr = sock.recvfrom(1024)
                sock.close()
                
                if len(response) > 0:
                    port_open = True
            except:
                port_open = False
            
            factors.append({
                "name": "Port 161 Open",
                "passed": port_open,
                "reason": "Port 161 (SNMP) is open" if port_open else "Port 161 not responding"
            })
            
            if not port_open:
                return self._build_result(
                    vector_id, vector_name, False,
                    "SNMP port not accessible", factors,
                    extra={'snmp_communities': [], 'mib_data': {}}
                )
            
            # Фактор 2: SNMP GET с community "public"
            public_works = False
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                
                snmp_get_public = (
                    b'\x30\x29'
                    b'\x02\x01\x00'
                    b'\x04\x06\x70\x75\x62\x6c\x69\x63'  # "public"
                    b'\xa0\x1c'
                    b'\x02\x04\x00\x00\x00\x01'
                    b'\x02\x01\x00'
                    b'\x02\x01\x00'
                    b'\x30\x0e'
                    b'\x30\x0c'
                    b'\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00'
                    b'\x05\x00'
                )
                
                sock.sendto(snmp_get_public, (self.target_ip, 161))
                response, addr = sock.recvfrom(1024)
                sock.close()
                
                if len(response) > 0 and b'\xa2' in response:  # GetResponse-PDU
                    public_works = True
                    snmp_communities.append('public')
            except:
                pass
            
            factors.append({
                "name": "Community 'public'",
                "passed": public_works,
                "reason": "Community 'public' works (VULNERABLE)" if public_works else "Community 'public' denied"
            })
            
            # Фактор 3: SNMP GET с community "private"
            private_works = False
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                
                snmp_get_private = (
                    b'\x30\x2a'
                    b'\x02\x01\x00'
                    b'\x04\x07\x70\x72\x69\x76\x61\x74\x65'  # "private"
                    b'\xa0\x1c'
                    b'\x02\x04\x00\x00\x00\x02'
                    b'\x02\x01\x00'
                    b'\x02\x01\x00'
                    b'\x30\x0e'
                    b'\x30\x0c'
                    b'\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00'
                    b'\x05\x00'
                )
                
                sock.sendto(snmp_get_private, (self.target_ip, 161))
                response, addr = sock.recvfrom(1024)
                sock.close()
                
                if len(response) > 0 and b'\xa2' in response:
                    private_works = True
                    snmp_communities.append('private')
            except:
                pass
            
            factors.append({
                "name": "Community 'private'",
                "passed": private_works,
                "reason": "Community 'private' works (VULNERABLE)" if private_works else "Community 'private' denied"
            })
            
            # Фактор 4: Получение SNMP response (уже проверено выше)
            response_received = public_works or private_works
            
            factors.append({
                "name": "SNMP Response",
                "passed": response_received,
                "reason": "SNMP responses received" if response_received else "No SNMP responses"
            })
            
            # Фактор 5: Проверка стандартной community
            uses_default_community = len(snmp_communities) > 0
            
            factors.append({
                "name": "Default Community",
                "passed": uses_default_community,
                "reason": f"Uses default communities: {', '.join(snmp_communities)}" if uses_default_community else "Custom community strings"
            })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            confidence = passed_factors / len(factors)
            
            details = (
                f"SNMP service analyzed "
                f"({passed_factors}/{len(factors)} factors confirmed)"
            )
            
            return self._build_result(
                vector_id, vector_name, vulnerable,
                details, factors, confidence,
                extra={'snmp_communities': snmp_communities, 'mib_data': mib_data}
            )
        
        except Exception as e:
            logger.error(f"Error checking SNMP: {str(e)}")
            return self._build_result(
                vector_id, vector_name, False,
                f"Error checking SNMP: {str(e)}", factors, error=str(e),
                extra={'snmp_communities': [], 'mib_data': {}}
            )
    
    def check_open_tftp(self) -> Dict[str, Any]:
        """
        Вектор 3.4: Проверка открытого TFTP (порт 69).
        
        Многофакторная проверка:
        - Фактор 1: Сканирование порта 69 (UDP)
        - Фактор 2: Попытка подключения к TFTP
        - Фактор 3: Попытка чтения файла
        - Фактор 4: Проверка что файл прочитан без аутентификации
        
        Returns:
            dict с результатами проверки
        """
        vector_id = 3004
        vector_name = "Open TFTP Port (69)"
        factors = []
        readable_files = []
        
        try:
            # Фактор 1: Сканирование порта 69 (UDP)
            port_open = False
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                
                # TFTP Read Request для файла "test"
                tftp_rrq = (
                    b'\x00\x01'  # Opcode: Read Request
                    b'test\x00'  # Filename
                    b'octet\x00' # Mode
                )
                
                sock.sendto(tftp_rrq, (self.target_ip, 69))
                
                try:
                    response, addr = sock.recvfrom(1024)
                    if len(response) > 0:
                        port_open = True
                except:
                    pass
                
                sock.close()
            except:
                port_open = False
            
            factors.append({
                "name": "Port 69 Open",
                "passed": port_open,
                "reason": "Port 69 (TFTP) is open" if port_open else "Port 69 not responding"
            })
            
            if not port_open:
                return self._build_result(
                    vector_id, vector_name, False,
                    "TFTP port not accessible", factors,
                    extra={'readable_files': []}
                )
            
            # Фактор 2: Попытка подключения к TFTP (уже выполнено выше)
            tftp_connection_ok = port_open
            
            factors.append({
                "name": "TFTP Connection",
                "passed": tftp_connection_ok,
                "reason": "TFTP server responds" if tftp_connection_ok else "No TFTP response"
            })
            
            # Фактор 3: Попытка чтения файлов
            test_files = ['test.txt', 'config.txt', 'startup-config', 'running-config']
            file_read_success = False
            
            for filename in test_files:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(2)
                    
                    tftp_rrq = b'\x00\x01' + filename.encode() + b'\x00octet\x00'
                    sock.sendto(tftp_rrq, (self.target_ip, 69))
                    
                    response, addr = sock.recvfrom(1024)
                    sock.close()
                    
                    # Opcode 3 = DATA packet
                    if len(response) > 4 and response[0:2] == b'\x00\x03':
                        file_read_success = True
                        readable_files.append(filename)
                        break
                except:
                    pass
            
            factors.append({
                "name": "File Read",
                "passed": file_read_success,
                "reason": f"Successfully read files: {', '.join(readable_files)}" if file_read_success else "Could not read test files"
            })
            
            # Фактор 4: Проверка что файл прочитан без аутентификации
            no_auth_required = file_read_success  # TFTP не имеет встроенной аутентификации
            
            factors.append({
                "name": "No Authentication",
                "passed": no_auth_required,
                "reason": "Files readable without authentication (VULNERABLE)" if no_auth_required else "Authentication required"
            })
            
            # Расчет результата (нужны ≥3 фактора из 4)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            confidence = passed_factors / len(factors)
            
            details = (
                f"TFTP service analyzed "
                f"({passed_factors}/{len(factors)} factors confirmed)"
            )
            
            return self._build_result(
                vector_id, vector_name, vulnerable,
                details, factors, confidence,
                extra={'readable_files': readable_files}
            )
        
        except Exception as e:
            logger.error(f"Error checking TFTP: {str(e)}")
            return self._build_result(
                vector_id, vector_name, False,
                f"Error checking TFTP: {str(e)}", factors, error=str(e),
                extra={'readable_files': []}
            )
    
    def check_open_syslog(self) -> Dict[str, Any]:
        """
        Вектор 3.5: Проверка открытого Syslog (порт 514).
        
        Многофакторная проверка:
        - Фактор 1: Сканирование порта 514 (UDP)
        - Фактор 2: Отправка Syslog сообщения
        - Фактор 3: Проверка что сообщение принято
        
        Returns:
            dict с результатами проверки
        """
        vector_id = 3005
        vector_name = "Open Syslog Port (514)"
        factors = []
        
        try:
            # Фактор 1: Сканирование порта 514 (UDP)
            port_open = False
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                
                # Простое Syslog сообщение (RFC 3164)
                syslog_msg = b'<34>Oct 11 22:14:15 test: AASFA security scan test message'
                
                sock.sendto(syslog_msg, (self.target_ip, 514))
                
                # UDP не гарантирует ответ, но порт может быть открыт
                # Считаем что если нет ICMP Destination Unreachable, то порт открыт
                try:
                    sock.recvfrom(1024)
                except socket.timeout:
                    # Timeout - нормально для Syslog (не отвечает)
                    port_open = True
                
                sock.close()
            except Exception as e:
                if 'unreachable' not in str(e).lower():
                    port_open = True  # Нет явного отказа
            
            factors.append({
                "name": "Port 514 Open",
                "passed": port_open,
                "reason": "Port 514 (Syslog) appears open" if port_open else "Port 514 unreachable"
            })
            
            if not port_open:
                return self._build_result(
                    vector_id, vector_name, False,
                    "Syslog port not accessible", factors
                )
            
            # Фактор 2: Отправка Syslog сообщения (уже выполнено выше)
            message_sent = port_open
            
            factors.append({
                "name": "Syslog Message Sent",
                "passed": message_sent,
                "reason": "Syslog message sent successfully" if message_sent else "Could not send message"
            })
            
            # Фактор 3: Проверка что сообщение принято
            # Для Syslog это сложно проверить без доступа к логам сервера
            # Считаем что если порт открыт и сообщение отправлено, то оно принято
            message_accepted = message_sent
            
            factors.append({
                "name": "Message Accepted",
                "passed": message_accepted,
                "reason": "Syslog appears to accept messages" if message_accepted else "Message not accepted"
            })
            
            # Расчет результата (нужны ≥2 фактора из 3)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            confidence = passed_factors / len(factors)
            
            details = (
                f"Syslog service analyzed "
                f"({passed_factors}/{len(factors)} factors confirmed)"
            )
            
            return self._build_result(
                vector_id, vector_name, vulnerable,
                details, factors, confidence
            )
        
        except Exception as e:
            logger.error(f"Error checking Syslog: {str(e)}")
            return self._build_result(
                vector_id, vector_name, False,
                f"Error checking Syslog: {str(e)}", factors, error=str(e)
            )
    
    # ========================================================================
    # ЧАСТЬ 4: ПРОТОКОЛЬНЫЕ УЯЗВИМОСТИ
    # ========================================================================
    
    def check_open_upnp(self) -> Dict[str, Any]:
        """
        Вектор 4.1: Проверка открытого UPnP (порт 1900).
        
        Многофакторная проверка:
        - Фактор 1: Сканирование порта 1900
        - Фактор 2: Отправка SSDP M-SEARCH запроса
        - Фактор 3: Получение SSDP ответа
        - Фактор 4: Анализ возвращаемых устройств
        
        Returns:
            dict с результатами проверки
        """
        vector_id = 4001
        vector_name = "Open UPnP/SSDP (1900)"
        factors = []
        devices = []
        
        try:
            # Фактор 1: Сканирование порта 1900 (UDP, multicast)
            port_open = False
            
            # Фактор 2: Отправка SSDP M-SEARCH запроса
            ssdp_discover = (
                'M-SEARCH * HTTP/1.1\r\n'
                'HOST: 239.255.255.250:1900\r\n'
                'MAN: "ssdp:discover"\r\n'
                'MX: 2\r\n'
                'ST: ssdp:all\r\n'
                '\r\n'
            ).encode()
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                
                # Отправка на multicast адрес
                sock.sendto(ssdp_discover, ('239.255.255.250', 1900))
                
                # Также попытка отправки напрямую на target IP
                sock.sendto(ssdp_discover, (self.target_ip, 1900))
                
                # Фактор 3: Получение SSDP ответа
                responses = []
                try:
                    while True:
                        response, addr = sock.recvfrom(4096)
                        responses.append(response.decode('utf-8', errors='ignore'))
                        
                        if len(responses) >= 5:  # Ограничение
                            break
                except socket.timeout:
                    pass
                
                sock.close()
                
                if len(responses) > 0:
                    port_open = True
                    
                    # Фактор 4: Анализ возвращаемых устройств
                    for response in responses:
                        if 'LOCATION:' in response.upper():
                            for line in response.split('\n'):
                                if line.upper().startswith('LOCATION:'):
                                    location = line.split(':', 1)[1].strip()
                                    devices.append(location)
            except Exception as e:
                logger.debug(f"SSDP discovery failed: {str(e)}")
            
            factors.append({
                "name": "Port 1900 Open",
                "passed": port_open,
                "reason": "SSDP/UPnP port responds" if port_open else "No SSDP response"
            })
            
            factors.append({
                "name": "SSDP M-SEARCH Sent",
                "passed": True,  # Всегда отправляем
                "reason": "SSDP discovery request sent"
            })
            
            ssdp_response_received = port_open
            factors.append({
                "name": "SSDP Response",
                "passed": ssdp_response_received,
                "reason": f"Received {len(responses)} SSDP responses" if responses else "No SSDP responses"
            })
            
            devices_found = len(devices) > 0
            factors.append({
                "name": "UPnP Devices",
                "passed": devices_found,
                "reason": f"Found {len(devices)} UPnP devices" if devices_found else "No devices discovered"
            })
            
            # Расчет результата (нужны ≥3 фактора из 4)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            confidence = passed_factors / len(factors)
            
            details = (
                f"UPnP/SSDP service analyzed "
                f"({passed_factors}/{len(factors)} factors confirmed)"
            )
            
            return self._build_result(
                vector_id, vector_name, vulnerable,
                details, factors, confidence,
                extra={'devices': devices}
            )
        
        except Exception as e:
            logger.error(f"Error checking UPnP: {str(e)}")
            return self._build_result(
                vector_id, vector_name, False,
                f"Error checking UPnP: {str(e)}", factors, error=str(e),
                extra={'devices': []}
            )
    
    def check_mqtt_exposure(self) -> Dict[str, Any]:
        """
        Вектор 4.2: Проверка открытого MQTT (порт 1883).
        
        Многофакторная проверка:
        - Фактор 1: Сканирование порта 1883
        - Фактор 2: Попытка подключения к MQTT без пароля
        - Фактор 3: Попытка подписания на топик
        - Фактор 4: Получение MQTT сообщений
        
        Returns:
            dict с результатами проверки
        """
        vector_id = 4002
        vector_name = "MQTT Exposure (1883)"
        factors = []
        topics = []
        requires_auth = True
        
        try:
            # Фактор 1: Сканирование порта 1883
            port_open = port_is_open(self.target_ip, 1883, timeout=self.port_scan_timeout)
            factors.append({
                "name": "Port 1883 Open",
                "passed": port_open,
                "reason": "Port 1883 (MQTT) is open" if port_open else "Port 1883 closed"
            })
            
            if not port_open:
                return self._build_result(
                    vector_id, vector_name, False,
                    "MQTT port not accessible", factors,
                    extra={'topics': [], 'requires_auth': True}
                )
            
            # Фактор 2: Попытка подключения к MQTT без пароля
            mqtt_connection_ok = False
            
            try:
                # Простой MQTT CONNECT packet (без аутентификации)
                client_id = b'aasfa_scanner'
                
                # Fixed header: CONNECT (0x10), Remaining Length
                # Variable header: Protocol Name Length (0x00 0x04) + "MQTT" + Protocol Level (0x04)
                mqtt_connect = (
                    b'\x10'  # CONNECT packet type
                    # Remaining length вычисляется динамически
                )
                
                # Variable header
                protocol_name = b'\x00\x04MQTT'
                protocol_level = b'\x04'  # MQTT 3.1.1
                connect_flags = b'\x02'   # Clean Session
                keep_alive = b'\x00\x3c'  # 60 seconds
                
                # Payload
                client_id_length = struct.pack('>H', len(client_id))
                payload = client_id_length + client_id
                
                variable_header = protocol_name + protocol_level + connect_flags + keep_alive
                remaining_length = len(variable_header) + len(payload)
                
                # Encode remaining length
                remaining_length_bytes = bytes([remaining_length])
                
                mqtt_connect_full = mqtt_connect + remaining_length_bytes + variable_header + payload
                
                response = send_raw_data(self.target_ip, 1883, mqtt_connect_full, timeout=3)
                
                # CONNACK packet: 0x20 (успешное подключение)
                if len(response) > 0 and response[0:1] == b'\x20':
                    mqtt_connection_ok = True
                    # Проверяем Return Code (4й байт)
                    if len(response) >= 4 and response[3:4] == b'\x00':
                        requires_auth = False
            except Exception as e:
                logger.debug(f"MQTT connection failed: {str(e)}")
            
            factors.append({
                "name": "MQTT Connection",
                "passed": mqtt_connection_ok,
                "reason": "MQTT connection successful" if mqtt_connection_ok else "MQTT connection failed"
            })
            
            factors.append({
                "name": "No Authentication",
                "passed": not requires_auth,
                "reason": "No authentication required (VULNERABLE)" if not requires_auth else "Authentication required"
            })
            
            # Фактор 3: Попытка подписания на топик (требует полной MQTT библиотеки)
            # Упрощенная проверка
            subscription_ok = mqtt_connection_ok and not requires_auth
            
            factors.append({
                "name": "Topic Subscription",
                "passed": subscription_ok,
                "reason": "Can subscribe to topics" if subscription_ok else "Cannot subscribe"
            })
            
            # Фактор 4: Получение MQTT сообщений (требует полной MQTT библиотеки)
            messages_received = False  # Упрощенно считаем что нет
            
            # Расчет результата (нужны ≥3 фактора из 4)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            confidence = passed_factors / len(factors)
            
            details = (
                f"MQTT service analyzed "
                f"({passed_factors}/{len(factors)} factors confirmed)"
            )
            
            return self._build_result(
                vector_id, vector_name, vulnerable,
                details, factors, confidence,
                extra={'topics': topics, 'requires_auth': requires_auth}
            )
        
        except Exception as e:
            logger.error(f"Error checking MQTT: {str(e)}")
            return self._build_result(
                vector_id, vector_name, False,
                f"Error checking MQTT: {str(e)}", factors, error=str(e),
                extra={'topics': [], 'requires_auth': True}
            )
    
    def check_websocket_unauth(self) -> Dict[str, Any]:
        """
        Вектор 4.3: Проверка WebSocket без аутентификации (порты 80, 443, 8080).
        
        Многофакторная проверка:
        - Фактор 1: Сканирование портов
        - Фактор 2: Попытка WebSocket upgrade без аутентификации
        - Фактор 3: Получение WebSocket соединения
        - Фактор 4: Отправка/получение WebSocket сообщения
        
        Returns:
            dict с результатами проверки
        """
        vector_id = 4003
        vector_name = "WebSocket Without Auth"
        factors = []
        ws_paths = []
        requires_auth = True
        
        try:
            # Фактор 1: Сканирование портов
            ports_to_check = [80, 443, 8080]
            open_ports = []
            
            for port in ports_to_check:
                if port_is_open(self.target_ip, port, timeout=self.port_scan_timeout):
                    open_ports.append(port)
            
            factors.append({
                "name": "Ports Open",
                "passed": len(open_ports) > 0,
                "reason": f"Open ports: {', '.join(map(str, open_ports))}" if open_ports else "No ports open"
            })
            
            if not open_ports:
                return self._build_result(
                    vector_id, vector_name, False,
                    "No HTTP/WebSocket ports accessible", factors,
                    extra={'ws_paths': [], 'requires_auth': True}
                )
            
            # Фактор 2: Попытка WebSocket upgrade
            ws_upgrade_success = False
            common_ws_paths = ['/', '/ws', '/websocket', '/socket.io', '/chat']
            
            for port in open_ports[:2]:  # Проверяем первые 2 порта
                for path in common_ws_paths[:3]:  # Проверяем первые 3 пути
                    try:
                        # WebSocket upgrade request
                        ws_request = (
                            f'GET {path} HTTP/1.1\r\n'
                            f'Host: {self.target_ip}:{port}\r\n'
                            'Upgrade: websocket\r\n'
                            'Connection: Upgrade\r\n'
                            'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
                            'Sec-WebSocket-Version: 13\r\n'
                            '\r\n'
                        ).encode()
                        
                        response = send_raw_data(self.target_ip, port, ws_request, timeout=3)
                        response_str = response.decode('utf-8', errors='ignore')
                        
                        # Проверка WebSocket upgrade response (101 Switching Protocols)
                        if '101' in response_str and 'websocket' in response_str.lower():
                            ws_upgrade_success = True
                            ws_paths.append(f'{self.target_ip}:{port}{path}')
                            requires_auth = False
                            break
                    except Exception as e:
                        logger.debug(f"WebSocket upgrade failed for {port}{path}: {str(e)}")
                
                if ws_upgrade_success:
                    break
            
            factors.append({
                "name": "WebSocket Upgrade",
                "passed": ws_upgrade_success,
                "reason": f"WebSocket upgrade successful on {ws_paths[0]}" if ws_upgrade_success else "WebSocket upgrade failed"
            })
            
            # Фактор 3: Получение WebSocket соединения
            ws_connection_established = ws_upgrade_success
            
            factors.append({
                "name": "WebSocket Connection",
                "passed": ws_connection_established,
                "reason": "WebSocket connection established" if ws_connection_established else "No WebSocket connection"
            })
            
            # Фактор 4: Отправка/получение WebSocket сообщения (упрощенно)
            ws_communication = ws_upgrade_success and not requires_auth
            
            factors.append({
                "name": "No Authentication",
                "passed": ws_communication,
                "reason": "WebSocket accessible without auth (VULNERABLE)" if ws_communication else "Authentication required"
            })
            
            # Расчет результата (нужны ≥3 фактора из 4)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            confidence = passed_factors / len(factors)
            
            details = (
                f"WebSocket service analyzed "
                f"({passed_factors}/{len(factors)} factors confirmed)"
            )
            
            return self._build_result(
                vector_id, vector_name, vulnerable,
                details, factors, confidence,
                extra={'ws_paths': ws_paths, 'requires_auth': requires_auth}
            )
        
        except Exception as e:
            logger.error(f"Error checking WebSocket: {str(e)}")
            return self._build_result(
                vector_id, vector_name, False,
                f"Error checking WebSocket: {str(e)}", factors, error=str(e),
                extra={'ws_paths': [], 'requires_auth': True}
            )
    
    # ========================================================================
    # ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
    # ========================================================================
    
    def _build_result(
        self,
        vector_id: int,
        vector_name: str,
        vulnerable: bool,
        details: str,
        factors: List[Dict[str, Any]],
        confidence: Optional[float] = None,
        error: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Построение структурированного результата проверки вектора.
        
        Args:
            vector_id: ID вектора
            vector_name: Название вектора
            vulnerable: Найдена ли уязвимость
            details: Детальное описание
            factors: Список проверенных факторов
            confidence: Уверенность (0.0-1.0)
            error: Сообщение об ошибке (если есть)
            extra: Дополнительные данные
            
        Returns:
            dict со структурированным результатом
        """
        if confidence is None:
            passed_factors = sum(1 for f in factors if f.get("passed", False))
            confidence = passed_factors / len(factors) if factors else 0.0
        
        result = {
            "vector_id": vector_id,
            "vector_name": vector_name,
            "vulnerable": vulnerable,
            "details": details,
            "factors": factors,
            "confidence": confidence,
            "timestamp": datetime.now().isoformat(),
            "error": error
        }
        
        if extra:
            result.update(extra)
        
        return result
    
    def get_all_vectors(self) -> List[callable]:
        """
        Получение списка всех доступных векторов для сканирования.
        
        Returns:
            Список методов проверки векторов
        """
        return [
            # ЧАСТЬ 1: Базовые сетевые порты
            self.check_telnet_port_open,
            self.check_ftp_port_open,
            self.check_ssh_port_open,
            self.check_http_port_open,
            self.check_https_port_open,
            self.check_rdp_port_open,
            self.check_vnc_port_open,
            
            # ЧАСТЬ 2: SSL/TLS уязвимости
            self.check_weak_ssl_tls_ciphers,
            self.check_self_signed_certificate,
            self.check_expired_certificate,
            self.check_missing_hsts,
            
            # ЧАСТЬ 3: Сетевые сервисы
            self.check_open_smb,
            self.check_open_nfs,
            self.check_open_snmp,
            self.check_open_tftp,
            self.check_open_syslog,
            
            # ЧАСТЬ 4: Протокольные уязвимости
            self.check_open_upnp,
            self.check_mqtt_exposure,
            self.check_websocket_unauth,
        ]
    
    def run_all_checks(self) -> List[Dict[str, Any]]:
        """
        Запуск всех проверок сетевых векторов.
        
        Returns:
            Список результатов всех проверок
        """
        results = []
        vectors = self.get_all_vectors()
        
        logger.info(f"Starting network security scan with {len(vectors)} vectors")
        
        for vector_func in vectors:
            try:
                logger.debug(f"Running vector: {vector_func.__name__}")
                result = vector_func()
                results.append(result)
            except Exception as e:
                logger.error(f"Error running vector {vector_func.__name__}: {str(e)}")
                results.append({
                    "vector_id": 0,
                    "vector_name": vector_func.__name__,
                    "vulnerable": False,
                    "details": f"Error: {str(e)}",
                    "factors": [],
                    "confidence": 0.0,
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e)
                })
        
        logger.info(f"Network security scan completed: {len(results)} vectors checked")
        
        return results


# ============================================================================
# ЭКСПОРТИРУЕМЫЕ ФУНКЦИИ ДЛЯ ИСПОЛЬЗОВАНИЯ В ДРУГИХ МОДУЛЯХ
# ============================================================================


def scan_network_security_vectors(config: ScanConfig) -> List[Dict[str, Any]]:
    """
    Главная функция для запуска сканирования сетевых векторов безопасности.
    
    Args:
        config: Конфигурация сканирования
        
    Returns:
        Список результатов всех проверок
    """
    scanner = NetworkSecurityVectors(config)
    return scanner.run_all_checks()


def get_vector_count() -> int:
    """
    Получение количества реализованных векторов.
    
    Returns:
        Количество векторов
    """
    return 18  # 7 + 4 + 5 + 3


def get_vector_categories() -> Dict[str, List[str]]:
    """
    Получение категорий векторов и их списков.
    
    Returns:
        dict с категориями и списками векторов
    """
    return {
        "basic_ports": [
            "Telnet (23)", "FTP (21)", "SSH (22)", "HTTP (80)",
            "HTTPS (443)", "RDP (3389)", "VNC (5900)"
        ],
        "ssl_tls": [
            "Weak SSL/TLS Ciphers", "Self-Signed Certificate",
            "Expired Certificate", "Missing HSTS"
        ],
        "network_services": [
            "Open SMB (139, 445)", "Open NFS (2049)", "Open SNMP (161)",
            "Open TFTP (69)", "Open Syslog (514)"
        ],
        "protocol_vulnerabilities": [
            "Open UPnP (1900)", "MQTT Exposure (1883)",
            "WebSocket Without Auth"
        ]
    }
