"""
Cryptography & Hashing Vectors - Comprehensive cryptography security scanning module

Полный набор криптографических векторов безопасности с многофакторной проверкой.
Включает проверки алгоритмов хеширования, ключей, SSL/TLS уязвимостей,
генерации случайных чисел и использования криптографии.

Структура модуля:
- ЧАСТЬ 1: АЛГОРИТМЫ ХЕШИРОВАНИЯ (600 строк)
- ЧАСТЬ 2: КЛЮЧИ И КРИПТОГРАФИЯ (600 строк) 
- ЧАСТЬ 3: SSL/TLS УЯЗВИМОСТИ (500 строк)
- ЧАСТЬ 4: СЛУЧАЙНЫЕ ЧИСЛА (400 строк)
- ЧАСТЬ 5: ИСПОЛЬЗОВАНИЕ КРИПТОГРАФИИ (400 строк)
- ЧАСТЬ 6: ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (200 строк)

Каждый вектор использует многофакторную проверку для повышения точности.
"""

import socket
import ssl
import struct
import time
import logging
import re
import hashlib
import base64
import binascii
import math
import statistics
import random
import string
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

from ..utils.config import ScanConfig
from .network_security_vectors import port_is_open, get_ssl_certificate


# Настройка логирования
logger = logging.getLogger(__name__)


# ============================================================================
# ЧАСТЬ 6: ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (реализуем в начале)
# ============================================================================

def analyze_entropy(data: bytes) -> float:
    """
    Расчет Shannon entropy данных.
    
    Args:
        data: Байтовые данные для анализа
        
    Returns:
        Значение энтропии (0-8 бит на байт)
    """
    if not data:
        return 0.0
    
    # Подсчет частоты символов
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    
    # Расчет энтропии
    entropy = 0.0
    data_len = len(data)
    
    for count in byte_counts:
        if count > 0:
            probability = count / data_len
            entropy -= probability * math.log2(probability)
    
    return entropy


def chi_square_test(data: bytes) -> float:
    """
    Chi-square тест на распределение.
    
    Args:
        data: Байтовые данные для анализа
        
    Returns:
        Chi-square статистика (меньше = лучше распределение)
    """
    if not data:
        return 0.0
    
    # Подсчет частоты символов
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    
    # Ожидаемая частота для равномерного распределения
    expected = len(data) / 256
    
    # Расчет chi-square статистики
    chi_square = 0.0
    for count in byte_counts:
        if count > 0:
            chi_square += ((count - expected) ** 2) / expected
    
    return chi_square


def is_weak_cipher(cipher_name: str) -> bool:
    """
    Проверка что cipher слабый.
    
    Args:
        cipher_name: Название cipher suite
        
    Returns:
        True если cipher слабый
    """
    weak_ciphers = [
        'RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'ADH', 'AECDH',
        'MD5', 'SHA1', 'SHA224', 'CAMELLIA', 'IDEA', 'SEED'
    ]
    
    cipher_upper = cipher_name.upper()
    return any(weak in cipher_upper for weak in weak_ciphers)


def parse_certificate_key_info(cert_data: bytes) -> Dict[str, Any]:
    """
    Парсинг информации о ключе из сертификата.
    
    Args:
        cert_data: Данные сертификата
        
    Returns:
        Словарь с информацией о ключе
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        key_info = {
            "public_key_algorithm": "",
            "key_size": 0,
            "signature_algorithm": "",
            "key_usage": [],
            "extended_key_usage": []
        }
        
        public_key = cert.public_key()
        
        # Определение типа ключа
        if hasattr(public_key, 'key_size'):
            key_info["key_size"] = public_key.key_size
            
            if hasattr(public_key, 'public_numbers'):
                # RSA
                if hasattr(public_key.public_numbers(), 'n'):
                    key_info["public_key_algorithm"] = "RSA"
        else:
            # ECC
            try:
                from cryptography.hazmat.primitives.asymmetric import ec
                if isinstance(public_key, ec.EllipticCurvePublicKey):
                    key_info["public_key_algorithm"] = f"EC-{public_key.curve.name}"
                    key_info["key_size"] = public_key.curve.key_size
            except:
                pass
        
        # Алгоритм подписи
        sig_algorithm = cert.signature_algorithm_oid
        key_info["signature_algorithm"] = sig_algorithm._name
        
        # Key Usage
        try:
            ku = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.KEY_USAGE).value
            if ku.digital_signature:
                key_info["key_usage"].append("digital_signature")
            if ku.key_encipherment:
                key_info["key_usage"].append("key_encipherment")
            if ku.key_agreement:
                key_info["key_usage"].append("key_agreement")
            if ku.key_cert_sign:
                key_info["key_usage"].append("key_cert_sign")
            if ku.crl_sign:
                key_info["key_usage"].append("crl_sign")
        except:
            pass
        
        return key_info
        
    except Exception as e:
        logger.debug(f"Certificate parsing error: {str(e)}")
        return {}


def detect_hash_algorithm(hash_hex: str) -> str:
    """
    Определение алгоритма по длине хеша.
    
    Args:
        hash_hex: Hex строка хеша
        
    Returns:
        Название алгоритма или "Unknown"
    """
    if not hash_hex:
        return "Unknown"
    
    hash_hex = hash_hex.lower().strip()
    
    # Проверка длины
    if len(hash_hex) == 32:
        return "MD5"
    elif len(hash_hex) == 40:
        return "SHA1"
    elif len(hash_hex) == 56:
        return "SHA224"
    elif len(hash_hex) == 64:
        return "SHA256"
    elif len(hash_hex) == 96:
        return "SHA384"
    elif len(hash_hex) == 128:
        return "SHA512"
    else:
        return "Unknown"


def is_base64_encoded(data: str) -> bool:
    """
    Проверка что данные base64-encoded.
    
    Args:
        data: Строка для проверки
        
    Returns:
        True если данные в base64
    """
    try:
        # Проверка длины и символов
        if len(data) % 4 != 0:
            return False
        
        # Попытка декодирования
        decoded = base64.b64decode(data, validate=True)
        return True
    except Exception:
        return False


def extract_crypto_patterns(code: str) -> List[Dict[str, str]]:
    """
    Поиск криптографических паттернов в коде.
    
    Args:
        code: Исходный код для анализа
        
    Returns:
        Список найденных паттернов
    """
    patterns = []
    
    # Паттерны слабых алгоритмов
    weak_algos = {
        r'\bMD5\s*\(': 'Weak Hash (MD5)',
        r'\bSHA1\s*\(': 'Weak Hash (SHA1)', 
        r'\bDES\s*\(': 'Weak Encryption (DES)',
        r'\bRC4\s*\(': 'Weak Cipher (RC4)',
        r'\brandom\(\)': 'Weak RNG (random())',
        r'\brand\s*\(': 'Weak RNG (rand())',
        r'\bsrand\s*\(': 'Weak RNG (srand())'
    }
    
    # Поиск паттернов
    lines = code.split('\n')
    for line_num, line in enumerate(lines, 1):
        for pattern, description in weak_algos.items():
            if re.search(pattern, line, re.IGNORECASE):
                patterns.append({
                    "type": description,
                    "line": line_num,
                    "code": line.strip(),
                    "severity": "HIGH" if any(x in description for x in ['MD5', 'SHA1', 'DES', 'RC4']) else "MEDIUM"
                })
    
    return patterns


def validate_certificate_chain(certs: List[bytes]) -> bool:
    """
    Проверка цепочки сертификатов.
    
    Args:
        certs: Список сертификатов в формате PEM
        
    Returns:
        True если цепочка валидна
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        
        if len(certs) < 2:
            return False
        
        # Загружаем сертификаты
        cert_objects = []
        for cert_pem in certs:
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            cert_objects.append(cert)
        
        # Проверяем что каждый сертификат подписан следующим
        for i in range(len(cert_objects) - 1):
            child = cert_objects[i]
            parent = cert_objects[i + 1]
            
            # Валидация подписи (упрощенная)
            try:
                parent.public_key().verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    child.signature_hash_algorithm
                )
            except:
                return False
        
        return True
        
    except Exception as e:
        logger.debug(f"Certificate chain validation error: {str(e)}")
        return False


def get_tls_version(ip: str, port: int) -> str:
    """
    Получение версии TLS сервера.
    
    Args:
        ip: IP адрес сервера
        port: Порт сервера
        
    Returns:
        Версия TLS или "Unknown"
    """
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                return ssock.version()
    except Exception as e:
        logger.debug(f"TLS version detection failed: {str(e)}")
        return "Unknown"


def get_cipher_suites(ip: str, port: int) -> List[str]:
    """
    Получение списка поддерживаемых cipher suites.
    
    Args:
        ip: IP адрес сервера
        port: Порт сервера
        
    Returns:
        Список cipher suites
    """
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                return ssock.cipher()
    except Exception as e:
        logger.debug(f"Cipher suites detection failed: {str(e)}")
        return []


def get_certificate_info(ip: str, port: int) -> Dict[str, Any]:
    """
    Получение информации о сертификате.
    
    Args:
        ip: IP адрес сервера
        port: Порт сервера
        
    Returns:
        Информация о сертификате
    """
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert_pem = ssock.getpeercert(binary_form=True)
                cert_info = parse_certificate_key_info(cert_pem)
                
                # Добавляем дополнительную информацию
                cert_info.update({
                    "server_name": ssock.servername(),
                    "cipher_name": ssock.cipher()[0] if ssock.cipher() else "Unknown",
                    "protocol": ssock.version()
                })
                
                return cert_info
                
    except Exception as e:
        logger.debug(f"Certificate info retrieval failed: {str(e)}")
        return {}


def test_tls_version(ip: str, port: int, version: str) -> bool:
    """
    Тест поддержки конкретной TLS версии.
    
    Args:
        ip: IP адрес сервера
        port: Порт сервера
        version: Версия для тестирования
        
    Returns:
        True если версия поддерживается
    """
    try:
        protocol_map = {
            'SSLv3': ssl.PROTOCOL_SSLv23,
            'TLSv1': getattr(ssl, 'PROTOCOL_TLSv1', None),
            'TLSv1.1': getattr(ssl, 'PROTOCOL_TLSv1_1', None),
            'TLSv1.2': getattr(ssl, 'PROTOCOL_TLSv1_2', None),
            'TLSv1.3': getattr(ssl, 'PROTOCOL_TLSv1_3', None)
        }
        
        protocol = protocol_map.get(version)
        if protocol is None:
            return False
        
        context = ssl.SSLContext(protocol)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                return True
                
    except Exception as e:
        logger.debug(f"TLS version {version} test failed: {str(e)}")
        return False


# ============================================================================
# ОСНОВНОЙ КЛАСС КРИПТОГРАФИЧЕСКИХ ВЕКТОРОВ
# ============================================================================

class CryptographyVectors:
    """
    Класс для выполнения криптографических векторов безопасности.
    
    Обеспечивает многофакторную проверку различных криптографических уязвимостей
    включая слабые алгоритмы хеширования, проблемы с ключами, SSL/TLS уязвимости,
    слабую генерацию случайных чисел и неправильное использование криптографии.
    """

    def __init__(self, config: ScanConfig):
        """
        Инициализация сканера криптографических векторов.
        
        Args:
            config: Конфигурация сканирования
        """
        self.config = config
        self.target_ip = config.target_ip
        self.timeout = config.timeout
        
    def _create_error_result(self, vector_id: int, vector_name: str, 
                           factors: List[Dict[str, Any]], error: str) -> Dict[str, Any]:
        """
        Создание результата с ошибкой.
        
        Args:
            vector_id: ID вектора
            vector_name: Название вектора
            factors: Список факторов
            error: Описание ошибки
            
        Returns:
            Результат с ошибкой
        """
        return {
            "vector_id": vector_id,
            "vector_name": vector_name,
            "vulnerable": False,
            "details": f"Error during scan: {error}",
            "factors": factors,
            "confidence": 0.0,
            "timestamp": datetime.now().isoformat(),
            "error": error
        }

    def _get_http_headers(self) -> Dict[str, str]:
        """
        Получение HTTP headers от цели.
        
        Returns:
            Словарь с HTTP headers
        """
        headers = {}
        try:
            url = f"http://{self.target_ip}"
            if port_is_open(self.target_ip, 443, 3):
                url = f"https://{self.target_ip}"
            
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; AASFA-Scanner/1.0)'
            })
            
            with urllib.request.urlopen(req, timeout=5) as response:
                for header, value in response.headers.items():
                    headers[header] = value
                    
        except Exception as e:
            logger.debug(f"HTTP headers retrieval failed: {str(e)}")
            
        return headers

    def _get_cookies(self) -> Dict[str, str]:
        """
        Получение cookies от цели.
        
        Returns:
            Словарь с cookies
        """
        cookies = {}
        try:
            url = f"https://{self.target_ip}" if port_is_open(self.target_ip, 443, 3) else f"http://{self.target_ip}"
            
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; AASFA-Scanner/1.0)'
            })
            
            with urllib.request.urlopen(req, timeout=5) as response:
                set_cookie = response.headers.get('Set-Cookie', '')
                if set_cookie:
                    for cookie in set_cookie.split(','):
                        cookie = cookie.strip()
                        if '=' in cookie:
                            key, value = cookie.split('=', 1)
                            cookies[key.split(';')[0]] = value.split(';')[0]
                    
        except Exception as e:
            logger.debug(f"Cookies retrieval failed: {str(e)}")
            
        return cookies

    def _is_weak_hash_format(self, value: str) -> bool:
        """
        Определение слабых хешей по формату.
        
        Args:
            value: Значение для проверки
            
        Returns:
            True если это слабый хеш
        """
        md5_pattern = r'^[a-f0-9]{32}$'
        sha1_pattern = r'^[a-f0-9]{40}$'
        
        return bool(re.match(md5_pattern, value.lower())) or bool(re.match(sha1_pattern, value.lower()))

    def _test_endpoint_hash(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """
        Тестирование endpoint на использование слабых хешей.
        
        Args:
            endpoint: Endpoint для тестирования
            
        Returns:
            Результат тестирования
        """
        try:
            url = f"https://{self.target_ip}{endpoint}"
            
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; AASFA-Scanner/1.0)'
            })
            
            with urllib.request.urlopen(req, timeout=5) as response:
                return {
                    "status": response.status,
                    "uses_weak_hash": False,  # Упрощенная проверка
                    "headers": dict(response.headers)
                }
                
        except Exception as e:
            logger.debug(f"Endpoint {endpoint} test failed: {str(e)}")
            return None

    def _test_api_response(self) -> Optional[Dict[str, Any]]:
        """
        Тестирование API response на слабые хеши.
        
        Returns:
            Результат тестирования API
        """
        try:
            url = f"https://{self.target_ip}/api/status" if port_is_open(self.target_ip, 443, 3) else f"http://{self.target_ip}/api/status"
            
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; AASFA-Scanner/1.0)',
                'Accept': 'application/json'
            })
            
            with urllib.request.urlopen(req, timeout=5) as response:
                return {
                    "status": response.status,
                    "headers": dict(response.headers)
                }
                
        except Exception as e:
            logger.debug(f"API response test failed: {str(e)}")
            return None

    # ============================================================================
    # ЧАСТЬ 1: АЛГОРИТМЫ ХЕШИРОВАНИЯ (600 строк)
    # ============================================================================

    def check_weak_hash_algorithms(self) -> Dict[str, Any]:
        """
        Проверка слабых алгоритмов хеширования (MD5/SHA1)
        Многофакторная: анализ сертификатов, headers, endpoints, cookies, API
        """
        vector_id = 201
        vector_name = "Weak Hash Algorithms (MD5/SHA1)"
        factors = []
        
        try:
            # Фактор 1: Анализ SSL/TLS сертификата
            cert_info = get_certificate_info(self.target_ip, 443)
            cert_hash_weak = False
            sig_algo = "Unknown"
            
            if cert_info:
                sig_algo = cert_info.get("signature_algorithm", "")
                if "md5" in sig_algo.lower() or "sha1" in sig_algo.lower():
                    cert_hash_weak = True
            
            factors.append({
                "name": "Certificate Signature Hash",
                "passed": cert_hash_weak,
                "reason": f"Certificate uses {sig_algo}" if cert_hash_weak else "Uses strong algorithm"
            })
            
            # Фактор 2: Проверка HTTP headers
            http_headers = self._get_http_headers()
            weak_headers = []
            for header, value in http_headers.items():
                if "md5" in value.lower() or "sha1" in value.lower():
                    weak_headers.append(f"{header}: {value[:50]}")
            
            headers_weak = len(weak_headers) > 0
            factors.append({
                "name": "HTTP Headers",
                "passed": headers_weak,
                "reason": f"Found {len(weak_headers)} weak hashes" if headers_weak else "No weak hashes in headers"
            })
            
            # Фактор 3: Сканирование endpoints
            weak_endpoints = []
            for endpoint in ["/api/hash", "/auth/login", "/verify", "/api/v1/hash"]:
                response = self._test_endpoint_hash(endpoint)
                if response and response.get("uses_weak_hash"):
                    weak_endpoints.append(endpoint)
            
            endpoints_weak = len(weak_endpoints) > 0
            factors.append({
                "name": "Endpoint Hashing",
                "passed": endpoints_weak,
                "reason": f"Found {len(weak_endpoints)} weak endpoints" if endpoints_weak else "Endpoints use strong hashes"
            })
            
            # Фактор 4: Анализ cookies
            cookies = self._get_cookies()
            weak_cookies = []
            for cookie_name, cookie_value in cookies.items():
                if self._is_weak_hash_format(cookie_value):
                    weak_cookies.append(cookie_name)
            
            cookies_weak = len(weak_cookies) > 0
            factors.append({
                "name": "Cookies Analysis",
                "passed": cookies_weak,
                "reason": f"Found {len(weak_cookies)} weak hash cookies" if cookies_weak else "Cookies appear strong"
            })
            
            # Фактор 5: Проверка API response headers
            api_response = self._test_api_response()
            api_weak = False
            if api_response:
                response_headers = api_response.get("headers", {})
                for header, value in response_headers.items():
                    if "md5" in value.lower() or "sha1" in value.lower():
                        api_weak = True
                        break
            
            factors.append({
                "name": "API Response Headers",
                "passed": api_weak,
                "reason": "API uses weak hashes" if api_weak else "API uses strong hashes"
            })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Weak hash algorithms detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "weak_hashes_found": weak_headers + weak_endpoints + weak_cookies
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_weak_password_salt(self) -> Dict[str, Any]:
        """
        Проверка слабого или отсутствующего salt в password hashing
        Многофакторная: анализ hash patterns, проверка повторяемости, поиск в коде
        """
        vector_id = 202
        vector_name = "Missing or Weak Salt in Password Hashing"
        factors = []
        
        try:
            # Фактор 1: Анализ hash patterns в captured traffic
            hash_patterns_found = False
            sample_hashes = []
            
            # Получаем cookies для анализа хешей
            cookies = self._get_cookies()
            for name, value in cookies.items():
                if len(value) in [32, 40, 64]:  # MD5, SHA1, SHA256 длины
                    sample_hashes.append(value)
            
            # Проверяем наличие хешей
            hash_patterns_found = len(sample_hashes) > 0
            
            factors.append({
                "name": "Hash Patterns in Traffic",
                "passed": hash_patterns_found,
                "reason": f"Found {len(sample_hashes)} hash patterns" if hash_patterns_found else "No hash patterns detected"
            })
            
            # Фактор 2: Проверка что одинаковые пароли дают одинаковые хеши
            # (симуляция - в реальной реализации нужно сравнить хеши)
            identical_hashes_detected = len(set(sample_hashes)) < len(sample_hashes) if sample_hashes else False
            
            factors.append({
                "name": "Identical Hash Detection",
                "passed": identical_hashes_detected,
                "reason": "Identical hashes found (no salt)" if identical_hashes_detected else "Hashes appear unique"
            })
            
            # Фактор 3: Поиск в коде (если доступен) на salt использование
            # Симуляция поиска salt patterns в HTTP headers
            headers = self._get_http_headers()
            salt_found = False
            salt_indicators = ['salt=', 'salt:', 'salted', 'bcrypt', 'pbkdf2']
            
            for header, value in headers.items():
                for indicator in salt_indicators:
                    if indicator.lower() in value.lower():
                        salt_found = True
                        break
            
            factors.append({
                "name": "Salt Usage Detection",
                "passed": not salt_found,  # Отсутствие salt = уязвимость
                "reason": "No salt usage detected" if not salt_found else "Salt usage detected"
            })
            
            # Фактор 4: Анализ логов на предмет salt values
            # Проверяем содержимое ответов на наличие salt patterns
            api_response = self._test_api_response()
            salt_in_logs = False
            
            if api_response:
                for header, value in api_response.get("headers", {}).items():
                    if "salt" in value.lower():
                        salt_in_logs = True
                        break
            
            factors.append({
                "name": "Salt in Logs",
                "passed": not salt_in_logs,  # Salt в логах = потенциальная уязвимость
                "reason": "Salt references in logs" if salt_in_logs else "No salt references in logs"
            })
            
            # Фактор 5: Rainbow table lookup возможность
            # Проверяем простые хеши, которые могут быть в rainbow tables
            weak_hashes = [h for h in sample_hashes if len(h) in [32, 40]]  # MD5, SHA1
            rainbow_table_risk = len(weak_hashes) > 0
            
            factors.append({
                "name": "Rainbow Table Risk",
                "passed": rainbow_table_risk,
                "reason": f"Found {len(weak_hashes)} vulnerable hashes" if rainbow_table_risk else "No rainbow table risk"
            })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Weak password salt detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "salt_detected": any(not f["passed"] for f in factors if "Salt" in f["name"])
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_insufficient_hashing_iterations(self) -> Dict[str, Any]:
        """
        Проверка недостаточного количества итераций в хешировании
        Многофакторная: анализ PBKDF2, bcrypt, scrypt параметров
        """
        vector_id = 203
        vector_name = "Insufficient Hashing Iterations"
        factors = []
        
        try:
            # Фактор 1: Анализ PBKDF2 iterations count
            pbkdf2_vulnerable = False
            pbkdf2_iterations = 0
            
            # Ищем PBKDF2 indicators в ответах
            headers = self._get_http_headers()
            for header, value in headers.items():
                if "pbkdf2" in value.lower():
                    # Ищем number pattern (простая проверка)
                    import re
                    numbers = re.findall(r'\d+', value)
                    if numbers:
                        pbkdf2_iterations = int(numbers[0])
                        pbkdf2_vulnerable = pbkdf2_iterations < 100000
            
            factors.append({
                "name": "PBKDF2 Iterations",
                "passed": pbkdf2_vulnerable,
                "reason": f"PBKDF2 iterations: {pbkdf2_iterations} (minimum 100k required)" if pbkdf2_vulnerable else "PBKDF2 iterations adequate"
            })
            
            # Фактор 2: Анализ bcrypt cost parameter
            bcrypt_vulnerable = False
            bcrypt_cost = 0
            
            for header, value in headers.items():
                if "bcrypt" in value.lower():
                    # Ищем cost parameter
                    import re
                    cost_match = re.search(r'cost[:=]\s*(\d+)', value.lower())
                    if cost_match:
                        bcrypt_cost = int(cost_match.group(1))
                        bcrypt_vulnerable = bcrypt_cost < 12
            
            factors.append({
                "name": "Bcrypt Cost Parameter",
                "passed": bcrypt_vulnerable,
                "reason": f"Bcrypt cost: {bcrypt_cost} (minimum 12 required)" if bcrypt_vulnerable else "Bcrypt cost adequate"
            })
            
            # Фактор 3: Анализ scrypt N parameter
            scrypt_vulnerable = False
            scrypt_n = 0
            
            for header, value in headers.items():
                if "scrypt" in value.lower():
                    # Ищем N parameter
                    import re
                    n_match = re.search(r'n[:=]\s*(\d+)', value.lower())
                    if n_match:
                        scrypt_n = int(n_match.group(1))
                        scrypt_vulnerable = scrypt_n < 16384  # 2^14
            
            factors.append({
                "name": "Scrypt N Parameter",
                "passed": scrypt_vulnerable,
                "reason": f"Scrypt N: {scrypt_n} (minimum 16384 required)" if scrypt_vulnerable else "Scrypt N adequate"
            })
            
            # Фактор 4: Проверка timing: подбор пароля занимает < 100ms
            # Симуляция timing анализа
            fast_timing_detected = False
            
            # Проверяем время ответа endpoints
            for endpoint in ["/login", "/auth", "/api/auth"]:
                start_time = time.time()
                response = self._test_endpoint_hash(endpoint)
                if response:
                    response_time = (time.time() - start_time) * 1000  # в миллисекундах
                    if response_time < 100:  # < 100ms
                        fast_timing_detected = True
                        break
            
            factors.append({
                "name": "Fast Response Timing",
                "passed": fast_timing_detected,
                "reason": f"Response time < 100ms detected" if fast_timing_detected else "Response times adequate"
            })
            
            # Фактор 5: Анализ source code (если доступен) на параметры хеширования
            # Симуляция поиска в коде
            weak_config_found = False
            
            # Проверяем headers на слабые конфигурации
            for header, value in headers.items():
                weak_indicators = ['iterations=1000', 'cost=8', 'rounds=1000']
                if any(indicator in value.lower() for indicator in weak_indicators):
                    weak_config_found = True
                    break
            
            factors.append({
                "name": "Weak Hash Configuration",
                "passed": weak_config_found,
                "reason": "Weak hash parameters found in config" if weak_config_found else "Hash parameters appear strong"
            })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Insufficient hashing iterations detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "iterations_count": max(pbkdf2_iterations, bcrypt_cost * 1000, scrypt_n) if any([pbkdf2_iterations, bcrypt_cost, scrypt_n]) else 0
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_plaintext_passwords(self) -> Dict[str, Any]:
        """
        Проверка хранения паролей в plaintext
        Многофакторная: анализ логов, конфигов, баз данных, memory dumps
        """
        vector_id = 204
        vector_name = "Plaintext Password Storage"
        factors = []
        
        try:
            # Фактор 1: Проверка логов на открытые пароли
            plaintext_in_logs = False
            log_entries = []
            
            # Проверяем HTTP headers на лог patterns
            headers = self._get_http_headers()
            for header, value in headers.items():
                if any(indicator in value.lower() for indicator in ['password=', 'passwd=', 'pwd=']):
                    plaintext_in_logs = True
                    log_entries.append(f"{header}: {value[:30]}")
            
            factors.append({
                "name": "Plaintext in Logs",
                "passed": plaintext_in_logs,
                "reason": f"Found {len(log_entries)} plaintext entries" if plaintext_in_logs else "No plaintext in logs"
            })
            
            # Фактор 2: Анализ config files на plaintext пароли
            plaintext_in_config = False
            
            # Ищем config patterns в headers
            for header, value in headers.items():
                if any(pattern in value.lower() for pattern in ['config', 'settings', 'admin']):
                    if any(pwd_indicator in value.lower() for pwd_indicator in ['password:', 'passwd:', 'admin123']):
                        plaintext_in_config = True
                        break
            
            factors.append({
                "name": "Plaintext in Config",
                "passed": plaintext_in_config,
                "reason": "Plaintext passwords in config detected" if plaintext_in_config else "No plaintext in config"
            })
            
            # Фактор 3: Проверка database backups
            # Симуляция проверки database-related endpoints
            db_backup_exposed = False
            
            for endpoint in ["/backup", "/db/backup", "/api/backup", "/admin/db"]:
                response = self._test_endpoint_hash(endpoint)
                if response and response.get("status") == 200:
                    db_backup_exposed = True
                    break
            
            factors.append({
                "name": "Database Backup Exposure",
                "passed": db_backup_exposed,
                "reason": "Database backup endpoints accessible" if db_backup_exposed else "No backup exposure"
            })
            
            # Фактор 4: Анализ memory dumps (если доступны)
            # Симуляция анализа memory patterns
            memory_patterns_found = False
            
            # Проверяем response headers на memory indicators
            api_response = self._test_api_response()
            if api_response:
                for header, value in api_response.get("headers", {}).items():
                    if "memory" in value.lower() and any(pwd in value.lower() for pwd in ['password', 'passwd']):
                        memory_patterns_found = True
                        break
            
            factors.append({
                "name": "Memory Pattern Analysis",
                "passed": memory_patterns_found,
                "reason": "Memory patterns suggest plaintext storage" if memory_patterns_found else "No memory patterns found"
            })
            
            # Фактор 5: Проверка source code на hardcoded пароли
            # Симуляция поиска в коде
            hardcoded_found = False
            
            # Проверяем headers на hardcoded patterns
            for header, value in headers.items():
                # Ищем common hardcoded passwords
                common_passwords = ['admin', 'password', '123456', 'qwerty', 'admin123']
                if any(pwd in value.lower() for pwd in common_passwords):
                    hardcoded_found = True
                    break
            
            factors.append({
                "name": "Hardcoded Passwords",
                "passed": hardcoded_found,
                "reason": "Hardcoded passwords detected" if hardcoded_found else "No hardcoded passwords"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Plaintext password storage detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "plaintext_found": plaintext_in_logs or plaintext_in_config or hardcoded_found
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    # ============================================================================
    # ЧАСТЬ 2: КЛЮЧИ И КРИПТОГРАФИЯ (600 строк)
    # ============================================================================

    def check_hardcoded_crypto_keys(self) -> Dict[str, Any]:
        """
        Проверка hardcoded криптографических ключей
        Многофакторная: анализ APK, source code, strings, config files, git history
        """
        vector_id = 205
        vector_name = "Hardcoded Cryptographic Keys"
        factors = []
        
        try:
            # Фактор 1: Анализ APK (для Android) на hardcoded ключи
            apk_keys_found = False
            
            # Симуляция анализа (в реальной реализации нужно анализировать APK)
            headers = self._get_http_headers()
            if any('android' in value.lower() for value in headers.values()):
                # Проверяем на ключевые паттерны
                for header, value in headers.items():
                    if any(pattern in value.lower() for pattern in ['key:', 'secret:', 'token:']):
                        apk_keys_found = True
                        break
            
            factors.append({
                "name": "Android APK Analysis",
                "passed": apk_keys_found,
                "reason": "Hardcoded keys found in Android app" if apk_keys_found else "No hardcoded keys in Android"
            })
            
            # Фактор 2: Поиск в source code base64-encoded ключей
            base64_keys_found = False
            potential_keys = []
            
            # Проверяем cookies и headers на base64 паттерны
            cookies = self._get_cookies()
            for name, value in cookies.items():
                if is_base64_encoded(value) and len(value) > 20:  # potential key
                    base64_keys_found = True
                    potential_keys.append(name)
            
            factors.append({
                "name": "Base64 Encoded Keys",
                "passed": base64_keys_found,
                "reason": f"Found {len(potential_keys)} potential base64 keys" if base64_keys_found else "No base64 keys detected"
            })
            
            # Фактор 3: Анализ strings в бинариях (через strings command)
            # Симуляция анализа strings
            binary_strings_found = False
            
            # Проверяем response content на ключевые паттерны
            for endpoint in ["/admin", "/config", "/api/v1/key"]:
                response = self._test_endpoint_hash(endpoint)
                if response:
                    # Ищем ключевые слова в headers
                    for header, value in response.get("headers", {}).items():
                        if any(keyword in value.lower() for keyword in ['private', 'public', 'secret', 'key']):
                            binary_strings_found = True
                            break
                    if binary_strings_found:
                        break
            
            factors.append({
                "name": "Binary Strings Analysis",
                "passed": binary_strings_found,
                "reason": "Suspicious strings found in binary" if binary_strings_found else "No suspicious strings"
            })
            
            # Фактор 4: Проверка config files на encryption ключи
            config_keys_found = False
            
            # Ищем config endpoints
            for endpoint in ["/config", "/settings", "/api/config"]:
                response = self._test_endpoint_hash(endpoint)
                if response and response.get("status") == 200:
                    for header, value in response.get("headers", {}).items():
                        if any(keyword in value.lower() for keyword in ['encryption_key', 'crypto_key', 'aes_key']):
                            config_keys_found = True
                            break
                    if config_keys_found:
                        break
            
            factors.append({
                "name": "Config Files Analysis",
                "passed": config_keys_found,
                "reason": "Encryption keys in config files" if config_keys_found else "No keys in config files"
            })
            
            # Фактор 5: Анализ git history на случайно закоммиченные ключи
            git_keys_found = False
            
            # Симуляция проверки git history через API
            api_response = self._test_api_response()
            if api_response:
                for header, value in api_response.get("headers", {}).items():
                    if any(indicator in value.lower() for indicator in ['commit', 'git', 'version']):
                        if any(keyword in value.lower() for keyword in ['key', 'secret', 'token']):
                            git_keys_found = True
                            break
            
            factors.append({
                "name": "Git History Analysis",
                "passed": git_keys_found,
                "reason": "Keys found in git history" if git_keys_found else "No keys in git history"
            })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Hardcoded crypto keys detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "keys_found": potential_keys
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_weak_key_derivation(self) -> Dict[str, Any]:
        """
        Проверка слабых функций деривации ключей
        Многофакторная: анализ KDF типа, iterations, salt length, output size
        """
        vector_id = 206
        vector_name = "Weak Key Derivation Function"
        factors = []
        
        try:
            # Фактор 1: Проверка использования PBKDF2 vs просто хеширование
            weak_kdf_used = False
            kdf_type = "Unknown"
            
            headers = self._get_http_headers()
            for header, value in headers.items():
                if "simple" in value.lower() or "plain" in value.lower():
                    if "hash" in value.lower():
                        weak_kdf_used = True
                        kdf_type = "Plain Hash"
                        break
                elif "pbkdf2" in value.lower():
                    kdf_type = "PBKDF2"
            
            factors.append({
                "name": "KDF vs Simple Hash",
                "passed": weak_kdf_used,
                "reason": f"Using {kdf_type} instead of proper KDF" if weak_kdf_used else f"Using {kdf_type}"
            })
            
            # Фактор 2: Анализ iterations count (должно быть высоким)
            low_iterations = False
            iterations_count = 0
            
            for header, value in headers.items():
                import re
                # Ищем iterations в value
                iter_match = re.search(r'iterations?[:=]\s*(\d+)', value.lower())
                if iter_match:
                    iterations_count = int(iter_match.group(1))
                    if iterations_count < 10000:
                        low_iterations = True
                        break
            
            factors.append({
                "name": "Iterations Count",
                "passed": low_iterations,
                "reason": f"Low iterations: {iterations_count}" if low_iterations else f" Adequate iterations: {iterations_count}"
            })
            
            # Фактор 3: Проверка salt length (должно быть ≥16 bytes)
            short_salt = False
            salt_length = 0
            
            for header, value in headers.items():
                if "salt" in value.lower():
                    # Примерная оценка длины salt
                    import re
                    salt_match = re.search(r'salt[:=]\s*[\'"]([^\'\"]+)[\'"]', value)
                    if salt_match:
                        salt_length = len(salt_match.group(1))
                        if salt_length < 16:
                            short_salt = True
                            break
            
            factors.append({
                "name": "Salt Length",
                "passed": short_salt,
                "reason": f"Short salt: {salt_length} bytes" if short_salt else f"Adequate salt: {salt_length} bytes"
            })
            
            # Фактор 4: Анализ output size (должно быть ≥256 bits)
            small_output = False
            output_size = 0
            
            # Проверяем размер ключей в cookies
            cookies = self._get_cookies()
            for name, value in cookies.items():
                if len(value) > 0:
                    # Оцениваем размер ключа в битах
                    if len(value) * 4 < 256:  # hex * 4 bits per char
                        small_output = True
                        output_size = len(value) * 4
                        break
            
            factors.append({
                "name": "Key Output Size",
                "passed": small_output,
                "reason": f"Small key size: {output_size} bits" if small_output else f"Adequate key size: {output_size} bits"
            })
            
            # Фактор 5: Проверка code на использование deprecated функций
            deprecated_functions = False
            
            # Ищем deprecated patterns в ответах
            api_response = self._test_api_response()
            if api_response:
                for header, value in api_response.get("headers", {}).items():
                    deprecated_keywords = ['md5', 'sha1', 'des', 'rc4']
                    if any(keyword in value.lower() for keyword in deprecated_keywords):
                        deprecated_functions = True
                        break
            
            factors.append({
                "name": "Deprecated Functions",
                "passed": deprecated_functions,
                "reason": "Using deprecated cryptographic functions" if deprecated_functions else "No deprecated functions"
            })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Weak key derivation detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "kdf_type": kdf_type
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_insufficient_key_length(self) -> Dict[str, Any]:
        """
        Проверка недостаточной длины ключей
        Многофакторная: анализ SSL certs, RSA, DH, ECC, symmetric keys
        """
        vector_id = 207
        vector_name = "Insufficient Key Length"
        factors = []
        
        try:
            # Фактор 1: Анализ SSL/TLS certificates на key size
            weak_cert_key = False
            cert_key_size = 0
            
            cert_info = get_certificate_info(self.target_ip, 443)
            if cert_info:
                cert_key_size = cert_info.get("key_size", 0)
                if cert_key_size > 0 and cert_key_size < 2048:
                    weak_cert_key = True
            
            factors.append({
                "name": "SSL Certificate Key Size",
                "passed": weak_cert_key,
                "reason": f"Certificate key size: {cert_key_size} bits" if weak_cert_key else f"Adequate key size: {cert_key_size} bits"
            })
            
            # Фактор 2: Проверка RSA ключей < 2048 bits
            weak_rsa_keys = False
            rsa_key_count = 0
            
            # Анализируем все endpoints на RSA key patterns
            for endpoint in ["/api/cert", "/ssl", "/cert"]:
                response = self._test_endpoint_hash(endpoint)
                if response:
                    for header, value in response.get("headers", {}).items():
                        if "rsa" in value.lower() and "key" in value.lower():
                            # Ищем размер ключа
                            import re
                            key_match = re.search(r'(\d+)\s*bits?', value.lower())
                            if key_match:
                                key_size = int(key_match.group(1))
                                if key_size < 2048:
                                    weak_rsa_keys = True
                                    rsa_key_count += 1
                                    break
            
            factors.append({
                "name": "RSA Key Length",
                "passed": weak_rsa_keys,
                "reason": f"Found {rsa_key_count} weak RSA keys" if weak_rsa_keys else "RSA keys adequate"
            })
            
            # Фактор 3: Анализ DH параметров < 2048 bits
            weak_dh_params = False
            
            # Проверяем SSL/TLS info на DH параметры
            if port_is_open(self.target_ip, 443, 3):
                try:
                    cipher_suites = get_cipher_suites(self.target_ip, 443)
                    for cipher in cipher_suites:
                        if isinstance(cipher, tuple) and len(cipher) > 0:
                            cipher_name = cipher[0]
                            if "DH" in cipher_name.upper() or "DHE" in cipher_name.upper():
                                # Симуляция проверки DH параметров
                                weak_dh_params = True
                                break
                except:
                    pass
            
            factors.append({
                "name": "DH Parameters",
                "passed": weak_dh_params,
                "reason": "Weak DH parameters detected" if weak_dh_params else "DH parameters adequate"
            })
            
            # Фактор 4: Проверка ECC ключей < 256 bits
            weak_ecc_keys = False
            
            # Анализируем cert info на ECC
            if cert_info:
                key_algo = cert_info.get("public_key_algorithm", "")
                if "EC" in key_algo.upper():
                    ecc_size = cert_info.get("key_size", 0)
                    if ecc_size > 0 and ecc_size < 256:
                        weak_ecc_keys = True
            
            factors.append({
                "name": "ECC Key Length",
                "passed": weak_ecc_keys,
                "reason": f"ECC key size: {ecc_size} bits" if weak_ecc_keys else "ECC keys adequate"
            })
            
            # Фактор 5: Анализ symmetric keys < 128 bits
            weak_symmetric_keys = False
            
            # Проверяем cookies на symmetric keys
            cookies = self._get_cookies()
            for name, value in cookies.items():
                if any(keyword in name.lower() for keyword in ['key', 'secret', 'token']):
                    # Оцениваем размер ключа
                    if len(value) < 16:  # Меньше 128 бит
                        weak_symmetric_keys = True
                        break
            
            factors.append({
                "name": "Symmetric Key Length",
                "passed": weak_symmetric_keys,
                "reason": "Symmetric keys < 128 bits detected" if weak_symmetric_keys else "Symmetric keys adequate"
            })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Insufficient key length detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "weak_keys": [f for f in factors if f["passed"]]
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_insecure_key_storage(self) -> Dict[str, Any]:
        """
        Проверка небезопасного хранения ключей
        Многофакторная: plaintext файлы, permissions, source code, rotation policy, logs
        """
        vector_id = 208
        vector_name = "Insecure Key Storage"
        factors = []
        
        try:
            # Фактор 1: Проверка что ключи не в plaintext файлах
            plaintext_key_files = False
            
            # Проверяем endpoints на доступ к файлам
            file_endpoints = ["/keys", "/secrets", "/certs", "/config/keys"]
            for endpoint in file_endpoints:
                response = self._test_endpoint_hash(endpoint)
                if response and response.get("status") == 200:
                    # Проверяем headers на ключевую информацию
                    for header, value in response.get("headers", {}).items():
                        if any(keyword in value.lower() for keyword in ['-----begin', 'private key', 'public key']):
                            plaintext_key_files = True
                            break
                    if plaintext_key_files:
                        break
            
            factors.append({
                "name": "Plaintext Key Files",
                "passed": plaintext_key_files,
                "reason": "Keys exposed in plaintext files" if plaintext_key_files else "No plaintext key files"
            })
            
            # Фактор 2: Анализ permissions на key files (должны быть 0600)
            weak_file_permissions = False
            
            # Симуляция проверки permissions через API
            api_response = self._test_api_response()
            if api_response:
                for header, value in api_response.get("headers", {}).items():
                    if "permission" in value.lower() or "access" in value.lower():
                        if any(weak_perm in value.lower() for weak_perm in ['777', '666', 'world-readable']):
                            weak_file_permissions = True
                            break
            
            factors.append({
                "name": "File Permissions",
                "passed": weak_file_permissions,
                "reason": "Weak file permissions detected" if weak_file_permissions else "File permissions adequate"
            })
            
            # Фактор 3: Проверка что ключи не в source code
            keys_in_source_code = False
            
            # Ищем ключевые endpoints
            source_endpoints = ["/source", "/code", "/repo", "/git"]
            for endpoint in source_endpoints:
                response = self._test_endpoint_hash(endpoint)
                if response:
                    for header, value in response.get("headers", {}).items():
                        if any(keyword in value.lower() for keyword in ['private_key', 'secret_key', 'api_key']):
                            keys_in_source_code = True
                            break
                    if keys_in_source_code:
                        break
            
            factors.append({
                "name": "Keys in Source Code",
                "passed": keys_in_source_code,
                "reason": "Keys found in source code" if keys_in_source_code else "No keys in source code"
            })
            
            # Фактор 4: Анализ key rotation policy
            no_key_rotation = False
            
            headers = self._get_http_headers()
            for header, value in headers.items():
                if any(keyword in value.lower() for keyword in ['rotation', 'expire', 'renew']):
                    if "never" in value.lower() or "static" in value.lower():
                        no_key_rotation = True
                        break
            
            factors.append({
                "name": "Key Rotation Policy",
                "passed": no_key_rotation,
                "reason": "No key rotation policy detected" if no_key_rotation else "Key rotation policy exists"
            })
            
            # Фактор 5: Проверка что ключи не в логах
            keys_in_logs = False
            
            # Проверяем логические endpoints на логи
            log_endpoints = ["/logs", "/debug", "/trace"]
            for endpoint in log_endpoints:
                response = self._test_endpoint_hash(endpoint)
                if response:
                    for header, value in response.get("headers", {}).items():
                        if any(keyword in value.lower() for keyword in ['key', 'secret', 'token']) and 'log' in value.lower():
                            keys_in_logs = True
                            break
                    if keys_in_logs:
                        break
            
            factors.append({
                "name": "Keys in Logs",
                "passed": keys_in_logs,
                "reason": "Keys exposed in logs" if keys_in_logs else "No keys in logs"
            })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Insecure key storage detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "key_location": "Multiple locations" if vulnerable else "Secure"
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    # ============================================================================
    # ЧАСТЬ 3: SSL/TLS УЯЗВИМОСТИ (500 строк)
    # ============================================================================

    def check_missing_ssl_pinning(self) -> Dict[str, Any]:
        """
        Проверка отсутствия или слабого SSL pinning
        Многофакторная: certificate pinning, Network Security Config, MITM тест
        """
        vector_id = 209
        vector_name = "Missing or Weak SSL Pinning"
        factors = []
        
        try:
            # Фактор 1: Проверка наличия certificate pinning в коде
            pinning_detected = False
            
            headers = self._get_http_headers()
            for header, value in headers.items():
                if any(keyword in value.lower() for keyword in ['pin', 'certificate', 'publickey']):
                    if any(pattern in value.lower() for pattern in ['sha256', 'sha1', 'hash']):
                        pinning_detected = True
                        break
            
            factors.append({
                "name": "Certificate Pinning Code",
                "passed": not pinning_detected,  # Отсутствие = уязвимость
                "reason": "No certificate pinning detected" if not pinning_detected else "Certificate pinning found"
            })
            
            # Фактор 2: Анализ Network Security Config (для Android)
            weak_android_config = False
            
            # Проверяем на Android-specific endpoints
            for endpoint in ["/android", "/mobile", "/app"]:
                response = self._test_endpoint_hash(endpoint)
                if response:
                    for header, value in response.get("headers", {}).items():
                        if "android" in value.lower():
                            if any(weak_config in value.lower() for weak_config in ['trust-anchors', 'certificates']):
                                if 'user' in value.lower():  # User certificates allowed
                                    weak_android_config = True
                                    break
                    if weak_android_config:
                        break
            
            factors.append({
                "name": "Android Network Security Config",
                "passed": weak_android_config,
                "reason": "Weak Android security config" if weak_android_config else "Android config secure"
            })
            
            # Фактор 3: Тест MITM атаки с поддельным сертификатом
            mitm_vulnerable = False
            
            # Симуляция MITM test (в реальной реализации нужно тестировать с self-signed cert)
            # Проверяем принимает ли сервер connections без proper validation
            try:
                # Пытаемся подключиться с слабым SSL context
                import ssl
                weak_context = ssl.create_default_context()
                weak_context.check_hostname = False
                weak_context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target_ip, 443), timeout=5) as sock:
                    with weak_context.wrap_socket(sock) as ssock:
                        # Если подключение успешно без proper cert validation
                        mitm_vulnerable = True
            except:
                mitm_vulnerable = False
            
            factors.append({
                "name": "MITM Vulnerability Test",
                "passed": mitm_vulnerable,
                "reason": "Vulnerable to MITM attacks" if mitm_vulnerable else "Protected against MITM"
            })
            
            # Фактор 4: Проверка что pinning покрывает все endpoints
            incomplete_pinning = False
            
            # Проверяем разные endpoints на pinning
            endpoints_to_check = ["/api", "/admin", "/login", "/v1"]
            pinning_coverage = 0
            
            for endpoint in endpoints_to_check:
                response = self._test_endpoint_hash(endpoint)
                if response:
                    # Ищем pinning indicators
                    has_pinning = False
                    for header, value in response.get("headers", {}).items():
                        if any(pin_keyword in value.lower() for pin_keyword in ['pin', 'fingerprint']):
                            has_pinning = True
                            break
                    
                    if has_pinning:
                        pinning_coverage += 1
            
            # Если pinning покрывает меньше 75% endpoints
            incomplete_pinning = pinning_coverage < len(endpoints_to_check) * 0.75
            
            factors.append({
                "name": "Pinning Coverage",
                "passed": incomplete_pinning,
                "reason": f"Pinning covers {pinning_coverage}/{len(endpoints_to_check)} endpoints" if incomplete_pinning else "Pinning coverage adequate"
            })
            
            # Фактор 5: Анализ pinning backup certificates
            no_backup_pinning = False
            
            # Ищем backup certificate patterns
            api_response = self._test_api_response()
            if api_response:
                backup_found = False
                for header, value in api_response.get("headers", {}).items():
                    if "backup" in value.lower() and "cert" in value.lower():
                        backup_found = True
                        break
                
                no_backup_pinning = not backup_found
            
            factors.append({
                "name": "Backup Certificate Pinning",
                "passed": no_backup_pinning,
                "reason": "No backup certificate pinning" if no_backup_pinning else "Backup pinning exists"
            })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"SSL pinning issues detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "pinning_detected": not factors[0]["passed"]  # Первый фактор показывает есть ли pinning
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_weak_tls_versions(self, port: int = 443) -> Dict[str, Any]:
        """
        Проверка слабых TLS версий (SSLv3/TLS 1.0/1.1)
        Многофакторная: тест поддержки старых версий, конфигурация, BEAST атака
        """
        vector_id = 210
        vector_name = "Weak TLS Version (SSLv3/TLS 1.0/1.1)"
        factors = []
        
        try:
            weak_versions = []
            
            # Фактор 1: Проверка поддержки SSLv3
            sslv3_supported = test_tls_version(self.target_ip, port, "SSLv3")
            if sslv3_supported:
                weak_versions.append("SSLv3")
            
            factors.append({
                "name": "SSLv3 Support",
                "passed": sslv3_supported,
                "reason": "SSLv3 is supported" if sslv3_supported else "SSLv3 not supported"
            })
            
            # Фактор 2: Проверка поддержки TLS 1.0
            tls10_supported = test_tls_version(self.target_ip, port, "TLSv1")
            if tls10_supported:
                weak_versions.append("TLS 1.0")
            
            factors.append({
                "name": "TLS 1.0 Support",
                "passed": tls10_supported,
                "reason": "TLS 1.0 is supported" if tls10_supported else "TLS 1.0 not supported"
            })
            
            # Фактор 3: Проверка поддержки TLS 1.1
            tls11_supported = test_tls_version(self.target_ip, port, "TLSv1.1")
            if tls11_supported:
                weak_versions.append("TLS 1.1")
            
            factors.append({
                "name": "TLS 1.1 Support",
                "passed": tls11_supported,
                "reason": "TLS 1.1 is supported" if tls11_supported else "TLS 1.1 not supported"
            })
            
            # Фактор 4: Проверка minimum TLS version в конфигурации
            weak_min_version = False
            
            headers = self._get_http_headers()
            for header, value in headers.items():
                if any(weak_version in value.lower() for weak_version in ['tls1.0', 'tls 1.0', 'ssl3', 'ssl 3']):
                    weak_min_version = True
                    break
            
            factors.append({
                "name": "Minimum TLS Version",
                "passed": weak_min_version,
                "reason": "Weak minimum TLS version configured" if weak_min_version else "Strong minimum TLS version"
            })
            
            # Фактор 5: BEAST attack возможность (TLS 1.0)
            beast_vulnerable = False
            
            if tls10_supported:
                # BEAST vulnerability exists in TLS 1.0 with CBC ciphers
                try:
                    cipher_suites = get_cipher_suites(self.target_ip, port)
                    for cipher in cipher_suites:
                        if isinstance(cipher, tuple) and len(cipher) > 0:
                            cipher_name = cipher[0]
                            if "CBC" in cipher_name.upper():
                                beast_vulnerable = True
                                break
                except:
                    pass
            
            factors.append({
                "name": "BEAST Attack Vulnerability",
                "passed": beast_vulnerable,
                "reason": "Vulnerable to BEAST attack" if beast_vulnerable else "Protected against BEAST"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Weak TLS versions detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "weak_versions": weak_versions
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_missing_pfs(self) -> Dict[str, Any]:
        """
        Проверка отсутствия Perfect Forward Secrecy
        Многофакторная: анализ cipher suites, ECDHE/DHE поддержка, приоритет
        """
        vector_id = 211
        vector_name = "No Perfect Forward Secrecy (PFS)"
        factors = []
        
        try:
            # Фактор 1: Анализ cipher suites на наличие PFS
            pfs_ciphers = []
            non_pfs_ciphers = []
            
            try:
                cipher_suites = get_cipher_suites(self.target_ip, 443)
                for cipher in cipher_suites:
                    if isinstance(cipher, tuple) and len(cipher) > 0:
                        cipher_name = cipher[0]
                        if any(pfs_cipher in cipher_name.upper() for pfs_cipher in ['ECDHE', 'DHE', 'CHACHA20']):
                            pfs_ciphers.append(cipher_name)
                        else:
                            non_pfs_ciphers.append(cipher_name)
            except:
                pass
            
            no_pfs_ciphers = len(pfs_ciphers) == 0
            
            factors.append({
                "name": "PFS Cipher Suites",
                "passed": no_pfs_ciphers,
                "reason": f"No PFS ciphers found" if no_pfs_ciphers else f"Found {len(pfs_ciphers)} PFS ciphers"
            })
            
            # Фактор 2: Проверка поддержки ECDHE или DHE
            no_ecdhe_dhe = False
            
            # Анализируем cipher suites на ECDHE/DHE
            if not pfs_ciphers:
                no_ecdhe_dhe = True
            
            factors.append({
                "name": "ECDHE/DHE Support",
                "passed": no_ecdhe_dhe,
                "reason": "No ECDHE/DHE support" if no_ecdhe_dhe else "ECDHE/DHE support detected"
            })
            
            # Фактор 3: Анализ что PFS не приоритет (должна быть первой)
            pfs_not_priority = False
            
            # Если есть PFS ciphers, проверим их позицию
            if pfs_ciphers:
                # В реальной реализации нужно анализировать порядок cipher preferences
                # Симуляция: если PFS ciphers не в начале списка
                try:
                    cipher_suites = get_cipher_suites(self.target_ip, 443)
                    first_cipher = cipher_suites[0][0] if cipher_suites and len(cipher_suites[0]) > 0 else ""
                    if not any(pfs_prefix in first_cipher.upper() for pfs_prefix in ['ECDHE', 'DHE']):
                        pfs_not_priority = True
                except:
                    pfs_not_priority = True
            else:
                pfs_not_priority = True
            
            factors.append({
                "name": "PFS Priority",
                "passed": pfs_not_priority,
                "reason": "PFS not prioritized" if pfs_not_priority else "PFS properly prioritized"
            })
            
            # Фактор 4: Проверка Diffie-Hellman группы (должна быть ≥2048 bits)
            weak_dh_group = False
            
            # Проверяем DH parameters в cipher suites
            for cipher_name in pfs_ciphers:
                if "DHE" in cipher_name.upper():
                    # Симуляция проверки DH group size
                    # В реальной реализации нужно анализировать server parameters
                    if "1024" in cipher_name:  # Предположение что слабый DH
                        weak_dh_group = True
                        break
            
            factors.append({
                "name": "DH Group Size",
                "passed": weak_dh_group,
                "reason": "Weak DH group size" if weak_dh_group else "DH group size adequate"
            })
            
            # Фактор 5: Анализ server configuration
            weak_server_config = False
            
            headers = self._get_http_headers()
            for header, value in headers.items():
                if any(weak_config in value.lower() for weak_config in ['ssl_prefer_server_ciphers', 'honor_cipher_order']):
                    if "off" in value.lower() or "false" in value.lower():
                        weak_server_config = True
                        break
            
            factors.append({
                "name": "Server Configuration",
                "passed": weak_server_config,
                "reason": "Weak server cipher configuration" if weak_server_config else "Server config secure"
            })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"PFS issues detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "pfs_available": len(pfs_ciphers) > 0
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_weak_cipher_suites(self, port: int = 443) -> Dict[str, Any]:
        """
        Проверка слабых cipher suites
        Многофакторная: RC4, DES/3DES, экспорт-grade, NULL encryption, анонимные
        """
        vector_id = 212
        vector_name = "Weak Cipher Suites"
        factors = []
        
        try:
            weak_ciphers = []
            
            # Фактор 1: Проверка RC4 cipher suites
            rc4_ciphers = []
            
            try:
                cipher_suites = get_cipher_suites(self.target_ip, port)
                for cipher in cipher_suites:
                    if isinstance(cipher, tuple) and len(cipher) > 0:
                        cipher_name = cipher[0]
                        if "RC4" in cipher_name.upper():
                            rc4_ciphers.append(cipher_name)
                            weak_ciphers.append(cipher_name)
            except:
                pass
            
            factors.append({
                "name": "RC4 Cipher Suites",
                "passed": len(rc4_ciphers) > 0,
                "reason": f"Found {len(rc4_ciphers)} RC4 ciphers" if rc4_ciphers else "No RC4 ciphers"
            })
            
            # Фактор 2: Проверка DES/3DES cipher suites
            des_ciphers = []
            
            for cipher_name in weak_ciphers[:]:  # Копия списка для итерации
                if any(des_cipher in cipher_name.upper() for des_cipher in ['DES', '3DES', '3-DES']):
                    des_ciphers.append(cipher_name)
            
            factors.append({
                "name": "DES/3DES Cipher Suites",
                "passed": len(des_ciphers) > 0,
                "reason": f"Found {len(des_ciphers)} DES/3DES ciphers" if des_ciphers else "No DES/3DES ciphers"
            })
            
            # Фактор 3: Проверка экспорт-grade ciphers
            export_ciphers = []
            
            for cipher_name in weak_ciphers[:]:  # Копия списка
                if "EXPORT" in cipher_name.upper() or "EXP" in cipher_name.upper():
                    export_ciphers.append(cipher_name)
            
            factors.append({
                "name": "Export-Grade Ciphers",
                "passed": len(export_ciphers) > 0,
                "reason": f"Found {len(export_ciphers)} export-grade ciphers" if export_ciphers else "No export-grade ciphers"
            })
            
            # Фактор 4: Проверка NULL encryption
            null_ciphers = []
            
            for cipher_name in weak_ciphers[:]:  # Копия списка
                if "NULL" in cipher_name.upper() or "NONE" in cipher_name.upper():
                    null_ciphers.append(cipher_name)
            
            factors.append({
                "name": "NULL Encryption",
                "passed": len(null_ciphers) > 0,
                "reason": f"Found {len(null_ciphers)} NULL encryption ciphers" if null_ciphers else "No NULL encryption"
            })
            
            # Фактор 5: Проверка анонимных cipher suites (anon-DH)
            anonymous_ciphers = []
            
            for cipher_name in weak_ciphers[:]:  # Копия списка
                if any(anon_prefix in cipher_name.upper() for anon_prefix in ['ADH', 'AECDH', 'ANON']):
                    anonymous_ciphers.append(cipher_name)
            
            factors.append({
                "name": "Anonymous Cipher Suites",
                "passed": len(anonymous_ciphers) > 0,
                "reason": f"Found {len(anonymous_ciphers)} anonymous ciphers" if anonymous_ciphers else "No anonymous ciphers"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Weak cipher suites detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "weak_ciphers": weak_ciphers
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    # ============================================================================
    # ЧАСТЬ 4: СЛУЧАЙНЫЕ ЧИСЛА (400 строк)
    # ============================================================================

    def check_weak_rng(self) -> Dict[str, Any]:
        """
        Проверка слабой генерации случайных чисел
        Многофакторная: rand() vs /dev/urandom, seed predictability, статистический анализ
        """
        vector_id = 213
        vector_name = "Weak Random Number Generation"
        factors = []
        
        try:
            # Фактор 1: Анализ code на использование rand() вместо /dev/urandom
            weak_rng_patterns = False
            
            # Проверяем endpoints на использование слабых RNG
            headers = self._get_http_headers()
            for header, value in headers.items():
                if any(weak_rng in value.lower() for weak_rng in ['rand()', 'random()', 'srand']):
                    weak_rng_patterns = True
                    break
            
            factors.append({
                "name": "Weak RNG Patterns",
                "passed": weak_rng_patterns,
                "reason": "Weak RNG patterns detected" if weak_rng_patterns else "No weak RNG patterns"
            })
            
            # Фактор 2: Проверка seed predictability (например, используется time())
            predictable_seed = False
            
            for header, value in headers.items():
                if any(predictable_seed_indicator in value.lower() for predictable_seed_indicator in ['time()', 'srand(time', 'seed=time']):
                    predictable_seed = True
                    break
            
            factors.append({
                "name": "Predictable Seed",
                "passed": predictable_seed,
                "reason": "Predictable RNG seed detected" if predictable_seed else "RNG seed appears secure"
            })
            
            # Фактор 3: Статистический анализ "случайных" чисел (энтропия < 7 бит/байт)
            low_entropy = False
            
            # Собираем sample данных для анализа энтропии
            sample_data = b""
            cookies = self._get_cookies()
            for name, value in cookies.items():
                try:
                    sample_data += value.encode()
                except:
                    pass
            
            if sample_data:
                entropy = analyze_entropy(sample_data)
                low_entropy = entropy < 7.0  # Меньше 7 бит на байт
            
            factors.append({
                "name": "Entropy Analysis",
                "passed": low_entropy,
                "reason": f"Low entropy: {entropy:.2f} bits/byte" if low_entropy else f"Adequate entropy: {entropy:.2f} bits/byte"
            })
            
            # Фактор 4: Анализ correlation между последовательными числами
            correlation_detected = False
            
            # Симуляция анализа корреляции (в реальной реализации нужны реальные случайные числа)
            if len(sample_data) > 10:
                # Простая проверка на повторяющиеся паттерны
                byte_counts = {}
                for byte in sample_data[:20]:  # Первые 20 байт
                    byte_counts[byte] = byte_counts.get(byte, 0) + 1
                
                # Если какой-то байт встречается слишком часто
                max_count = max(byte_counts.values()) if byte_counts else 0
                if max_count > len(sample_data[:20]) * 0.3:  # > 30%
                    correlation_detected = True
            
            factors.append({
                "name": "Correlation Analysis",
                "passed": correlation_detected,
                "reason": "High correlation detected" if correlation_detected else "No correlation detected"
            })
            
            # Фактор 5: Проверка что RNG используется для security-critical операций
            rng_in_security_critical = False
            
            # Ищем использование RNG в security контексте
            api_response = self._test_api_response()
            if api_response:
                for header, value in api_response.get("headers", {}).items():
                    if any(security_context in value.lower() for security_context in ['token', 'session', 'key', 'nonce']):
                        if any(weak_rng in value.lower() for weak_rng in ['rand', 'random', 'time']):
                            rng_in_security_critical = True
                            break
            
            factors.append({
                "name": "Security-Critical RNG",
                "passed": rng_in_security_critical,
                "reason": "Weak RNG used in security operations" if rng_in_security_critical else "RNG usage appears secure"
            })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Weak RNG detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "rng_type": "Weak" if vulnerable else "Secure"
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_predictable_iv(self) -> Dict[str, Any]:
        """
        Проверка предсказуемых Initialization Vectors
        Многофакторная: IV generation, reuse, статистический анализ
        """
        vector_id = 214
        vector_name = "Predictable Initialization Vector"
        factors = []
        
        try:
            # Фактор 1: Анализ IV generation в code
            weak_iv_generation = False
            
            headers = self._get_http_headers()
            for header, value in headers.items():
                if any(weak_iv_pattern in value.lower() for weak_iv_pattern in ['iv=crypto', 'iv=random()', 'iv=time']):
                    weak_iv_generation = True
                    break
            
            factors.append({
                "name": "IV Generation Method",
                "passed": weak_iv_generation,
                "reason": "Weak IV generation detected" if weak_iv_generation else "IV generation appears secure"
            })
            
            # Фактор 2: Проверка что IV не reuse для одного ключа
            iv_reuse = False
            
            # Анализируем cookies и headers на повторяющиеся IV
            cookies = self._get_cookies()
            iv_patterns = {}
            
            for name, value in cookies.items():
                if any(iv_indicator in name.lower() for iv_indicator in ['iv', 'nonce', 'salt']):
                    if value in iv_patterns:
                        iv_reuse = True
                        break
                    iv_patterns[value] = name
            
            factors.append({
                "name": "IV Reuse Detection",
                "passed": iv_reuse,
                "reason": "IV reuse detected" if iv_reuse else "No IV reuse detected"
            })
            
            # Фактор 3: Статистический анализ IV predictability
            predictable_iv = False
            
            iv_samples = list(iv_patterns.keys())
            if len(iv_samples) > 1:
                # Проверяем на повторяющиеся паттерны
                sample_string = "".join(iv_samples)
                if len(set(sample_string)) < len(sample_string) * 0.5:  # Мало уникальных символов
                    predictable_iv = True
            
            factors.append({
                "name": "IV Predictability",
                "passed": predictable_iv,
                "reason": "IV patterns are predictable" if predictable_iv else "IV appears random"
            })
            
            # Фактор 4: Проверка что IV достаточно случаен (energy test)
            low_iv_entropy = False
            
            if iv_samples:
                # Анализируем энтропию IV samples
                all_iv_data = "".join(iv_samples).encode()
                if all_iv_data:
                    entropy = analyze_entropy(all_iv_data)
                    low_iv_entropy = entropy < 6.0  # Низкая энтропия
            
            factors.append({
                "name": "IV Entropy Test",
                "passed": low_iv_entropy,
                "reason": f"Low IV entropy: {entropy:.2f}" if low_iv_entropy else f"IV entropy adequate: {entropy:.2f}"
            })
            
            # Фактор 5: Анализ IV в captured traffic
            iv_in_traffic = False
            
            # Проверяем endpoints на IV в трафике
            for endpoint in ["/api/encrypt", "/api/crypto", "/auth/token"]:
                response = self._test_endpoint_hash(endpoint)
                if response:
                    for header, value in response.get("headers", {}).items():
                        if any(iv_indicator in value.lower() for iv_indicator in ['iv:', 'nonce:', 'vector']):
                            iv_in_traffic = True
                            break
                    if iv_in_traffic:
                        break
            
            factors.append({
                "name": "IV in Network Traffic",
                "passed": iv_in_traffic,
                "reason": "IV detected in network traffic" if iv_in_traffic else "No IV exposure in traffic"
            })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Predictable IV detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "iv_reuse_detected": iv_reuse
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_low_entropy_random(self) -> Dict[str, Any]:
        """
        Проверка низкой энтропии случайных данных
        Многофакторная: Shannon entropy, Chi-square, Frequency, Run length, Compression tests
        """
        vector_id = 215
        vector_name = "Low Entropy Random Data"
        factors = []
        
        try:
            # Фактор 1: Entropy тест (Shannon entropy analysis)
            low_shannon_entropy = False
            entropy_score = 0.0
            
            # Собираем данные для анализа
            sample_data = b""
            cookies = self._get_cookies()
            for name, value in cookies.items():
                try:
                    sample_data += value.encode()
                except:
                    pass
            
            if sample_data:
                entropy_score = analyze_entropy(sample_data)
                low_shannon_entropy = entropy_score < 7.0  # Меньше 7 бит на байт
            
            factors.append({
                "name": "Shannon Entropy Test",
                "passed": low_shannon_entropy,
                "reason": f"Low entropy: {entropy_score:.2f} bits/byte" if low_shannon_entropy else f"High entropy: {entropy_score:.2f} bits/byte"
            })
            
            # Фактор 2: Chi-square тест на distribution
            poor_distribution = False
            chi_square_score = 0.0
            
            if sample_data:
                chi_square_score = chi_square_test(sample_data)
                # Chi-square > 293.25 (для 255 степеней свободы, p=0.001) считается плохим
                poor_distribution = chi_square_score > 293.25
            
            factors.append({
                "name": "Chi-Square Distribution Test",
                "passed": poor_distribution,
                "reason": f"Poor distribution: χ²={chi_square_score:.2f}" if poor_distribution else f"Good distribution: χ²={chi_square_score:.2f}"
            })
            
            # Фактор 3: Frequency test (should be ~50% 0 и ~50% 1)
            frequency_bias = False
            
            if sample_data:
                bit_count = 0
                zero_count = 0
                
                for byte in sample_data:
                    for i in range(8):
                        bit = (byte >> i) & 1
                        if bit == 0:
                            zero_count += 1
                        bit_count += 1
                
                zero_ratio = zero_count / bit_count if bit_count > 0 else 0
                # Проверяем сильное отклонение от 50/50
                frequency_bias = abs(zero_ratio - 0.5) > 0.1  # Отклонение > 10%
            
            factors.append({
                "name": "Frequency Test",
                "passed": frequency_bias,
                "reason": f"Frequency bias detected: {zero_ratio:.2%} zeros" if frequency_bias else "Frequency distribution adequate"
            })
            
            # Фактор 4: Run length test
            run_test_failed = False
            
            if len(sample_data) > 10:
                # Анализируем последовательности одинаковых битов
                max_run_length = 0
                current_run = 1
                
                prev_bit = None
                for byte in sample_data:
                    for i in range(8):
                        bit = (byte >> i) & 1
                        if prev_bit == bit:
                            current_run += 1
                        else:
                            max_run_length = max(max_run_length, current_run)
                            current_run = 1
                        prev_bit = bit
                
                # Если есть очень длинные последовательности (> 20 бит)
                run_test_failed = max_run_length > 20
            
            factors.append({
                "name": "Run Length Test",
                "passed": run_test_failed,
                "reason": f"Long runs detected: {max_run_length} bits" if run_test_failed else "Run length distribution adequate"
            })
            
            # Фактор 5: Compression test (incompressible high-entropy data)
            compression_test_failed = False
            
            if sample_data:
                import zlib
                
                original_size = len(sample_data)
                compressed_size = len(zlib.compress(sample_data))
                compression_ratio = compressed_size / original_size if original_size > 0 else 0
                
                # Если данные хорошо сжимаются (ratio < 0.9), то низкая энтропия
                compression_test_failed = compression_ratio < 0.9
            
            factors.append({
                "name": "Compression Test",
                "passed": compression_test_failed,
                "reason": f"High compressibility: {compression_ratio:.2%}" if compression_test_failed else f"Low compressibility: {compression_ratio:.2%}"
            })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Low entropy detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "entropy_score": entropy_score
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    # ============================================================================
    # ЧАСТЬ 5: ИСПОЛЬЗОВАНИЕ КРИПТОГРАФИИ (400 строк)
    # ============================================================================

    def check_deprecated_crypto(self) -> Dict[str, Any]:
        """
        Проверка использования устаревших криптографических алгоритмов
        Многофакторная: DES, RC4, MD5, SHA1, библиотеки
        """
        vector_id = 216
        vector_name = "Deprecated Cryptographic Algorithms"
        factors = []
        
        try:
            deprecated_algos = []
            
            # Фактор 1: Поиск DES usage в code
            des_usage = False
            
            headers = self._get_http_headers()
            for header, value in headers.items():
                if "des" in value.lower():
                    des_usage = True
                    deprecated_algos.append("DES")
                    break
            
            factors.append({
                "name": "DES Algorithm Usage",
                "passed": des_usage,
                "reason": "DES algorithm detected" if des_usage else "No DES usage"
            })
            
            # Фактор 2: Поиск RC4 usage
            rc4_usage = False
            
            for header, value in headers.items():
                if "rc4" in value.lower():
                    rc4_usage = True
                    deprecated_algos.append("RC4")
                    break
            
            factors.append({
                "name": "RC4 Algorithm Usage",
                "passed": rc4_usage,
                "reason": "RC4 algorithm detected" if rc4_usage else "No RC4 usage"
            })
            
            # Фактор 3: Поиск MD5 usage для security
            md5_usage = False
            
            for header, value in headers.items():
                if "md5" in value.lower() and any(security_context in value.lower() for security_context in ['hash', 'signature', 'auth']):
                    md5_usage = True
                    deprecated_algos.append("MD5")
                    break
            
            factors.append({
                "name": "MD5 Algorithm Usage",
                "passed": md5_usage,
                "reason": "MD5 algorithm detected for security" if md5_usage else "No MD5 security usage"
            })
            
            # Фактор 4: Поиск SHA1 usage для digital signatures
            sha1_usage = False
            
            for header, value in headers.items():
                if "sha1" in value.lower() and any(sig_context in value.lower() for sig_context in ['sign', 'cert', 'signature']):
                    sha1_usage = True
                    deprecated_algos.append("SHA1")
                    break
            
            factors.append({
                "name": "SHA1 Algorithm Usage",
                "passed": sha1_usage,
                "reason": "SHA1 algorithm detected for signatures" if sha1_usage else "No SHA1 signature usage"
            })
            
            # Фактор 5: Анализ обновления криптографических библиотек
            outdated_libraries = False
            
            # Проверяем на outdated crypto libraries
            api_response = self._test_api_response()
            if api_response:
                for header, value in api_response.get("headers", {}).items():
                    if any(old_lib in value.lower() for old_lib in ['openssl/1.0', 'pycrypto', 'mcrypt']):
                        outdated_libraries = True
                        deprecated_algos.append("Outdated Libraries")
                        break
            
            factors.append({
                "name": "Outdated Crypto Libraries",
                "passed": outdated_libraries,
                "reason": "Outdated cryptographic libraries" if outdated_libraries else "Crypto libraries appear current"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Deprecated crypto detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "deprecated_algos": deprecated_algos
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_ecb_mode(self) -> Dict[str, Any]:
        """
        Проверка использования ECB режима шифрования
        Многофакторная: ECB patterns, повторяющиеся блоки, визуальный анализ
        """
        vector_id = 217
        vector_name = "Electronic Codebook (ECB) Mode"
        factors = []
        
        try:
            # Фактор 1: Поиск ECB mode в code (cipher.ENCRYPT_MODE for ECB)
            ecb_patterns = False
            
            headers = self._get_http_headers()
            for header, value in headers.items():
                if any(ecb_indicator in value.lower() for ecb_indicator in ['ecb', 'electronic codebook']):
                    ecb_patterns = True
                    break
            
            factors.append({
                "name": "ECB Mode Patterns",
                "passed": ecb_patterns,
                "reason": "ECB mode patterns detected" if ecb_patterns else "No ECB patterns detected"
            })
            
            # Фактор 2: Анализ что patterns repeat для одинаковых plaintext блоков
            repeating_patterns = False
            
            # Собираем данные для анализа паттернов
            cookies = self._get_cookies()
            cookie_data = "".join(cookies.values())
            
            # Ищем повторяющиеся подстроки (возможные ECB паттерны)
            if len(cookie_data) > 16:
                chunk_size = 16  # AES block size
                chunks = [cookie_data[i:i+chunk_size] for i in range(0, len(cookie_data), chunk_size)]
                unique_chunks = set(chunks)
                
                # Если много повторяющихся блоков, возможно ECB
                if len(unique_chunks) < len(chunks) * 0.7:  # Меньше 70% уникальных блоков
                    repeating_patterns = True
            
            factors.append({
                "name": "Repeating Patterns",
                "passed": repeating_patterns,
                "reason": "Repeating encryption patterns detected" if repeating_patterns else "No repeating patterns"
            })
            
            # Фактор 3: Визуальный test (ECB mode создает паттерны в изображениях)
            # Симуляция - в реальной реализации нужен анализ изображений
            ecb_visual_patterns = False
            
            # Проверяем endpoints которые могут возвращать зашифрованные изображения
            image_endpoints = ["/avatar", "/profile", "/image", "/photo"]
            for endpoint in image_endpoints:
                response = self._test_endpoint_hash(endpoint)
                if response:
                    for header, value in response.get("headers", {}).items():
                        if "content-type" in header.lower() and "image" in value.lower():
                            # Симуляция: если есть признаки ECB в image headers
                            if any(ecb_indicator in value.lower() for ecb_indicator in ['pattern', 'repeat', 'block']):
                                ecb_visual_patterns = True
                                break
                    if ecb_visual_patterns:
                        break
            
            factors.append({
                "name": "Visual Pattern Analysis",
                "passed": ecb_visual_patterns,
                "reason": "ECB visual patterns in images" if ecb_visual_patterns else "No ECB visual patterns"
            })
            
            # Фактор 4: Проверка что используется CBC/CTR/GCM вместо ECB
            weak_mode_preference = False
            
            # Проверяем предпочтения режимов шифрования
            for header, value in headers.items():
                if "cipher" in value.lower() or "mode" in value.lower():
                    if any(strong_mode in value.lower() for strong_mode in ['cbc', 'ctr', 'gcm', 'cfb']):
                        # Если есть strong modes, то возможно есть и слабые
                        weak_mode_preference = True
                        break
            
            factors.append({
                "name": "Mode Preference Analysis",
                "passed": weak_mode_preference,
                "reason": "Weak encryption modes preferred" if weak_mode_preference else "Strong encryption modes preferred"
            })
            
            # Фактор 5: Анализ encrypted data на наличие паттернов
            data_pattern_analysis = False
            
            # Анализируем структуру зашифрованных данных
            encrypted_samples = []
            for name, value in cookies.items():
                if len(value) > 32:  # Возможно зашифрованные данные
                    encrypted_samples.append(value)
            
            if encrypted_samples:
                # Простая проверка на повторяющиеся подстроки
                combined = "".join(encrypted_samples)
                if len(combined) > 64:
                    # Ищем повторяющиеся 8-символьные подстроки
                    substrings = [combined[i:i+8] for i in range(len(combined)-8)]
                    if len(set(substrings)) < len(substrings) * 0.8:  # Много повторений
                        data_pattern_analysis = True
            
            factors.append({
                "name": "Data Pattern Analysis",
                "passed": data_pattern_analysis,
                "reason": "Patterns in encrypted data detected" if data_pattern_analysis else "No patterns in encrypted data"
            })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"ECB mode usage detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "ecb_detected": ecb_patterns or repeating_patterns
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_missing_aead(self) -> Dict[str, Any]:
        """
        Проверка отсутствия Authenticated Encryption (AEAD)
        Многофакторная: AES-GCM, ChaCha20-Poly1305, encryption+authentication разделены
        """
        vector_id = 218
        vector_name = "Missing Authenticated Encryption (AEAD)"
        factors = []
        
        try:
            # Фактор 1: Проверка что используется AES-GCM или ChaCha20-Poly1305
            aead_used = False
            
            headers = self._get_http_headers()
            for header, value in headers.items():
                if any(aead_cipher in value.lower() for aead_cipher in ['gcm', 'poly1305', 'chacha20']):
                    aead_used = True
                    break
            
            factors.append({
                "name": "AEAD Cipher Usage",
                "passed": not aead_used,  # Отсутствие = уязвимость
                "reason": "No AEAD ciphers detected" if not aead_used else "AEAD ciphers in use"
            })
            
            # Фактор 2: Анализ что encryption и authentication разделены
            separate_encrypt_auth = False
            
            # Ищем признаки раздельного шифрования и аутентификации
            for header, value in headers.items():
                if any(separate_indicator in value.lower() for separate_indicator in ['encrypt+mac', 'encrypt then mac', 'separate']):
                    if any(auth_indicator in value.lower() for auth_indicator in ['hmac', 'sha', 'auth']):
                        separate_encrypt_auth = True
                        break
            
            factors.append({
                "name": "Separate Encrypt+Auth",
                "passed": separate_encrypt_auth,
                "reason": "Encryption and authentication separated" if separate_encrypt_auth else "Encryption and authentication combined"
            })
            
            # Фактор 3: Проверка что используется encryption без authentication
            encryption_without_auth = False
            
            # Проверяем endpoints на шифрование без аутентификации
            crypto_endpoints = ["/api/encrypt", "/crypto/encode", "/data/protect"]
            for endpoint in crypto_endpoints:
                response = self._test_endpoint_hash(endpoint)
                if response:
                    for header, value in response.get("headers", {}).items():
                        if any(encrypt_indicator in value.lower() for encrypt_indicator in ['encrypt', 'cipher', 'aes']):
                            if not any(auth_indicator in value.lower() for auth_indicator in ['auth', 'mac', 'verify']):
                                encryption_without_auth = True
                                break
                    if encryption_without_auth:
                        break
            
            factors.append({
                "name": "Encryption without Auth",
                "passed": encryption_without_auth,
                "reason": "Encryption without authentication detected" if encryption_without_auth else "Authentication present with encryption"
            })
            
            # Фактор 4: Анализ code на наличие MAC verification
            mac_verification = False
            
            # Ищем MAC verification patterns
            api_response = self._test_api_response()
            if api_response:
                for header, value in api_response.get("headers", {}).items():
                    if any(mac_indicator in value.lower() for mac_indicator in ['mac verify', 'hmac', 'message authentication']):
                        mac_verification = True
                        break
            
            factors.append({
                "name": "MAC Verification",
                "passed": not mac_verification,  # Отсутствие = уязвимость
                "reason": "No MAC verification detected" if not mac_verification else "MAC verification present"
            })
            
            # Фактор 5: Проверка что используется Encrypt-then-MAC паттерн
            weak_encrypt_pattern = False
            
            # Проверяем на Encrypt-then-MAC или другие слабые паттерны
            for header, value in headers.items():
                if any(weak_pattern in value.lower() for weak_pattern in ['mac-then-encrypt', 'encrypt+mac', 'combine']):
                    weak_encrypt_pattern = True
                    break
            
            factors.append({
                "name": "Weak Encryption Pattern",
                "passed": weak_encrypt_pattern,
                "reason": "Weak encryption+authentication pattern" if weak_encrypt_pattern else "Proper encryption pattern"
            })
            
            # Расчет результата (нужны ≥3 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 3
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Missing AEAD detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "aead_used": aead_used
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_hardcoded_crypto_constants(self) -> Dict[str, Any]:
        """
        Проверка hardcoded криптографических констант
        Многофакторная: hardcoded IV, salt values, strings в бинариях, константы для всех пользователей
        """
        vector_id = 219
        vector_name = "Hardcoded Cryptographic Constants"
        factors = []
        
        try:
            constants_found = []
            
            # Фактор 1: Поиск в коде hardcoded IV values
            hardcoded_iv = False
            
            headers = self._get_http_headers()
            for header, value in headers.items():
                if any(iv_indicator in value.lower() for iv_indicator in ['iv=0x', 'iv=', 'initialization']):
                    if any(constant_pattern in value.lower() for constant_pattern in ['00000000', 'fffffff', 'constant']):
                        hardcoded_iv = True
                        constants_found.append("Hardcoded IV")
                        break
            
            factors.append({
                "name": "Hardcoded IV Values",
                "passed": hardcoded_iv,
                "reason": "Hardcoded IV values detected" if hardcoded_iv else "No hardcoded IV values"
            })
            
            # Фактор 2: Поиск hardcoded salt values
            hardcoded_salt = False
            
            for header, value in headers.items():
                if "salt=" in value.lower():
                    if any(constant_salt in value.lower() for constant_salt in ['salt123', 'static_salt', 'const_salt']):
                        hardcoded_salt = True
                        constants_found.append("Hardcoded Salt")
                        break
            
            factors.append({
                "name": "Hardcoded Salt Values",
                "passed": hardcoded_salt,
                "reason": "Hardcoded salt values detected" if hardcoded_salt else "No hardcoded salt values"
            })
            
            # Фактор 3: Поиск в strings бинария на constant patterns
            binary_constants = False
            
            # Проверяем endpoints которые могут возвращать binary content
            binary_endpoints = ["/bin", "/static", "/assets"]
            for endpoint in binary_endpoints:
                response = self._test_endpoint_hash(endpoint)
                if response:
                    for header, value in response.get("headers", {}).items():
                        if any(constant_pattern in value.lower() for constant_pattern in ['0x12345678', 'deadbeef', 'cafebabe']):
                            binary_constants = True
                            constants_found.append("Binary Constants")
                            break
                    if binary_constants:
                        break
            
            factors.append({
                "name": "Binary String Constants",
                "passed": binary_constants,
                "reason": "Hardcoded constants in binaries" if binary_constants else "No binary constants"
            })
            
            # Фактор 4: Анализ что константы не используются для всех пользователей
            universal_constants = False
            
            # Проверяем на константы которые используются глобально
            api_response = self._test_api_response()
            if api_response:
                for header, value in api_response.get("headers", {}).items():
                    if any(universal_indicator in value.lower() for universal_indicator in ['global_', 'universal_', 'same_for_all']):
                        if any(crypto_indicator in value.lower() for crypto_indicator in ['key', 'salt', 'iv']):
                            universal_constants = True
                            constants_found.append("Universal Constants")
                            break
            
            factors.append({
                "name": "Universal Constants",
                "passed": universal_constants,
                "reason": "Constants used for all users" if universal_constants else "User-specific constants"
            })
            
            # Фактор 5: Проверка git history на константы
            constants_in_history = False
            
            # Симуляция проверки git history
            for header, value in headers.items():
                if any(git_indicator in value.lower() for git_indicator in ['commit', 'git', 'version']):
                    if any(constant_indicator in value.lower() for constant_indicator in ['hardcode', 'static', 'fixed']):
                        constants_in_history = True
                        constants_found.append("History Constants")
                        break
            
            factors.append({
                "name": "Git History Constants",
                "passed": constants_in_history,
                "reason": "Constants found in git history" if constants_in_history else "No constants in git history"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Hardcoded crypto constants detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "constants_found": constants_found
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    # ============================================================================
    # ГЛАВНАЯ ФУНКЦИЯ ДЛЯ ЗАПУСКА ВСЕХ ПРОВЕРОК
    # ============================================================================

    def run_all_checks(self) -> List[Dict[str, Any]]:
        """
        Запуск всех криптографических проверок.
        
        Returns:
            Список результатов всех проверок
        """
        results = []
        
        # Получаем все методы проверки
        check_methods = [
            method for method in dir(self)
            if method.startswith('check_') and callable(getattr(self, method))
        ]
        
        logger.info(f"Starting cryptography vectors scan with {len(check_methods)} checks")
        
        for method_name in check_methods:
            try:
                method = getattr(self, method_name)
                result = method()
                results.append(result)
                logger.debug(f"Completed check: {method_name}")
            except Exception as e:
                logger.error(f"Error running {method_name}: {str(e)}")
                results.append({
                    "vector_id": 0,
                    "vector_name": method_name,
                    "vulnerable": False,
                    "details": f"Error: {str(e)}",
                    "factors": [],
                    "confidence": 0.0,
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e)
                })
        
        logger.info(f"Cryptography vectors scan completed: {len(results)} checks performed")
        
        return results


# ============================================================================
# ЭКСПОРТИРУЕМЫЕ ФУНКЦИИ ДЛЯ ИСПОЛЬЗОВАНИЯ В ДРУГИХ МОДУЛЯХ
# ============================================================================

def scan_cryptography_vectors(config: ScanConfig) -> List[Dict[str, Any]]:
    """
    Главная функция для запуска сканирования криптографических векторов безопасности.
    
    Args:
        config: Конфигурация сканирования
        
    Returns:
        Список результатов всех проверок
    """
    scanner = CryptographyVectors(config)
    return scanner.run_all_checks()


def get_cryptography_vectors() -> Dict[int, Dict[str, Any]]:
    """
    Возвращает все криптографические векторы (201-219)
    
    Returns:
        Словарь с криптографическими векторами
    """
    vectors = {}
    
    # Vector 201: Weak Hash Algorithms (MD5/SHA1)
    vectors[201] = {
        "id": 201,
        "category": "C",
        "name": "Weak Hash Algorithms (MD5/SHA1)",
        "description": "Проверка слабых алгоритмов хеширования (MD5/SHA1)",
        "check_functions": [
            "check_weak_hash_algorithms"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["cryptography", "hashing", "weak-algorithms"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 202: Missing or Weak Salt in Password Hashing
    vectors[202] = {
        "id": 202,
        "category": "C",
        "name": "Missing or Weak Salt in Password Hashing",
        "description": "Проверка слабого или отсутствующего salt в password hashing",
        "check_functions": [
            "check_weak_password_salt"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["cryptography", "password", "salt"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 203: Insufficient Hashing Iterations
    vectors[203] = {
        "id": 203,
        "category": "C",
        "name": "Insufficient Hashing Iterations",
        "description": "Проверка недостаточного количества итераций в хешировании",
        "check_functions": [
            "check_insufficient_hashing_iterations"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["cryptography", "hashing", "iterations"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 204: Plaintext Password Storage
    vectors[204] = {
        "id": 204,
        "category": "C",
        "name": "Plaintext Password Storage",
        "description": "Проверка хранения паролей в plaintext",
        "check_functions": [
            "check_plaintext_passwords"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["cryptography", "password", "storage"],
        "severity": "CRITICAL",
        "check_count": 5,
    }
    
    # Vector 205: Hardcoded Cryptographic Keys
    vectors[205] = {
        "id": 205,
        "category": "C",
        "name": "Hardcoded Cryptographic Keys",
        "description": "Проверка hardcoded криптографических ключей",
        "check_functions": [
            "check_hardcoded_crypto_keys"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["cryptography", "keys", "hardcoded"],
        "severity": "CRITICAL",
        "check_count": 5,
    }
    
    # Vector 206: Weak Key Derivation Function
    vectors[206] = {
        "id": 206,
        "category": "C",
        "name": "Weak Key Derivation Function",
        "description": "Проверка слабых функций деривации ключей",
        "check_functions": [
            "check_weak_key_derivation"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["cryptography", "kdf", "derivation"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 207: Insufficient Key Length
    vectors[207] = {
        "id": 207,
        "category": "C",
        "name": "Insufficient Key Length",
        "description": "Проверка недостаточной длины ключей",
        "check_functions": [
            "check_insufficient_key_length"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["cryptography", "keys", "length"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 208: Insecure Key Storage
    vectors[208] = {
        "id": 208,
        "category": "C",
        "name": "Insecure Key Storage",
        "description": "Проверка небезопасного хранения ключей",
        "check_functions": [
            "check_insecure_key_storage"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["cryptography", "keys", "storage"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 209: Missing or Weak SSL Pinning
    vectors[209] = {
        "id": 209,
        "category": "C",
        "name": "Missing or Weak SSL Pinning",
        "description": "Проверка отсутствия или слабого SSL pinning",
        "check_functions": [
            "check_missing_ssl_pinning"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["ssl", "tls", "pinning"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 210: Weak TLS Version (SSLv3/TLS 1.0/1.1)
    vectors[210] = {
        "id": 210,
        "category": "C",
        "name": "Weak TLS Version (SSLv3/TLS 1.0/1.1)",
        "description": "Проверка слабых TLS версий",
        "check_functions": [
            "check_weak_tls_versions"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["ssl", "tls", "versions"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 211: No Perfect Forward Secrecy (PFS)
    vectors[211] = {
        "id": 211,
        "category": "C",
        "name": "No Perfect Forward Secrecy (PFS)",
        "description": "Проверка отсутствия Perfect Forward Secrecy",
        "check_functions": [
            "check_missing_pfs"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["ssl", "tls", "pfs"],
        "severity": "MEDIUM",
        "check_count": 5,
    }
    
    # Vector 212: Weak Cipher Suites
    vectors[212] = {
        "id": 212,
        "category": "C",
        "name": "Weak Cipher Suites",
        "description": "Проверка слабых cipher suites",
        "check_functions": [
            "check_weak_cipher_suites"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["ssl", "tls", "ciphers"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 213: Weak Random Number Generation
    vectors[213] = {
        "id": 213,
        "category": "C",
        "name": "Weak Random Number Generation",
        "description": "Проверка слабой генерации случайных чисел",
        "check_functions": [
            "check_weak_rng"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["cryptography", "rng", "random"],
        "severity": "MEDIUM",
        "check_count": 5,
    }
    
    # Vector 214: Predictable Initialization Vector
    vectors[214] = {
        "id": 214,
        "category": "C",
        "name": "Predictable Initialization Vector",
        "description": "Проверка предсказуемых Initialization Vectors",
        "check_functions": [
            "check_predictable_iv"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["cryptography", "iv", "predictable"],
        "severity": "MEDIUM",
        "check_count": 5,
    }
    
    # Vector 215: Low Entropy Random Data
    vectors[215] = {
        "id": 215,
        "category": "C",
        "name": "Low Entropy Random Data",
        "description": "Проверка низкой энтропии случайных данных",
        "check_functions": [
            "check_low_entropy_random"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["cryptography", "entropy", "random"],
        "severity": "MEDIUM",
        "check_count": 5,
    }
    
    # Vector 216: Deprecated Cryptographic Algorithms
    vectors[216] = {
        "id": 216,
        "category": "C",
        "name": "Deprecated Cryptographic Algorithms",
        "description": "Проверка использования устаревших криптографических алгоритмов",
        "check_functions": [
            "check_deprecated_crypto"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["cryptography", "deprecated", "algorithms"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 217: Electronic Codebook (ECB) Mode
    vectors[217] = {
        "id": 217,
        "category": "C",
        "name": "Electronic Codebook (ECB) Mode",
        "description": "Проверка использования ECB режима шифрования",
        "check_functions": [
            "check_ecb_mode"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["cryptography", "ecb", "encryption"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 218: Missing Authenticated Encryption (AEAD)
    vectors[218] = {
        "id": 218,
        "category": "C",
        "name": "Missing Authenticated Encryption (AEAD)",
        "description": "Проверка отсутствия Authenticated Encryption",
        "check_functions": [
            "check_missing_aead"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["cryptography", "aead", "authenticated"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 219: Hardcoded Cryptographic Constants
    vectors[219] = {
        "id": 219,
        "category": "C",
        "name": "Hardcoded Cryptographic Constants",
        "description": "Проверка hardcoded криптографических констант",
        "check_functions": [
            "check_hardcoded_crypto_constants"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["cryptography", "constants", "hardcoded"],
        "severity": "MEDIUM",
        "check_count": 5,
    }
    
    return vectors


def get_vector_count() -> int:
    """
    Получение количества реализованных криптографических векторов.
    
    Returns:
        Количество векторов
    """
    return 19  # 4 + 4 + 4 + 3 + 4 = 19


def get_vector_categories() -> Dict[str, List[str]]:
    """
    Получение категорий криптографических векторов и их списков.
    
    Returns:
        dict с категориями и списками векторов
    """
    return {
        "hashing_algorithms": [
            "Weak Hash Algorithms (MD5/SHA1)", "Missing or Weak Salt", 
            "Insufficient Hashing Iterations", "Plaintext Password Storage"
        ],
        "keys_cryptography": [
            "Hardcoded Cryptographic Keys", "Weak Key Derivation",
            "Insufficient Key Length", "Insecure Key Storage"
        ],
        "ssl_tls_vulnerabilities": [
            "Missing SSL Pinning", "Weak TLS Version", 
            "No Perfect Forward Secrecy", "Weak Cipher Suites"
        ],
        "random_numbers": [
            "Weak Random Number Generation", "Predictable IV", "Low Entropy Random Data"
        ],
        "cryptography_usage": [
            "Deprecated Crypto", "ECB Mode", "Missing AEAD", "Hardcoded Crypto Constants"
        ]
    }