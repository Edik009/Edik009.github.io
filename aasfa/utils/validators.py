"""
Validation utilities for AASFA Scanner
"""
import ipaddress
import re
from typing import Optional


def validate_ip(ip: str) -> bool:
    """Валидация IP адреса"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    """Валидация порта"""
    return 1 <= port <= 65535


def validate_url(url: str) -> bool:
    """Валидация URL"""
    url_pattern = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return url_pattern.match(url) is not None


def validate_android_version(version: str) -> bool:
    """Валидация версии Android"""
    pattern = re.compile(r'^\d+(\.\d+)*$')
    return pattern.match(version) is not None


def sanitize_command(command: str) -> str:
    """Санитизация команды для безопасного выполнения"""
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r']
    for char in dangerous_chars:
        command = command.replace(char, '')
    return command.strip()


def is_private_ip(ip: str) -> bool:
    """Проверка на частный IP адрес"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False
