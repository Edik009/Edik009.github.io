"""
Helper utilities for AASFA Scanner
"""
import subprocess
import socket
from typing import Optional, List, Tuple
from datetime import datetime


def execute_command(command: List[str], timeout: int = 30) -> Tuple[bool, str, str]:
    """
    Выполнение системной команды
    Returns: (success, stdout, stderr)
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timeout"
    except Exception as e:
        return False, "", str(e)


def check_port_open(host: str, port: int, timeout: int = 5) -> bool:
    """Проверка доступности порта"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def parse_android_version(build_prop: str) -> Optional[str]:
    """Парсинг версии Android из build.prop"""
    for line in build_prop.split('\n'):
        if 'ro.build.version.release' in line:
            parts = line.split('=')
            if len(parts) == 2:
                return parts[1].strip()
    return None


def parse_device_model(build_prop: str) -> Optional[str]:
    """Парсинг модели устройства из build.prop"""
    for line in build_prop.split('\n'):
        if 'ro.product.model' in line:
            parts = line.split('=')
            if len(parts) == 2:
                return parts[1].strip()
    return None


def format_timestamp() -> str:
    """Форматирование текущего timestamp"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_severity(severity: str) -> int:
    """Конвертация severity в числовое значение"""
    severity_map = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0
    }
    return severity_map.get(severity.upper(), 0)


def format_duration(seconds: float) -> str:
    """Форматирование длительности"""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds / 3600)
        minutes = int((seconds % 3600) / 60)
        return f"{hours}h {minutes}m"
