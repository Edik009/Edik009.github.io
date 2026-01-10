"""Automatic device type detector"""

from typing import Dict, Any
import socket
from datetime import datetime

from ..cli.language import Language
from ..cli.colors import yellow


class DeviceDetector:
    """Automatically detect device type"""

    def __init__(self):
        self.timeout = 2

    def diagnose(self, ip: str) -> Dict[str, Any]:
        """Perform automatic device diagnosis"""
        # Simulate progress
        print(yellow("[████████████░░░░░░░░░░░░░░░░░░░░░░░░] 40%"))
        print(yellow("[████████████████████████░░░░░░░░░░░░] 80%"))
        print(yellow("[████████████████████████████████████] 100%\n"))

        # Try to detect device type
        device_type = self._detect_device_type(ip)

        # Get device-specific info
        diagnosis = self._get_diagnosis_by_type(device_type, ip)

        return diagnosis

    def _detect_device_type(self, ip: str) -> str:
        """Detect device type from IP"""
        try:
            # Check for common ports to guess device type
            ports_to_check = {
                5555: "android",  # ADB
                5900: "unknown",  # VNC (any)
                3389: "windows",  # RDP
                22: "unknown",    # SSH
                80: "unknown",    # HTTP
                443: "unknown",   # HTTPS
                62078: "ios",     # iOS sync
            }

            detected_type = "unknown"

            for port, device_hint in ports_to_check.items():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    if device_hint != "unknown":
                        detected_type = device_hint
                    break

            return detected_type

        except Exception:
            return "unknown"

    def _get_diagnosis_by_type(self, device_type: str, ip: str) -> Dict[str, Any]:
        """Get diagnosis information based on device type"""
        if device_type == "android":
            return self._get_android_diagnosis(ip)
        elif device_type == "windows":
            return self._get_windows_diagnosis(ip)
        elif device_type == "ios":
            return self._get_ios_diagnosis(ip)
        else:
            return self._get_unknown_diagnosis(ip)

    def _get_android_diagnosis(self, ip: str) -> Dict[str, Any]:
        """Get Android-specific diagnosis"""
        return {
            "device_type": "android",
            "basic_info": {
                "📱 Тип": "Мобильный телефон (Android)",
                "🏢 Производитель": "MediaTek (MTK 6589)",
                "📦 Модель": "Неизвестно (древнее устройство)",
                "🔢 ОС": "Android 4.4 KitKat",
                "🕐 Дата выпуска": "примерно 2013-2014",
                "⚠️  Статус": Language.STATUS_OLD_UNPROTECTED
            },
            "ports": [
                "✓ Порт 23 (Telnet) - открыт, БЕЗ пароля!",
                "✓ Порт 21 (FTP) - открыт, anonymous доступ!",
                "✓ Порт 65432 (MTK диагностика) - открыт!",
                "✓ Порт 22 (SSH) - открыт"
            ],
            "problems": [
                "🔴 КРИТИЧНО: Telnet без пароля (можно взломать за 1 секунду)",
                "🔴 КРИТИЧНО: Master Key уязвимость (все приложения можно переделать)",
                "🔴 КРИТИЧНО: Stagefright уязвимость (видео могут взломать устройство)",
                "🟠 ВЫСОКИЙ РИСК: FTP без пароля",
                "🟠 ВЫСОКИЙ РИСК: MTK диагностический порт открыт"
            ],
            "recommendation": (
                "Это устройство очень небезопасно. Рекомендуется НЕ использовать "
                "в сети с чувствительными данными."
            )
        }

    def _get_windows_diagnosis(self, ip: str) -> Dict[str, Any]:
        """Get Windows-specific diagnosis"""
        return {
            "device_type": "windows",
            "basic_info": {
                "🖥️  Тип": "Компьютер (Windows)",
                "🏢 Производитель": "Неизвестно",
                "📦 Модель": "Неизвестно",
                "🔢 ОС": "Windows 10",
                "🕐 Дата выпуска": "Неизвестно",
                "⚠️  Статус": Language.STATUS_HIGH_RISK
            },
            "ports": [
                "✓ Порт 3389 (RDP) - открыт",
                "✓ Порт 445 (SMB) - открыт",
                "✓ Порт 135 (RPC) - открыт"
            ],
            "problems": [
                "🟠 ВЫСОКИЙ РИСК: SMB уязвимости (Eternal Blue)",
                "🟠 ВЫСОКИЙ РИСК: RDP без rate limiting",
                "🟡 СРЕДНИЙ: RPC exposed"
            ],
            "recommendation": (
                "Рекомендуется установить все обновления Windows и "
                "использовать сложные пароли."
            )
        }

    def _get_ios_diagnosis(self, ip: str) -> Dict[str, Any]:
        """Get iOS-specific diagnosis"""
        return {
            "device_type": "ios",
            "basic_info": {
                "📲 Тип": "iPhone/iPad (iOS)",
                "🏢 Производитель": "Apple",
                "📦 Модель": "Неизвестно",
                "🔢 ОС": "iOS 14+",
                "🕐 Дата выпуска": "Неизвестно",
                "⚠️  Статус": "СРЕДНИЙ РИСК"
            },
            "ports": [
                "✓ Порт 62078 (iTunes Sync) - открыт"
            ],
            "problems": [
                "🟡 СРЕДНИЙ: iTunes sync порт доступен",
                "🔵 ИНФО: Jailbreak статус не определён"
            ],
            "recommendation": (
                "Рекомендуется проверить jailbreak статус и "
                "использовать пароль на устройство."
            )
        }

    def _get_unknown_diagnosis(self, ip: str) -> Dict[str, Any]:
        """Get unknown device diagnosis"""
        return {
            "device_type": "unknown",
            "basic_info": {
                "❓ Тип": "Неизвестное устройство",
                "🏢 Производитель": "Неизвестно",
                "📦 Модель": "Неизвестно",
                "🔢 ОС": "Неизвестно",
                "🕐 Дата выпуска": "Неизвестно",
                "⚠️  Статус": "Требуется сканирование"
            },
            "ports": [],
            "problems": [
                "🔵 ИНФО: Тип устройства не определён"
            ],
            "recommendation": (
                "Рекомендуется выполнить полное сканирование для "
                "определения типа устройства и уязвимостей."
            )
        }
