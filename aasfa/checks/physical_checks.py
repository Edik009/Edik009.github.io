"""
Physical and hardware-level checks
"""
from typing import Dict, Any
from ..connectors.adb_connector import ADBConnector


def check_usb_debugging_enabled(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка USB debugging"""
    connector = ADBConnector(target, port, timeout)
    if connector.connect():
        connector.disconnect()
        return {"vulnerable": True, "details": "USB debugging is enabled", "severity": "HIGH"}
    return {"vulnerable": False, "details": "USB debugging disabled"}


def check_developer_options_enabled(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка developer options"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    success, result = connector.execute("settings get global development_settings_enabled")
    connector.disconnect()
    
    if success and "1" in result:
        return {"vulnerable": True, "details": "Developer options enabled", "severity": "MEDIUM"}
    return {"vulnerable": False, "details": "Developer options disabled"}


def check_screen_lock_configured(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка screen lock"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    success, result = connector.execute("dumpsys window | grep mCurrentFocus")
    connector.disconnect()
    
    if success:
        return {"vulnerable": False, "details": "Screen lock status checked"}
    return {"vulnerable": False, "details": "Cannot determine screen lock"}


def check_encryption_status(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка шифрования устройства"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    encryption = connector.get_prop("ro.crypto.state")
    connector.disconnect()
    
    if encryption == "unencrypted":
        return {"vulnerable": True, "details": "Device is not encrypted", "severity": "CRITICAL"}
    elif encryption == "encrypted":
        return {"vulnerable": False, "details": "Device is encrypted"}
    return {"vulnerable": False, "details": "Encryption status unknown"}


def check_factory_reset_protection(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка Factory Reset Protection"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    success, result = connector.execute("settings get secure frp_state")
    connector.disconnect()
    
    if success and "1" in result:
        return {"vulnerable": False, "details": "FRP enabled"}
    return {"vulnerable": True, "details": "FRP not configured", "severity": "LOW"}
