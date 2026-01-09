"""
Application-level security checks
"""
from typing import Dict, Any
from ..connectors.adb_connector import ADBConnector


def check_debug_apps_installed(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка debug приложений"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    packages = connector.list_packages()
    connector.disconnect()
    
    debug_keywords = ["debug", "test", "dev", "staging"]
    debug_apps = []
    
    for package in packages:
        package_lower = package.lower()
        for keyword in debug_keywords:
            if keyword in package_lower:
                debug_apps.append(package)
                break
    
    if debug_apps:
        return {"vulnerable": True, "details": f"Found {len(debug_apps)} debug apps", "severity": "MEDIUM"}
    return {"vulnerable": False, "details": "No debug apps found"}


def check_adb_backup_enabled(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка ADB backup"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    backup_enabled = connector.get_prop("ro.adb.backup")
    connector.disconnect()
    
    if backup_enabled == "1":
        return {"vulnerable": True, "details": "ADB backup enabled", "severity": "MEDIUM"}
    return {"vulnerable": False, "details": "ADB backup disabled"}


def check_unknown_sources_allowed(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка установки из неизвестных источников"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    success, result = connector.execute("settings get secure install_non_market_apps")
    connector.disconnect()
    
    if success and "1" in result:
        return {"vulnerable": True, "details": "Unknown sources allowed", "severity": "MEDIUM"}
    return {"vulnerable": False, "details": "Unknown sources blocked"}


def check_package_verifier(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка package verifier"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    success, result = connector.execute("settings get global package_verifier_enable")
    connector.disconnect()
    
    if success and "0" in result:
        return {"vulnerable": True, "details": "Package verifier disabled", "severity": "HIGH"}
    return {"vulnerable": False, "details": "Package verifier enabled"}


def check_screenshot_protection(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка защиты от скриншотов"""
    return {"vulnerable": False, "details": "Screenshot protection requires app analysis"}


def check_third_party_sdks(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка сторонних SDK"""
    return {"vulnerable": False, "details": "SDK analysis requires app decompilation"}
