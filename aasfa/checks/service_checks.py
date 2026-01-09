"""
Service-level security checks
"""
from typing import Dict, Any
from ..connectors.adb_connector import ADBConnector


def check_exported_activities(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка exported activities"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    success, result = connector.execute("dumpsys activity | grep 'exported=true'")
    connector.disconnect()
    
    if success and "exported=true" in result:
        count = result.count("exported=true")
        return {"vulnerable": True, "details": f"Found {count} exported activities", "severity": "MEDIUM"}
    return {"vulnerable": False, "details": "No suspicious exported activities"}


def check_exported_services(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка exported services"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    success, result = connector.execute("dumpsys activity services | grep 'exported=true'")
    connector.disconnect()
    
    if success and "exported=true" in result:
        count = result.count("exported=true")
        return {"vulnerable": True, "details": f"Found {count} exported services", "severity": "MEDIUM"}
    return {"vulnerable": False, "details": "No suspicious exported services"}


def check_exported_receivers(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка exported receivers"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    success, result = connector.execute("dumpsys activity broadcasts | grep 'exported=true'")
    connector.disconnect()
    
    if success and "exported=true" in result:
        count = result.count("exported=true")
        return {"vulnerable": True, "details": f"Found {count} exported receivers", "severity": "MEDIUM"}
    return {"vulnerable": False, "details": "No suspicious exported receivers"}


def check_contentprovider_exposure(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка ContentProvider exposure"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    success, result = connector.execute("dumpsys activity providers")
    connector.disconnect()
    
    if success and "Provider" in result:
        return {"vulnerable": True, "details": "ContentProviders found, review needed", "severity": "LOW"}
    return {"vulnerable": False, "details": "No ContentProviders exposed"}


def check_backup_flag_enabled(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка allowBackup флага"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    packages = connector.list_packages()
    connector.disconnect()
    
    if len(packages) > 0:
        return {"vulnerable": True, "details": f"Device has {len(packages)} packages, backup check needed", "severity": "LOW"}
    return {"vulnerable": False, "details": "No packages to check"}


def check_intent_hijacking(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка возможности Intent hijacking"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    success, result = connector.execute("dumpsys package")
    connector.disconnect()
    
    if success and len(result) > 0:
        return {"vulnerable": True, "details": "Intent filters present, review needed", "severity": "LOW"}
    return {"vulnerable": False, "details": "No intent hijacking risk detected"}


def check_webview_version(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка версии WebView"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    webview_version = connector.get_prop("ro.build.version.webview")
    connector.disconnect()
    
    if webview_version:
        return {"vulnerable": False, "details": f"WebView version: {webview_version}"}
    return {"vulnerable": False, "details": "WebView version not found"}
