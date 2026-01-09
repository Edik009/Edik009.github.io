"""
ADB-specific security checks
"""
from typing import Dict, Any, Optional
from ..connectors.adb_connector import ADBConnector


def check_adb_over_tcp(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка ADB over TCP"""
    connector = ADBConnector(target, port, timeout)
    if connector.connect():
        connector.disconnect()
        return {"vulnerable": True, "details": f"ADB accessible over TCP on port {port}", "severity": "CRITICAL"}
    return {"vulnerable": False, "details": "ADB not accessible"}


def check_debuggable_build(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка debuggable build"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    debuggable = connector.get_prop("ro.debuggable")
    connector.disconnect()
    
    if debuggable == "1":
        return {"vulnerable": True, "details": "Device is debuggable", "severity": "HIGH"}
    return {"vulnerable": False, "details": "Device is not debuggable"}


def check_ro_secure_misconfig(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка ro.secure misconfiguration"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    ro_secure = connector.get_prop("ro.secure")
    connector.disconnect()
    
    if ro_secure == "0":
        return {"vulnerable": True, "details": "ro.secure is disabled", "severity": "CRITICAL"}
    return {"vulnerable": False, "details": "ro.secure is enabled"}


def check_ro_adb_secure(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка ro.adb.secure"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    adb_secure = connector.get_prop("ro.adb.secure")
    connector.disconnect()
    
    if adb_secure == "0":
        return {"vulnerable": True, "details": "ADB secure mode disabled", "severity": "HIGH"}
    return {"vulnerable": False, "details": "ADB secure mode enabled"}


def check_test_keys(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка test-keys в build"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    build_tags = connector.get_prop("ro.build.tags")
    connector.disconnect()
    
    if build_tags and "test-keys" in build_tags:
        return {"vulnerable": True, "details": "Build signed with test-keys", "severity": "CRITICAL"}
    return {"vulnerable": False, "details": "Build properly signed"}


def check_selinux_permissive(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка SELinux в режиме Permissive"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    selinux_status = connector.check_selinux()
    connector.disconnect()
    
    if selinux_status and selinux_status.lower() == "permissive":
        return {"vulnerable": True, "details": "SELinux in Permissive mode", "severity": "HIGH"}
    return {"vulnerable": False, "details": "SELinux properly configured"}


def check_userdebug_remnants(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка остатков userdebug"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    build_type = connector.get_prop("ro.build.type")
    connector.disconnect()
    
    if build_type in ["userdebug", "eng"]:
        return {"vulnerable": True, "details": f"Build type: {build_type}", "severity": "HIGH"}
    return {"vulnerable": False, "details": "Production build"}


def check_system_uid_leakage(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка system UID утечек"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    success, result = connector.execute("id")
    connector.disconnect()
    
    if success and "uid=1000" in result:
        return {"vulnerable": True, "details": "Shell running as system UID", "severity": "CRITICAL"}
    return {"vulnerable": False, "details": "Normal UID"}


def check_logcat_sensitive_data(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка чувствительных данных в logcat"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    success, result = connector.execute("logcat -d -t 100")
    connector.disconnect()
    
    sensitive_patterns = ["password", "token", "secret", "api_key", "auth"]
    
    if success:
        result_lower = result.lower()
        for pattern in sensitive_patterns:
            if pattern in result_lower:
                return {"vulnerable": True, "details": f"Sensitive data in logcat: {pattern}", "severity": "MEDIUM"}
    
    return {"vulnerable": False, "details": "No sensitive data in logcat"}


def check_root_access(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка root доступа"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    is_rooted = connector.is_rooted()
    connector.disconnect()
    
    if is_rooted:
        return {"vulnerable": True, "details": "Device is rooted", "severity": "CRITICAL"}
    return {"vulnerable": False, "details": "Device is not rooted"}
