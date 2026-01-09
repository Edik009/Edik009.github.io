"""
Firmware and system-level checks
"""
from typing import Dict, Any
from ..connectors.adb_connector import ADBConnector


def check_bootloader_unlock(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка разблокированного bootloader"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    unlock_state = connector.get_prop("ro.boot.flash.locked")
    connector.disconnect()
    
    if unlock_state == "0":
        return {"vulnerable": True, "details": "Bootloader is unlocked", "severity": "CRITICAL"}
    return {"vulnerable": False, "details": "Bootloader is locked"}


def check_oem_unlock_allowed(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка возможности OEM unlock"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    oem_unlock = connector.get_prop("sys.oem_unlock_allowed")
    connector.disconnect()
    
    if oem_unlock == "1":
        return {"vulnerable": True, "details": "OEM unlock allowed", "severity": "HIGH"}
    return {"vulnerable": False, "details": "OEM unlock not allowed"}


def check_firmware_version(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка версии firmware"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    build_date = connector.get_prop("ro.build.date")
    connector.disconnect()
    
    if build_date:
        return {"vulnerable": False, "details": f"Build date: {build_date}"}
    return {"vulnerable": False, "details": "Build date not found"}


def check_security_patch_level(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка уровня security patch"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    patch_level = connector.get_prop("ro.build.version.security_patch")
    connector.disconnect()
    
    if patch_level:
        return {"vulnerable": False, "details": f"Security patch level: {patch_level}"}
    return {"vulnerable": True, "details": "Security patch level not found", "severity": "MEDIUM"}


def check_system_partition_writable(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка доступности на запись /system"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    success, result = connector.execute("mount | grep system")
    connector.disconnect()
    
    if success and "rw" in result:
        return {"vulnerable": True, "details": "System partition is writable", "severity": "CRITICAL"}
    return {"vulnerable": False, "details": "System partition is read-only"}


def check_vendor_partition_security(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка безопасности vendor partition"""
    connector = ADBConnector(target, port, timeout)
    if not connector.connect():
        return {"vulnerable": False, "details": "Cannot connect to device"}
    
    success, result = connector.execute("mount | grep vendor")
    connector.disconnect()
    
    if success and "rw" in result:
        return {"vulnerable": True, "details": "Vendor partition is writable", "severity": "HIGH"}
    return {"vulnerable": False, "details": "Vendor partition is read-only"}
