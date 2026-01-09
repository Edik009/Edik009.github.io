"""
Network-level security checks
"""
from typing import Dict, Any
from ..connectors.network_connector import NetworkConnector
from ..connectors.http_connector import HTTPConnector
from ..utils.config import DEFAULT_PORTS


def check_vnc_availability(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка доступности VNC"""
    connector = NetworkConnector(target, timeout)
    for vnc_port in DEFAULT_PORTS["vnc"]:
        if connector.scan_port(vnc_port):
            return {"vulnerable": True, "details": f"VNC open on port {vnc_port}", "severity": "CRITICAL"}
    return {"vulnerable": False, "details": "VNC not accessible"}


def check_rdp_availability(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка доступности RDP"""
    connector = NetworkConnector(target, timeout)
    for rdp_port in DEFAULT_PORTS["rdp"]:
        if connector.scan_port(rdp_port):
            return {"vulnerable": True, "details": f"RDP open on port {rdp_port}", "severity": "CRITICAL"}
    return {"vulnerable": False, "details": "RDP not accessible"}


def check_ssh_open(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка открытого SSH без rate limiting"""
    connector = NetworkConnector(target, timeout)
    for ssh_port in DEFAULT_PORTS["ssh"]:
        if connector.scan_port(ssh_port):
            banner = connector.get_service_banner(ssh_port)
            return {"vulnerable": True, "details": f"SSH open on port {ssh_port}: {banner}", "severity": "HIGH"}
    return {"vulnerable": False, "details": "SSH not accessible"}


def check_telnet_presence(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка наличия Telnet"""
    connector = NetworkConnector(target, timeout)
    for telnet_port in DEFAULT_PORTS["telnet"]:
        if connector.scan_port(telnet_port):
            return {"vulnerable": True, "details": f"Telnet open on port {telnet_port}", "severity": "CRITICAL"}
    return {"vulnerable": False, "details": "Telnet not found"}


def check_adb_over_tcp_network(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка ADB over TCP без использования локального adb (network-only)."""
    connector = NetworkConnector(target, timeout)
    if connector.scan_port(port):
        banner = connector.get_service_banner(port)
        details = f"ADB TCP port {port} is open" + (f": {banner}" if banner else "")
        return {"vulnerable": True, "details": details, "severity": "CRITICAL"}
    return {"vulnerable": False, "details": "ADB not accessible"}


def check_upnp_exposure(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка UPnP exposure"""
    connector = NetworkConnector(target, timeout)
    if connector.check_udp_port(1900):
        return {"vulnerable": True, "details": "UPnP exposed on port 1900", "severity": "MEDIUM"}
    return {"vulnerable": False, "details": "UPnP not exposed"}


def check_mdns_exposure(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка mDNS exposure"""
    connector = NetworkConnector(target, timeout)
    if connector.check_udp_port(5353):
        return {"vulnerable": True, "details": "mDNS exposed on port 5353", "severity": "LOW"}
    return {"vulnerable": False, "details": "mDNS not exposed"}


def check_http_admin_panels(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка HTTP admin панелей"""
    admin_paths = ["/admin", "/manager", "/console", "/dashboard"]
    
    for http_port in DEFAULT_PORTS["http"]:
        connector = HTTPConnector(target, http_port, timeout=timeout)
        if connector.connect():
            for path in admin_paths:
                content = connector.get(path)
                if content and len(content) > 0:
                    return {"vulnerable": True, "details": f"Admin panel found at {path}", "severity": "HIGH"}
    
    return {"vulnerable": False, "details": "No admin panels found"}


def check_https_without_hsts(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка HTTPS без HSTS"""
    for https_port in DEFAULT_PORTS["https"]:
        connector = HTTPConnector(target, https_port, use_ssl=True, timeout=timeout)
        if connector.connect():
            if not connector.check_hsts():
                return {"vulnerable": True, "details": f"HTTPS on port {https_port} without HSTS", "severity": "MEDIUM"}
    
    return {"vulnerable": False, "details": "HSTS properly configured"}


def check_ftp_anonymous(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка анонимного FTP"""
    connector = NetworkConnector(target, timeout)
    for ftp_port in DEFAULT_PORTS["ftp"]:
        if connector.scan_port(ftp_port):
            banner = connector.get_service_banner(ftp_port)
            if banner and "FTP" in banner:
                return {"vulnerable": True, "details": f"FTP service on port {ftp_port}", "severity": "HIGH"}
    return {"vulnerable": False, "details": "FTP not accessible"}


def check_mqtt_exposure(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """Проверка MQTT exposure"""
    connector = NetworkConnector(target, timeout)
    for mqtt_port in DEFAULT_PORTS["mqtt"]:
        if connector.scan_port(mqtt_port):
            return {"vulnerable": True, "details": f"MQTT exposed on port {mqtt_port}", "severity": "MEDIUM"}
    return {"vulnerable": False, "details": "MQTT not exposed"}
