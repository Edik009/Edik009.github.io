"""
Network-level security checks

All checks must be non-blocking and always use socket timeouts.
"""

from __future__ import annotations

import base64
import os
import socket
import ssl
from typing import Any, Dict

from ..connectors.http_connector import HTTPConnector
from ..connectors.network_connector import NetworkConnector
from ..utils.config import DEFAULT_PORTS


def check_vnc_availability(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка доступности VNC"""
    connector = NetworkConnector(target, timeout)
    for vnc_port in DEFAULT_PORTS["vnc"]:
        if connector.scan_port_fast(vnc_port):
            return {"vulnerable": True, "details": f"VNC open on port {vnc_port}", "severity": "CRITICAL"}
    return {"vulnerable": False, "details": "VNC not accessible"}


def check_rdp_availability(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка доступности RDP"""
    connector = NetworkConnector(target, timeout)
    for rdp_port in DEFAULT_PORTS["rdp"]:
        if connector.scan_port_fast(rdp_port):
            return {"vulnerable": True, "details": f"RDP open on port {rdp_port}", "severity": "CRITICAL"}
    return {"vulnerable": False, "details": "RDP not accessible"}


def check_ssh_open(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка открытого SSH без rate limiting"""
    connector = NetworkConnector(target, timeout)
    for ssh_port in DEFAULT_PORTS["ssh"]:
        if connector.scan_port_fast(ssh_port):
            banner = connector.get_service_banner(ssh_port, timeout=min(float(timeout), 3.0))
            return {
                "vulnerable": True,
                "details": f"SSH open on port {ssh_port}: {banner or 'no banner'}",
                "severity": "HIGH",
            }
    return {"vulnerable": False, "details": "SSH not accessible"}


def check_telnet_presence(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка наличия Telnet"""
    connector = NetworkConnector(target, timeout)
    for telnet_port in DEFAULT_PORTS["telnet"]:
        if connector.scan_port_fast(telnet_port):
            return {"vulnerable": True, "details": f"Telnet open on port {telnet_port}", "severity": "CRITICAL"}
    return {"vulnerable": False, "details": "Telnet not found"}


def check_adb_over_tcp_network(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка ADB over TCP без использования локального adb (network-only)."""
    connector = NetworkConnector(target, timeout)
    if connector.scan_port_fast(port):
        banner = connector.get_service_banner(port, timeout=min(float(timeout), 3.0))
        details = f"ADB TCP port {port} is open" + (f": {banner}" if banner else "")
        return {"vulnerable": True, "details": details, "severity": "CRITICAL"}
    return {"vulnerable": False, "details": "ADB not accessible"}


def check_upnp_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка UPnP exposure"""
    connector = NetworkConnector(target, timeout)
    if connector.check_udp_port(1900, timeout=min(float(port_scan_timeout), 2.0)):
        return {"vulnerable": True, "details": "UPnP exposed on port 1900", "severity": "MEDIUM"}
    return {"vulnerable": False, "details": "UPnP not exposed"}


def check_mdns_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка mDNS exposure"""
    connector = NetworkConnector(target, timeout)
    if connector.check_udp_port(5353, timeout=min(float(port_scan_timeout), 2.0)):
        return {"vulnerable": True, "details": "mDNS exposed on port 5353", "severity": "LOW"}
    return {"vulnerable": False, "details": "mDNS not exposed"}


def check_http_admin_panels(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка HTTP admin панелей"""
    admin_paths = ["/admin", "/manager", "/console", "/dashboard"]

    for http_port in DEFAULT_PORTS["http"]:
        connector = HTTPConnector(target, http_port, timeout=timeout)
        if connector.connect():
            for path in admin_paths:
                content = connector.get(path)
                if content:
                    return {"vulnerable": True, "details": f"Admin panel found at {path}", "severity": "HIGH"}

    return {"vulnerable": False, "details": "No admin panels found"}


def check_https_without_hsts(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка HTTPS без HSTS"""
    for https_port in DEFAULT_PORTS["https"]:
        connector = HTTPConnector(target, https_port, use_ssl=True, timeout=timeout)
        if connector.connect():
            if not connector.check_hsts():
                return {
                    "vulnerable": True,
                    "details": f"HTTPS on port {https_port} without HSTS",
                    "severity": "MEDIUM",
                }

    return {"vulnerable": False, "details": "HSTS properly configured"}


def check_ftp_anonymous(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка анонимного FTP"""
    connector = NetworkConnector(target, timeout)
    for ftp_port in DEFAULT_PORTS["ftp"]:
        if connector.scan_port_fast(ftp_port):
            banner = connector.get_service_banner(ftp_port, timeout=min(float(timeout), 3.0))
            if banner and "FTP" in banner.upper():
                return {"vulnerable": True, "details": f"FTP service on port {ftp_port}", "severity": "HIGH"}
    return {"vulnerable": False, "details": "FTP not accessible"}


def check_mqtt_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка MQTT exposure"""
    connector = NetworkConnector(target, timeout)
    for mqtt_port in DEFAULT_PORTS["mqtt"]:
        if connector.scan_port_fast(mqtt_port):
            return {"vulnerable": True, "details": f"MQTT exposed on port {mqtt_port}", "severity": "MEDIUM"}
    return {"vulnerable": False, "details": "MQTT not exposed"}


def check_rtsp_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка RTSP exposure (реальная проверка протокола)."""
    rtsp_ports = [554, 8554]
    request = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"

    for rtsp_port in rtsp_ports:
        try:
            with socket.create_connection((target, rtsp_port), timeout=port_scan_timeout) as sock:
                sock.settimeout(float(port_scan_timeout))
                sock.sendall(request)
                data = sock.recv(1024)

            response = data.decode("utf-8", errors="ignore")
            if "RTSP/1.0 200" in response or "RTSP/1.0 404" in response:
                return {
                    "vulnerable": True,
                    "details": f"RTSP responded on port {rtsp_port}",
                    "severity": "MEDIUM",
                }

        except (socket.timeout, OSError):
            continue

    return {"vulnerable": False, "details": "RTSP not detected"}


def _websocket_upgrade_request(host: str) -> bytes:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    return request.encode("ascii")


def _try_websocket_upgrade(
    target: str,
    port: int,
    timeout: float,
    use_ssl: bool,
) -> bool:
    req = _websocket_upgrade_request(target)

    try:
        raw_sock = socket.create_connection((target, port), timeout=timeout)
        raw_sock.settimeout(timeout)

        sock: socket.socket
        if use_ssl:
            context = ssl._create_unverified_context()
            sock = context.wrap_socket(raw_sock, server_hostname=target)
            sock.settimeout(timeout)
        else:
            sock = raw_sock

        try:
            sock.sendall(req)
            resp = sock.recv(2048).decode("utf-8", errors="ignore")
        finally:
            sock.close()

        resp_upper = resp.upper()
        return "101" in resp_upper and "SWITCHING PROTOCOLS" in resp_upper and "UPGRADE: WEBSOCKET" in resp_upper

    except (socket.timeout, OSError, ssl.SSLError):
        return False


def check_websocket_unauth(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка WebSocket upgrade без аутентификации."""
    candidates = [80, 443, 8000]

    for ws_port in candidates:
        is_ssl = ws_port == 443
        if _try_websocket_upgrade(target, ws_port, timeout=float(port_scan_timeout), use_ssl=is_ssl):
            scheme = "wss" if is_ssl else "ws"
            return {
                "vulnerable": True,
                "details": f"WebSocket upgrade succeeded without auth on {scheme}://{target}:{ws_port}/",
                "severity": "HIGH",
            }

    return {"vulnerable": False, "details": "WebSocket not detected"}


def check_tftp_read_access(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка TFTP read access (RRQ boot.bin)."""
    tftp_port = 69

    # RRQ: opcode(1) + filename + 0 + mode + 0
    rrq = b"\x00\x01" + b"boot.bin" + b"\x00" + b"octet" + b"\x00"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(float(port_scan_timeout))
        sock.sendto(rrq, (target, tftp_port))
        data, _ = sock.recvfrom(516)
        sock.close()

        if len(data) >= 2:
            opcode = int.from_bytes(data[:2], "big")
            if opcode in {3, 4}:  # DATA or ACK
                return {
                    "vulnerable": True,
                    "details": "TFTP RRQ got a response (possible read access)",
                    "severity": "HIGH",
                }

        return {"vulnerable": False, "details": "TFTP responded but access not confirmed"}

    except (socket.timeout, OSError):
        try:
            sock.close()
        except Exception:
            pass
        return {"vulnerable": False, "details": "TFTP no response"}


def check_sip_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка SIP exposure (OPTIONS)."""
    message = f"OPTIONS sip:info@{target} SIP/2.0\r\nCSeq: 1\r\n\r\n".encode("ascii", errors="ignore")

    for sip_port in (5060, 5061):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(float(port_scan_timeout))
            sock.sendto(message, (target, sip_port))
            data, _ = sock.recvfrom(2048)
            sock.close()

            if data.startswith(b"SIP/2.0"):
                return {
                    "vulnerable": True,
                    "details": f"SIP responded on UDP port {sip_port}",
                    "severity": "MEDIUM",
                }

        except (socket.timeout, OSError):
            continue

    return {"vulnerable": False, "details": "SIP not detected"}


def _ber_encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_encode_length(len(value)) + value


def _ber_int(value: int) -> bytes:
    if value == 0:
        data = b"\x00"
    else:
        data = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if data[0] & 0x80:
            data = b"\x00" + data
    return _ber_tlv(0x02, data)


def _ber_octet_string(value: bytes) -> bytes:
    return _ber_tlv(0x04, value)


def _ber_null() -> bytes:
    return _ber_tlv(0x05, b"")


def _ber_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
    if len(parts) < 2:
        raise ValueError("Invalid OID")

    first = 40 * parts[0] + parts[1]
    encoded = bytearray([first])
    for p in parts[2:]:
        if p == 0:
            encoded.append(0)
            continue
        stack = []
        while p:
            stack.append(p & 0x7F)
            p >>= 7
        for i, b in enumerate(reversed(stack)):
            encoded.append(b | (0x80 if i < len(stack) - 1 else 0x00))

    return _ber_tlv(0x06, bytes(encoded))


def _snmp_v1_get_request(community: str, request_id: int = 1) -> bytes:
    # sysDescr.0
    oid = _ber_oid("1.3.6.1.2.1.1.1.0")

    varbind = _ber_tlv(0x30, oid + _ber_null())
    varbind_list = _ber_tlv(0x30, varbind)

    pdu_body = _ber_int(request_id) + _ber_int(0) + _ber_int(0) + varbind_list
    pdu = _ber_tlv(0xA0, pdu_body)  # GetRequest-PDU

    message = _ber_int(0) + _ber_octet_string(community.encode("ascii")) + pdu
    return _ber_tlv(0x30, message)


def check_snmp_open_community(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка SNMP с открытым community (public/private/guest)."""
    communities = ["public", "private", "guest"]

    for community in communities:
        payload = _snmp_v1_get_request(community)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(float(port_scan_timeout))
            sock.sendto(payload, (target, 161))
            data, addr = sock.recvfrom(4096)
            sock.close()

            if addr and addr[0] == target and data:
                return {
                    "vulnerable": True,
                    "details": f"SNMP responded on 161 with community '{community}'",
                    "severity": "HIGH",
                }

        except (socket.timeout, OSError):
            continue

    return {"vulnerable": False, "details": "SNMP not detected or community closed"}


def check_dlna_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 3,
) -> Dict[str, Any]:
    """Проверка DLNA/UPnP exposure через SSDP M-SEARCH multicast."""
    msearch = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: upnp:rootdevice\r\n"
        "\r\n"
    ).encode("ascii")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(float(port_scan_timeout))

    try:
        sock.sendto(msearch, ("239.255.255.250", 1900))
        while True:
            data, addr = sock.recvfrom(2048)
            if addr and addr[0] != target:
                continue

            text = data.decode("utf-8", errors="ignore").lower()
            if "upnp:rootdevice" in text:
                return {
                    "vulnerable": True,
                    "details": f"DLNA/UPnP SSDP response from {addr[0]}",
                    "severity": "LOW",
                }

    except socket.timeout:
        return {"vulnerable": False, "details": "No DLNA/UPnP SSDP response"}
    except OSError:
        return {"vulnerable": False, "details": "DLNA/UPnP check failed"}
    finally:
        sock.close()
