"""
A. Network & Remote Access Vectors (1-40)
"""
from typing import Dict, Any, Callable


def get_network_vectors() -> Dict[int, Dict[str, Any]]:
    """Возвращает все Network & Remote Access векторы (1-40)"""
    
    vectors = {}
    
    base_vectors = [
        (1, "VNC Availability", "Проверка доступности VNC без аутентификации", ["check_vnc_availability"]),
        (2, "RDP Availability", "Проверка доступности RDP", ["check_rdp_availability"]),
        (3, "SSH Open No Rate Limit", "SSH открыт без rate limiting", ["check_ssh_open"]),
        (4, "SSH Legacy Ciphers", "SSH использует устаревшие шифры", ["check_ssh_legacy_ciphers"]),
        (5, "Telnet Presence", "Telnet доступен", ["check_telnet_presence"]),
        # REMOVED: (6, "ADB Over TCP", "ADB доступен через TCP", ["check_adb_over_tcp_network"]),
        # REMOVED: (7, "ADB Pairing Misconfiguration", "Неправильная настройка ADB pairing", ["check_adb_pairing_misc"]),
        (8, "HTTP Admin Panels", "HTTP админ панели доступны", ["check_http_admin_panels"]),
        (9, "HTTPS Without HSTS", "HTTPS без HSTS заголовка", ["check_https_without_hsts"]),
        (10, "UPnP Exposure", "UPnP exposed", ["check_upnp_exposure"]),
        (11, "mDNS Exposure", "mDNS exposed", ["check_mdns_exposure"]),
        (12, "SSDP Reflection", "SSDP reflection возможен", ["check_ssdp_reflection"]),
        (13, "RTSP Exposure", "RTSP сервис exposed", ["check_rtsp_exposure"]),
        (14, "WebSocket Unauth", "WebSocket без аутентификации", ["check_websocket_unauth"]),
        (15, "MQTT Exposure", "MQTT exposed", ["check_mqtt_exposure"]),
        (16, "FTP Anonymous", "FTP анонимный доступ", ["check_ftp_anonymous"]),
        (17, "TFTP Read Access", "TFTP доступен для чтения", ["check_tftp_read_access"]),
        (18, "SIP Exposure", "SIP протокол exposed", ["check_sip_exposure"]),
        (19, "DLNA Exposure", "DLNA сервис exposed", ["check_dlna_exposure"]),
        (20, "Chromecast Debug", "Chromecast debug режим", ["check_chromecast_debug"]),
        (21, "OEM Diagnostic Ports", "OEM диагностические порты", ["check_oem_diagnostic_ports"]),
        (22, "Vendor OTA Ports", "Vendor OTA порты открыты", ["check_vendor_ota_ports"]),
        (23, "Remote Logging", "Удаленное логирование активно", ["check_remote_logging"]),
        (24, "SNMP Open Community", "SNMP с открытым community", ["check_snmp_open_community"]),
        (25, "IPv6 Exposed", "IPv6 неправильно настроен", ["check_ipv6_exposed"]),
        (26, "ICMP Misconfiguration", "ICMP неправильная конфигурация", ["check_icmp_misconfig"]),
        (27, "ARP Poisoning Vulnerable", "Уязвим к ARP poisoning", ["check_arp_poisoning"]),
        (28, "DHCP Rogue Server", "Возможен rogue DHCP server", ["check_dhcp_rogue"]),
        (29, "DNS Poisoning", "Уязвим к DNS poisoning", ["check_dns_poisoning"]),
        (30, "Captive Portal Bypass", "Bypass captive portal", ["check_captive_portal_bypass"]),
        (31, "Proxy Autoconfig Abuse", "Proxy autoconfig может быть использован", ["check_proxy_autoconfig_abuse"]),
        (32, "WebDAV Exposure", "WebDAV exposed", ["check_webdav_exposure"]),
        (33, "SMB Guest Access", "SMB guest доступ", ["check_smb_guest"]),
        (34, "NFS Exposure", "NFS exposed", ["check_nfs_exposure"]),
        (35, "VPN Split Tunnel", "VPN split tunnel уязвимость", ["check_vpn_split_tunnel"]),
        (36, "WireGuard Weak Key", "WireGuard слабый ключ", ["check_wireguard_weak_key"]),
        (37, "Bluetooth PAN", "Bluetooth PAN exposed", ["check_bluetooth_pan"]),
        (38, "WiFi Direct Abuse", "WiFi Direct может быть использован", ["check_wifi_direct_abuse"]),
        (39, "Hidden Debug Ports", "Скрытые отладочные порты", ["check_hidden_debug_ports"]),
        (40, "OEM Test Backdoors", "OEM тестовые бэкдоры", ["check_oem_test_backdoors"]),
    ]
    
    for vector_id, name, description, check_functions in base_vectors:
        vectors[vector_id] = {
            "id": vector_id,
            "category": "A",
            "name": name,
            "description": description,
            "check_functions": check_functions,
            "requires_adb": False,
            "requires_network": True,
            "priority": 1,
            "depends_on": [],
            "tags": ["network", "remote"],
            "severity": "INFO",
            "weights": None,
            "confirmed_threshold": 0.7,
            "inconclusive_threshold": 0.4,
            "check_count": 1,  # Single check for now
        }

    return vectors
