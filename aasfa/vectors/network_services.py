"""E. Network Services Vectors (301-380)

Network-only checks (no USB/ADB required).
"""

from __future__ import annotations

from typing import Any, Dict, List


_VECTOR_NAMES: List[str] = [
    "VNC brute-force feasibility",
    "VNC authentication downgrade",
    "RFB legacy protocol",
    "Hidden VNC discovery",
    "OEM remote support",
    "Vendor diagnostic TCP",
    "Remote log streaming",
    "Android TV remote",
    "Cast debug endpoints",
    "Chromecast pairing bypass",
    "MQTT retained messages",
    "MQTT anonymous publish",
    "CoAP exposure",
    "gRPC debug",
    "WebRTC signaling",
    "WebRTC ICE leakage",
    "STUN/TURN misconfig",
    "QUIC fallback",
    "HTTP/3 downgrade",
    "TLS 1.0/1.1 acceptance",
    "Weak ECDHE curves",
    "ALPN misconfig",
    "DNS over HTTPS misconfig",
    "DNS over TLS fallback",
    "OEM cloud relay",
    "Push notification relay abuse",
    "FCM token exposure",
    "Legacy sync services",
    "Backup transport",
    "Device-to-device sync",
    "Nearby Share abuse",
    "Wi-Fi Aware exposure",
    "Wi-Fi RTT misuse",
    "BLE GATT exposure",
    "BLE pairing downgrade",
    "BLE Just Works",
    "NFC reader emulation",
    "NFC HCE exposure",
    "Smart home bridge",
    "IoT hub trust",
    "Automotive projection",
    "Android Auto debug",
    "OEM emergency services",
    "eCall exposure",
    "IMS diagnostic",
    "VoLTE debug",
    "SIP debug",
    "RCS debug",
    "OTA delivery CDN",
    "Differential OTA leak",
    "Update metadata exposure",
    "Update signature weakness",
    "Rollback OTA feasibility",
    "Partial OTA",
    "Vendor test OTA",
    "Engineering OTA residue",
    "CDN cache poisoning",
    "Mirror server trust",
    "Firmware delta inspection",
    "Update scheduling abuse",
    "Legacy sync protocols",
    "Cloud restore endpoints",
    "OEM account federation",
    "Cross-region backend",
    "Cloud debug flags",
    "Hidden beta endpoints",
    "API version fallback",
    "Shadow API endpoints",
    "API rate-limit absence",
    "API schema disclosure",
    "API introspection",
    "GraphQL introspection",
    "gRPC reflection",
    "Backend error leakage",
    "Stack trace exposure",
    "Backend feature flags",
    "Canary deployment leak",
    "Test tenant exposure",
    "Staging environment reuse",
    "Forgotten dev endpoints",
]


def get_network_services_vectors() -> Dict[int, Dict[str, Any]]:
    """Возвращает все Network Services векторы (301-380)"""

    if len(_VECTOR_NAMES) != 80:
        raise ValueError(f"Category E must contain exactly 80 vectors, got {len(_VECTOR_NAMES)}")

    vectors: Dict[int, Dict[str, Any]] = {}

    start_id = 301
    for offset, name in enumerate(_VECTOR_NAMES):
        vector_id = start_id + offset
        vectors[vector_id] = {
            "id": vector_id,
            "category": "E",
            "name": name,
            "description": name,
            "check_function": f"check_vector_{vector_id}",
            "requires_adb": False,
            "requires_network": True,
            "priority": 2,
            "depends_on": [],
            "tags": ["network", "services", "remote"],
        }

    return vectors
