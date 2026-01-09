"""
I. OEM & Supply Chain Vectors (981-1060)

OEM-specific, supply chain, and advanced security checks using network analysis.
"""

from __future__ import annotations

from typing import Any, Dict, List


_RAW_VECTOR_NAMES = """
OEM cloud trust graph inference
Region-based backend mismatch
OEM beta channel leakage
Pre-release firmware backend
Forgotten staging endpoints
OEM microservice reuse
Certificate chain reuse across envs
OEM CDN misbinding
Firmware signing infra leakage
Update rollout phasing inference
Device cohort targeting inference
A/B test backend detection
OEM telemetry correlation
Vendor analytics schema leakage
Silent feature activation channels
OEM vendor lockdown scope
Proprietary protocol inference
Custom certificate authority detection
Encrypted bootloader communication
Vendor partition structure leakage
OEM APK signature validation bypass
Vendor service escalation paths
OEM system service privileges
Pre-installed app update mechanism
OEM bloatware update channels
Hidden partition access inference
OEM recovery image verification
Bootloader unlock mechanism
Fastboot protocol server presence
OEM debug interface remnants
Factory image distribution leakage
OEM security patch deployment
Security update timing correlation
Vulnerability disclosure patterns
CVE patch availability inference
Zero-day handling procedures
Exploit deployment detection
Intrusion detection patterns
Threat hunting infrastructure
Incident response automation
Malware signature distribution
Suspicious activity alerting
Behavioral anomaly detection
Network anomaly inference
Data exfiltration patterns
Command & control detection
Botnet communication
Worm propagation patterns
Ransomware behavior detection
Trojan activity inference
Rootkit presence detection
Bootkit persistence mechanisms
Hypervisor exploit detection
Privilege escalation chains
Lateral movement patterns
Persistence mechanism deployment
Data collection infrastructure
Exfiltration channel establishment
Covert communication patterns
Anti-analysis evasion
Emulator detection bypass
Debugger anti-attach mechanisms
Virtual machine detection
Sandbox escape attempts
Hardware forensics evasion
Code obfuscation patterns
String encryption usage
Control flow flattening
Dead code insertion
API hooking detection
Runtime patching presence
Self-modifying code patterns
Polymorphic behavior detection
Metamorphic code inference
Packing/unpacking patterns
Protocol wrapper detection
Traffic encryption analysis
Steganography usage inference
Covert channel creation
Information hiding detection
""".strip()

_VECTOR_NAMES: List[str] = [line.strip() for line in _RAW_VECTOR_NAMES.splitlines() if line.strip()]


def get_oem_supply_vectors() -> Dict[int, Dict[str, Any]]:
    """Возвращает все OEM & Supply Chain векторы (981-1060)"""

    if len(_VECTOR_NAMES) != 80:
        raise ValueError(f"Category I must contain exactly 80 vectors, got {len(_VECTOR_NAMES)}")

    vectors: Dict[int, Dict[str, Any]] = {}

    start_id = 981
    for offset, name in enumerate(_VECTOR_NAMES):
        vector_id = start_id + offset

        # Assign severity based on vector type
        severity = "MEDIUM"
        if any(word in name.lower() for word in ["leakage", "bypass", "escalation", "detection", "evasion", "persistence", "exfiltration", "command", "control", "botnet", "ransomware", "trojan", "rootkit", "bootkit", "hypervisor", "exploit"]):
            severity = "HIGH"
        elif any(word in name.lower() for word in ["inference", "correlation", "pattern", "mismatch"]):
            severity = "MEDIUM"
        else:
            severity = "LOW"

        vectors[vector_id] = {
            "id": vector_id,
            "category": "I",
            "name": name,
            "description": f"OEM/Supply Chain analysis: {name}",
            "check_function": f"check_vector_{vector_id}",
            "requires_adb": False,
            "requires_network": True,
            "priority": 4,
            "depends_on": [],
            "tags": ["oem", "supply-chain", "malware"],
            "severity": severity,
            "weights": {
                "mean_value": 0.35,
                "max_value": 0.25,
                "signal_count": 0.2,
                "mean_confidence": 0.2,
            },
            "confirmed_threshold": 0.6,
            "inconclusive_threshold": 0.35,
        }

    return vectors
