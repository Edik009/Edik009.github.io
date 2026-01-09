"""
H. Behavioral & Correlation Vectors (901-980)

Deep behavioral analysis and correlation-based detection.
"""

from __future__ import annotations

from typing import Any, Dict, List


_RAW_VECTOR_NAMES = """
Correlated service fingerprinting
Cross-protocol response timing
TLS handshake entropy deviation
ALPN behavior clustering
QUIC fallback heuristics
CDN edge behavior inference
Push service reaction timing
Power-state inference over network
Screen-on/off inference via RTT
Doze mode network signature
Adaptive connectivity profiling
Network sleep pattern inference
Background sync cadence leakage
Cloud relay consistency analysis
API throttling fingerprinting
Vendor backend behavior models
Differential response shaping
Canary vs prod behavior split
Feature-flag exposure inference
Backend deployment topology inference
Request authentication timing leak
Rate limiting behavior analysis
Load balancer signature exposure
Geographic endpoint distribution
Anycast routing pattern detection
DNS resolution caching behavior
HTTP/2 stream priority preference
TLS session resumption patterns
OCSP stapling presence inference
Certificate transparency log patterns
Cipher suite preference ordering
Extension ordering uniqueness
TLS version negotiation behavior
Protocol compatibility quirks
Error message timing variation
Timeout threshold fingerprinting
Retry logic pattern exposure
Circuit breaker state leakage
Exponential backoff deviation
Cache coherency timing inference
Distributed transaction patterns
Consensus algorithm detection
Eventual consistency timing
Database query timing inference
Index usage pattern leakage
Lock contention signals
Memory pressure indicators
Garbage collection timing leak
JIT compilation signatures
Runtime optimization patterns
Inline caching behavior
Branch prediction timing
Speculative execution patterns
Memory access patterns
Cache flush timing
TLB miss inference
Page fault patterns
Virtual memory swapping
Storage I/O timing
Network interface buffering
Interrupt handling latency
Kernel scheduler patterns
Thread context switching
Process affinity inference
NUMA memory access
CPU frequency scaling patterns
Power gating timing
Thermal throttling detection
Voltage scaling behavior
Clock gating patterns
Sleep state entry timing
Wake-up latency measurement
Interrupt controller behavior
Exception handler timing
Fault tolerance patterns
Redundancy detection
Failover timing analysis
Recovery procedure inference
State machine pattern detection
Transition timing analysis
""".strip()

_VECTOR_NAMES: List[str] = [line.strip() for line in _RAW_VECTOR_NAMES.splitlines() if line.strip()]


def get_behavioral_vectors() -> Dict[int, Dict[str, Any]]:
    """Возвращает все Behavioral & Correlation векторы (901-980)"""

    if len(_VECTOR_NAMES) != 80:
        raise ValueError(f"Category H must contain exactly 80 vectors, got {len(_VECTOR_NAMES)}")

    vectors: Dict[int, Dict[str, Any]] = {}

    start_id = 901
    for offset, name in enumerate(_VECTOR_NAMES):
        vector_id = start_id + offset

        # Assign severity based on vector type
        severity = "MEDIUM"
        if any(word in name.lower() for word in ["leak", "exposure", "inference", "leakage"]):
            severity = "HIGH"
        elif any(word in name.lower() for word in ["timing", "pattern", "behavior", "signature"]):
            severity = "MEDIUM"
        else:
            severity = "LOW"

        vectors[vector_id] = {
            "id": vector_id,
            "category": "H",
            "name": name,
            "description": f"Behavioral analysis: {name}",
            "check_function": f"check_vector_{vector_id}",
            "requires_adb": False,
            "requires_network": True,
            "priority": 4,
            "depends_on": [],
            "tags": ["behavioral", "correlation", "timing"],
            "severity": severity,
            "weights": {
                "mean_value": 0.35,
                "max_value": 0.25,
                "signal_count": 0.2,
                "mean_confidence": 0.2,
            },
            "confirmed_threshold": 0.65,
            "inconclusive_threshold": 0.35,
        }

    return vectors
