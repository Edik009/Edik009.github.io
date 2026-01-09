"""
Signal Collectors - Network-based signal collection for deep analysis
"""

from __future__ import annotations

import socket
import time
import struct
import ssl
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import hashlib


class BaseSignalCollector:
    """Base class for signal collectors"""

    def collect(self, target: str, config: Dict[str, Any]) -> List:
        """Collect signals from target"""
        raise NotImplementedError


@dataclass
class NetworkSignal:
    """Network-based signal"""
    port_open: bool
    banner: str
    service_detected: str
    ttl: int
    mtu: int
    latency: float


@dataclass
class TimingSignal:
    """Timing-based signal"""
    latency: float
    jitter: float
    packet_loss: float
    response_pattern: str


@dataclass
class ProtocolSignal:
    """Protocol-based signal"""
    tls_version: str
    cipher_suite: str
    certificate_info: Dict[str, Any]
    alpn_protocols: List[str]
    extensions: List[str]


class NetworkSignalCollector(BaseSignalCollector):
    """Collect signals from network layer"""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def collect(self, target: str, config: Dict[str, Any]) -> List:
        """Collect network signals"""
        from ..core.pipeline import VectorSignal

        signals = []
        ports = config.get("ports", [80, 443, 5555, 8080, 8443])

        # Port scan
        open_ports = self._port_scan(target, ports)
        if open_ports:
            signals.append(VectorSignal(
                source="network",
                value=min(len(open_ports) / len(ports), 1.0),
                confidence=0.9,
                timestamp=time.time(),
                metadata={"open_ports": open_ports}
            ))

        # Banner grabbing
        for port in open_ports[:3]:  # Limit to first 3 ports
            banner = self._grab_banner(target, port)
            if banner:
                signals.append(VectorSignal(
                    source="network",
                    value=0.8,
                    confidence=0.85,
                    timestamp=time.time(),
                    metadata={"port": port, "banner": banner[:100]}
                ))

        # Service fingerprinting
        service_signals = self._fingerprint_services(target, open_ports)
        signals.extend(service_signals)

        return signals

    def _port_scan(self, target: str, ports: List[int]) -> List[int]:
        """Scan ports"""
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                pass
        return open_ports

    def _grab_banner(self, target: str, port: int) -> Optional[str]:
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((target, port))

            if port in [80, 8080, 8000]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port in [21, 22, 23, 25, 110, 143]:
                # Just wait for banner
                pass
            else:
                sock.send(b"\r\n")

            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()
            return banner.strip()
        except Exception:
            return None

    def _fingerprint_services(self, target: str, ports: List[int]) -> List:
        """Fingerprint running services"""
        from ..core.pipeline import VectorSignal
        signals = []

        for port in ports:
            service = self._identify_service(port)
            if service:
                signals.append(VectorSignal(
                    source="network",
                    value=0.7,
                    confidence=0.75,
                    timestamp=time.time(),
                    metadata={"port": port, "service": service}
                ))

        return signals

    def _identify_service(self, port: int) -> Optional[str]:
        """Identify service by port"""
        service_map = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            5555: "ADB",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
        }
        return service_map.get(port)


class TimingSignalCollector(BaseSignalCollector):
    """Collect timing-based signals"""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def collect(self, target: str, config: Dict[str, Any]) -> List:
        """Collect timing signals"""
        from ..core.pipeline import VectorSignal

        signals = []
        port = config.get("port", 443)

        # Measure latency with multiple probes
        latencies = []
        for _ in range(5):
            latency = self._measure_latency(target, port)
            if latency is not None:
                latencies.append(latency)

        if latencies:
            mean_latency = sum(latencies) / len(latencies)
            jitter = self._calculate_jitter(latencies)

            # Low latency signal
            if mean_latency < 0.01:
                signals.append(VectorSignal(
                    source="timing",
                    value=0.9,
                    confidence=0.85,
                    timestamp=time.time(),
                    metadata={"mean_latency": mean_latency, "jitter": jitter}
                ))

            # High jitter signal
            if jitter > 0.005:
                signals.append(VectorSignal(
                    source="timing",
                    value=0.7,
                    confidence=0.8,
                    timestamp=time.time(),
                    metadata={"jitter": jitter}
                ))

        return signals

    def _measure_latency(self, target: str, port: int) -> Optional[float]:
        """Measure latency to port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            start = time.time()
            sock.connect((target, port))
            latency = time.time() - start
            sock.close()
            return latency
        except Exception:
            return None

    def _calculate_jitter(self, latencies: List[float]) -> float:
        """Calculate jitter (variation in latency)"""
        if len(latencies) < 2:
            return 0.0

        mean = sum(latencies) / len(latencies)
        variance = sum((x - mean) ** 2 for x in latencies) / len(latencies)
        return variance ** 0.5


class ProtocolSignalCollector(BaseSignalCollector):
    """Collect protocol-level signals"""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def collect(self, target: str, config: Dict[str, Any]) -> List:
        """Collect protocol signals"""
        from ..core.pipeline import VectorSignal

        signals = []
        port = config.get("port", 443)

        # TLS handshake analysis
        if port in [443, 8443]:
            tls_signal = self._analyze_tls(target, port)
            if tls_signal:
                signals.append(tls_signal)

        # HTTP behavior analysis
        if port in [80, 8080, 443, 8443]:
            http_signal = self._analyze_http(target, port)
            if http_signal:
                signals.append(http_signal)

        return signals

    def _analyze_tls(self, target: str, port: int) -> Optional:
        """Analyze TLS handshake"""
        from ..core.pipeline import VectorSignal

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            wrapped = context.wrap_socket(sock, server_hostname=target)
            wrapped.connect((target, port))

            cert = wrapped.getpeercert()
            cipher = wrapped.cipher()
            version = wrapped.version()

            wrapped.close()

            # Analyze certificate
            if cert:
                cert_hash = hashlib.sha256(str(cert).encode()).hexdigest()[:16]

                return VectorSignal(
                    source="protocol",
                    value=0.85,
                    confidence=0.9,
                    timestamp=time.time(),
                    metadata={
                        "tls_version": version,
                        "cipher": cipher[0] if cipher else None,
                        "cert_hash": cert_hash,
                    }
                )

        except Exception:
            pass

        return None

    def _analyze_http(self, target: str, port: int) -> Optional:
        """Analyze HTTP behavior"""
        from ..core.pipeline import VectorSignal

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            if port == 443:
                # Use HTTPS
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=target)

            request = f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n"
            sock.send(request.encode())

            response = sock.recv(4096).decode("utf-8", errors="ignore")
            sock.close()

            if response:
                # Parse headers
                lines = response.split("\r\n")
                server_header = None
                for line in lines:
                    if line.lower().startswith("server:"):
                        server_header = line.split(":", 1)[1].strip()
                        break

                return VectorSignal(
                    source="protocol",
                    value=0.8,
                    confidence=0.85,
                    timestamp=time.time(),
                    metadata={
                        "server_header": server_header,
                        "response_length": len(response),
                    }
                )

        except Exception:
            pass

        return None


class BehaviorSignalCollector(BaseSignalCollector):
    """Collect behavioral signals"""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def collect(self, target: str, config: Dict[str, Any]) -> List:
        """Collect behavioral signals"""
        from ..core.pipeline import VectorSignal

        signals = []
        port = config.get("port", 443)

        # Test retry behavior
        retry_signal = self._test_retry_behavior(target, port)
        if retry_signal:
            signals.append(retry_signal)

        # Test rate limiting
        rate_limit_signal = self._test_rate_limiting(target, port)
        if rate_limit_signal:
            signals.append(rate_limit_signal)

        # Test caching behavior
        cache_signal = self._test_caching(target, port)
        if cache_signal:
            signals.append(cache_signal)

        return signals

    def _test_retry_behavior(self, target: str, port: int) -> Optional:
        """Test retry behavior"""
        from ..core.pipeline import VectorSignal

        latencies = []
        for _ in range(3):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                start = time.time()
                sock.connect((target, port))
                sock.close()
                latencies.append(time.time() - start)
            except Exception:
                pass

        if latencies:
            # Consistent latencies suggest no backoff
            variance = sum((x - sum(latencies)/len(latencies))**2 for x in latencies) / len(latencies)
            if variance < 0.001:
                return VectorSignal(
                    source="behavior",
                    value=0.6,
                    confidence=0.7,
                    timestamp=time.time(),
                    metadata={"variance": variance, "behavior": "consistent_response"}
                )

        return None

    def _test_rate_limiting(self, target: str, port: int) -> Optional:
        """Test rate limiting"""
        from ..core.pipeline import VectorSignal

        successes = 0
        for _ in range(10):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((target, port))
                if result == 0:
                    successes += 1
                sock.close()
            except Exception:
                pass

        # High success rate suggests no rate limiting
        if successes >= 8:
            return VectorSignal(
                source="behavior",
                value=0.5,
                confidence=0.6,
                timestamp=time.time(),
                metadata={"successes": successes, "total": 10}
            )

        return None

    def _test_caching(self, target: str, port: int) -> Optional:
        """Test HTTP caching"""
        from ..core.pipeline import VectorSignal

        if port not in [80, 8080, 443, 8443]:
            return None

        try:
            times = []
            for i in range(2):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    if port == 443:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        sock = context.wrap_socket(sock, server_hostname=target)

                    sock.connect((target, port))
                    request = f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n"
                    start = time.time()
                    sock.send(request.encode())
                    sock.recv(4096)
                    times.append(time.time() - start)
                    sock.close()
                except Exception:
                    pass

            if len(times) == 2 and times[1] < times[0] * 0.8:
                # Second request significantly faster suggests caching
                return VectorSignal(
                    source="behavior",
                    value=0.7,
                    confidence=0.75,
                    timestamp=time.time(),
                    metadata={"first_time": times[0], "second_time": times[1]}
                )

        except Exception:
            pass

        return None
