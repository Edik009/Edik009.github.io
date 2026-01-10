"""
Configuration management for AASFA Scanner
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class ScanConfig:
    """Конфигурация сканирования"""

    target_ip: str
    adb_port: int = 5555
    mode: str = "full"  # fast, full, deep
    output_file: Optional[str] = None
    verbose: bool = False

    no_network: bool = False
    adb_only: bool = False
    remote_only: bool = False

    timeout: int = 30
    threads: int = 10

    # Debug verbosity for ScannerEngine (0=off, 1=stages, 2=verbose)
    debug_level: int = 0

    # Hard timeout for a single vector execution inside thread pool
    thread_timeout: int = 10

    # Network connector port scan timeout (seconds)
    port_scan_timeout: int = 2

    # NEW: Phase 1 Infrastructure - Side-Channel Analysis
    timing_samples: int = 30  # Number of timing samples to collect
    enrichment_mode: str = "offline"  # offline | enriched
    baseline_db: str = "aasfa/data/baseline.json"  # Baseline database path
    packet_capture_enabled: bool = False  # Enable packet capture for analysis

    def validate(self) -> bool:
        """Валидация конфигурации"""
        if not self.target_ip:
            return False
        if self.mode not in ["fast", "full", "deep"]:
            return False
        if self.threads < 1 or self.threads > 50:
            return False
        if self.timeout < 1:
            return False
        if self.thread_timeout < 1:
            return False
        if self.port_scan_timeout < 1:
            return False
        if self.debug_level < 0:
            return False
        if self.remote_only and (self.adb_only or self.no_network):
            return False
        
        # NEW: Phase 1 validation
        if self.timing_samples < 10 or self.timing_samples > 300:
            return False
        if self.enrichment_mode not in ["offline", "enriched"]:
            return False
        if self.baseline_db and not self.baseline_db.endswith('.json'):
            return False
            
        return True


DEFAULT_PORTS = {
    "adb": [5555, 5037],
    "vnc": [5900, 5901],
    "rdp": [3389],
    "ssh": [22],
    "telnet": [23],
    "http": [80, 8080, 8081, 8888],
    "https": [443, 8443],
    "ftp": [21],
    "mqtt": [1883, 8883],
    "upnp": [1900],
}

SEVERITY_LEVELS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

COLORS = {
    "CRITICAL": "\033[91m",  # Red
    "HIGH": "\033[93m",      # Yellow
    "MEDIUM": "\033[94m",    # Blue
    "LOW": "\033[92m",       # Green
    "INFO": "\033[37m",      # White
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
}
