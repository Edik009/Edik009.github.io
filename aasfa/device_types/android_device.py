"""Android device scanner"""

from typing import Dict, Any
from datetime import datetime

from .base_device import BaseDevice
from ..cli.language import Language
from ..utils.config import ScanConfig
from ..core.result_aggregator import ResultAggregator


class AndroidDevice(BaseDevice):
    """Android device scanner"""

    def __init__(self, ip: str):
        super().__init__(ip)
        self.device_type = "android"

    def scan(self, mode: str = "standard") -> Dict[str, Any]:
        """Perform security scan on Android device"""
        aggregator = self.run_scan(mode)
        self.show_results(aggregator, mode)

        return {
            "device_type": self.device_type,
            "ip": self.ip,
            "scan_duration": (self.scan_end_time - self.scan_start_time).total_seconds(),
            "vulnerabilities_found": len(aggregator.get_vulnerabilities())
        }

    def get_device_info(self) -> Dict[str, Any]:
        """Get Android device information"""
        return {
            "type": "Мобильный телефон (Android)",
            "manufacturer": "Неизвестно",
            "model": "Неизвестно",
            "os": "Android",
            "status": "Требуется сканирование"
        }

    def create_scan_config(self, mode: str) -> ScanConfig:
        """Create Android-specific scan configuration"""
        # Map UI modes to scanner modes
        mode_mapping = {
            "fast": "fast",
            "standard": "full",
            "deep": "deep",
            "learning": "full"
        }

        scan_mode = mode_mapping.get(mode, "full")

        return ScanConfig(
            target_ip=self.ip,
            mode=scan_mode,
            verbose=True,  # Always verbose in interactive mode
            no_network=False,
            adb_only=False,  # Network-only scan for now
            remote_only=True,
            timeout=10,
            threads=20,
            debug_level=0,
        )
