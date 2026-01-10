"""iOS device scanner"""

from .base_device import BaseDevice
from ..utils.config import ScanConfig
from ..core.result_aggregator import ResultAggregator
from typing import Dict, Any


class IOSDevice(BaseDevice):
    """iOS device scanner"""

    def __init__(self, ip: str):
        super().__init__(ip)
        self.device_type = "ios"

    def scan(self, mode: str = "standard") -> Dict[str, Any]:
        """Perform security scan on iOS device"""
        aggregator = self.run_scan(mode)
        self.show_results(aggregator, mode)

        return {
            "device_type": self.device_type,
            "ip": self.ip,
            "scan_duration": (self.scan_end_time - self.scan_start_time).total_seconds(),
            "vulnerabilities_found": len(aggregator.get_vulnerabilities())
        }

    def get_device_info(self) -> Dict[str, Any]:
        """Get iOS device information"""
        return {
            "type": "iPhone/iPad (iOS)",
            "manufacturer": "Apple",
            "model": "Неизвестно",
            "os": "iOS",
            "status": "Требуется сканирование"
        }

    def create_scan_config(self, mode: str) -> ScanConfig:
        """Create iOS-specific scan configuration"""
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
            verbose=True,
            no_network=False,
            adb_only=False,
            remote_only=True,
            timeout=10,
            threads=20,
            debug_level=0,
        )
