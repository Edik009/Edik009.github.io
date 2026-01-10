"""Scan history management"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional


class ScanHistory:
    """Manage scan history"""

    def __init__(self, history_file: str = "/results/scan_history.json"):
        self.history_file = Path(history_file)
        self.history: List[Dict[str, Any]] = []
        self._load_history()

    def _load_history(self) -> None:
        """Load history from file"""
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    self.history = json.load(f)
            except Exception:
                self.history = []

    def _save_history(self) -> None:
        """Save history to file"""
        self.history_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.history_file, 'w', encoding='utf-8') as f:
            json.dump(self.history, f, indent=2, ensure_ascii=False)

    def add_scan(
        self,
        ip: str,
        device_type: str,
        vulnerabilities_count: int,
        duration_seconds: float
    ) -> None:
        """Add a scan to history"""
        scan = {
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "device_type": device_type,
            "vulnerabilities_count": vulnerabilities_count,
            "duration_seconds": duration_seconds
        }

        self.history.append(scan)

        # Keep only last 50 scans
        if len(self.history) > 50:
            self.history = self.history[-50:]

        self._save_history()

    def get_all(self) -> List[str]:
        """Get all scan records as formatted strings"""
        formatted = []

        for i, scan in enumerate(self.history, 1):
            timestamp = datetime.fromisoformat(scan['timestamp']).strftime("%Y-%m-%d %H:%M")
            vuln_count = scan['vulnerabilities_count']
            duration = int(scan['duration_seconds'])

            line = (
                f"{i}. [{timestamp}] {scan['ip']} ({scan['device_type']}) - "
                f"{vuln_count} уязвимостей, {duration} сек"
            )
            formatted.append(line)

        return formatted

    def get_scan(self, index: int) -> Optional[Dict[str, Any]]:
        """Get a specific scan by index"""
        if 0 <= index < len(self.history):
            return self.history[index]
        return None

    def clear_history(self) -> None:
        """Clear all scan history"""
        self.history = []
        self._save_history()

    def get_stats(self) -> Dict[str, Any]:
        """Get scan statistics"""
        if not self.history:
            return {
                "total_scans": 0,
                "total_vulnerabilities": 0,
                "average_duration": 0,
                "device_types": {}
            }

        total_scans = len(self.history)
        total_vulns = sum(scan['vulnerabilities_count'] for scan in self.history)
        total_duration = sum(scan['duration_seconds'] for scan in self.history)

        device_types = {}
        for scan in self.history:
            dtype = scan['device_type']
            if dtype not in device_types:
                device_types[dtype] = 0
            device_types[dtype] += 1

        return {
            "total_scans": total_scans,
            "total_vulnerabilities": total_vulns,
            "average_duration": total_duration / total_scans,
            "device_types": device_types
        }
