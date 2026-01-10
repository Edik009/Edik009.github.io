"""Base class for all device scanners"""

from abc import ABC, abstractmethod
from typing import Dict, Any
from datetime import datetime

from ..cli.language import Language
from ..cli.colors import yellow, bold, green, red
from ..utils.config import ScanConfig
from ..core.scanner_engine import ScannerEngine
from ..core.result_aggregator import ResultAggregator
from ..results.result_formatter import ResultFormatter
from ..results.export_handler import ExportHandler


class BaseDevice(ABC):
    """Abstract base class for device scanners"""

    def __init__(self, ip: str):
        self.ip = ip
        self.device_type = "unknown"
        self.scan_start_time = None
        self.scan_end_time = None
        self.results = None

    @abstractmethod
    def scan(self, mode: str = "standard") -> Dict[str, Any]:
        """Perform security scan"""
        pass

    @abstractmethod
    def get_device_info(self) -> Dict[str, Any]:
        """Get device information"""
        pass

    def create_scan_config(self, mode: str) -> ScanConfig:
        """Create scan configuration"""
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
            adb_only=False,
            remote_only=True,
            timeout=10,
            threads=20,
            debug_level=0,
        )

    def run_scan(self, mode: str = "standard") -> ResultAggregator:
        """Run the actual scan using ScannerEngine"""
        print(f"\n{yellow(Language.PERFORMING_SCAN)}\n")

        config = self.create_scan_config(mode)

        self.scan_start_time = datetime.now()

        engine = ScannerEngine(config)
        aggregator = engine.scan()

        self.scan_end_time = datetime.now()
        self.results = aggregator

        return aggregator

    def show_results(self, aggregator: ResultAggregator, mode: str = "standard") -> None:
        """Display scan results in Russian"""
        formatter = ResultFormatter(self.device_type)

        # Display formatted results
        results_text = formatter.format_results(
            aggregator,
            self.ip,
            self.scan_start_time,
            self.scan_end_time,
            mode
        )

        print(results_text)

        # Ask if user wants to export
        self._handle_export(aggregator)

    def _handle_export(self, aggregator: ResultAggregator) -> None:
        """Handle export options"""
        print(f"\n{bold(Language.EXPORT_TITLE)}\n")

        for key, option in Language.EXPORT_OPTIONS.items():
            print(f"  {key}. {option}")

        print()
        choice = self.get_user_choice(Language.EXPORT_SELECT_PROMPT, ["1", "2", "3", "4", "5"], default="1")

        format_map = {
            "1": "pdf",
            "2": "json",
            "3": "html",
            "4": "csv",
            "5": "txt"
        }

        export_format = format_map.get(choice, "pdf")

        # Generate filename with IP and timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
        filename = f"/results/{self.ip}_{timestamp}.{export_format}"

        exporter = ExportHandler()
        success = exporter.export(aggregator, filename, export_format)

        if success:
            print(f"\n{green(Language.EXPORT_SUCCESS)} {filename}")
        else:
            print(f"\n{red('❌ Ошибка при сохранении отчета')}")

    def get_user_choice(self, prompt: str, options: list = None, default: str = None) -> str:
        """Get user input with validation"""
        while True:
            try:
                choice = input(bold(prompt)).strip()

                if not choice and default:
                    return default

                if options and choice not in options:
                    print(red(Language.INVALID_CHOICE))
                    continue

                return choice
            except (EOFError, KeyboardInterrupt):
                return default or "0"
