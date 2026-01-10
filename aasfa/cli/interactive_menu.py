"""Interactive Russian menu for AASFA Scanner v5"""

import sys
from typing import Optional

from .colors import Colors, bold, colorize, red, green, yellow, cyan, blue, use_colors
from .language import Language
from ..device_types.device_detector import DeviceDetector
from ..device_types.base_device import BaseDevice
from ..results.scan_history import ScanHistory


class InteractiveMenu:
    """Interactive menu system for Russian interface"""

    def __init__(self):
        self.device_detector = DeviceDetector()
        self.scan_history = ScanHistory()
        self.running = True

    def show_header(self) -> None:
        """Display beautiful ASCII header"""
        title = Language.APP_TITLE
        version = Language.APP_VERSION
        subtitle = Language.APP_SUBTITLE

        if use_colors():
            print(f"\n{Colors.BOLD}{Colors.CYAN}")
        print("╔" + "═" * 64 + "╗")
        print("║" + " " * 64 + "║")
        print(f"║{title.center(64)}║")
        print(f"║{version.center(64)}║")
        print(f"║{subtitle.center(64)}║")
        print("║" + " " * 64 + "║")
        print("╚" + "═" * 64 + "╝")
        if use_colors():
            print(Colors.RESET)

    def show_main_menu(self) -> None:
        """Display main menu options"""
        print("\n" + bold(Language.MAIN_MENU_TITLE) + "\n")

        for key, option in Language.MAIN_MENU_OPTIONS.items():
            print(f"  {key}. {option}")

        print()

    def get_user_choice(self, prompt: str, options: list = None, default: str = None) -> str:
        """Get user input with validation"""
        while True:
            try:
                choice = input(bold(prompt)).strip()

                # Handle empty input with default
                if not choice and default:
                    return default

                # Validate against options if provided
                if options and choice not in options:
                    print(red(Language.INVALID_CHOICE))
                    continue

                return choice
            except (EOFError, KeyboardInterrupt):
                print("\n" + yellow("Выход..."))
                sys.exit(0)

    def get_ip_address(self, prompt: str = None) -> str:
        """Get and validate IP address"""
        if not prompt:
            prompt = Language.ENTER_IP

        while True:
            ip = self.get_user_choice(prompt)

            # Basic IP validation
            parts = ip.split('.')
            if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                return ip
            else:
                print(red(Language.INVALID_IP))

    def show_scan_modes(self, device_type: str) -> str:
        """Show scan mode selection"""
        device_name = Language.DEVICE_TYPES.get(device_type, device_type)
        print(f"\n╔" + "═" * 64 + "╗")
        print(f"║{f'  Сканирование {device_name}'.center(64)}║")
        print("╚" + "═" * 64 + "╝\n")

        print(bold(Language.SCAN_MODE_TITLE) + "\n")

        modes = ["fast", "standard", "deep", "learning"]
        for i, mode in enumerate(modes, 1):
            print(f"  {i}. {Language.SCAN_MODES[mode]}")
            print(Language.SCAN_MODE_DESCRIPTIONS[mode])

        print()
        choice = self.get_user_choice(Language.SCAN_MODE_PROMPT, ["1", "2", "3", "4"])

        mode_map = {"1": "fast", "2": "standard", "3": "deep", "4": "learning"}
        return mode_map[choice]

    def handle_device_scan(self, device_type: str) -> None:
        """Handle scanning a specific device type"""
        ip = self.get_ip_address()
        mode = self.show_scan_modes(device_type)

        # Import appropriate device scanner
        device_scanner = self._get_device_scanner(device_type, ip)

        if device_scanner:
            device_scanner.scan(mode)
        else:
            print(red(f"❌ Сканирование для {device_type} ещё не реализовано"))

    def handle_auto_diagnosis(self) -> None:
        """Handle automatic device diagnosis"""
        ip = self.get_ip_address(Language.ENTER_IP_AUTO)

        print(f"\n{yellow(Language.SCANNING_CHARACTERISTICS)}")

        # Perform quick diagnosis
        diagnosis = self.device_detector.diagnose(ip)

        self._show_diagnosis_results(diagnosis)

        # Ask if user wants full scan
        choice = self.get_user_choice(Language.FULL_SCAN_PROMPT, ["д", "н", "y", "n"]).lower()

        if choice in ["д", "y"]:
            device_type = diagnosis.get("device_type", "android")
            self.handle_device_scan(device_type)

    def _show_diagnosis_results(self, diagnosis: dict) -> None:
        """Display diagnosis results"""
        print(f"\n╔" + "═" * 64 + "╗")
        print("║" + " " * 64 + "║")
        print("║" + bold(Language.DIAGNOSIS_RESULTS).center(64) + "║")
        print("║" + " " * 64 + "║")
        print("╚" + "═" * 64 + "╝")

        print(f"\n{bold(Language.BASIC_INFO)}")
        for key, value in diagnosis.get("basic_info", {}).items():
            print(f"  {key}: {value}")

        print(f"\n{bold(Language.PORTS_AND_SERVICES)}")
        for port_info in diagnosis.get("ports", []):
            print(f"  {port_info}")

        print(f"\n{bold(Language.FOUND_PROBLEMS)}")
        for problem in diagnosis.get("problems", []):
            print(f"  {problem}")

        print(f"\n{yellow(Language.RECOMMENDATION)}")
        print(f"  {diagnosis.get('recommendation', '')}\n")

    def show_scan_history(self) -> None:
        """Display scan history"""
        history = self.scan_history.get_all()

        print(f"\n╔" + "═" * 64 + "╗")
        print("║" + " " * 64 + "║")
        print("║" + bold(Language.SCAN_HISTORY_TITLE).center(64) + "║")
        print("║" + " " * 64 + "║")
        print("╚" + "═" * 64 + "╝\n")

        if not history:
            print(yellow(Language.NO_HISTORY))
        else:
            for i, scan in enumerate(history, 1):
                print(f"{i}. {scan}")

        print()

    def show_settings(self) -> None:
        """Display settings menu"""
        print(f"\n╔" + "═" * 64 + "╗")
        print("║" + " " * 64 + "║")
        print("║" + bold(Language.SETTINGS_TITLE).center(64) + "║")
        print("║" + " " * 64 + "║")
        print("╚" + "═" * 64 + "╝\n")

        print(cyan("Настройки ещё не реализованы.\n"))
        print(Language.BACK_TO_MENU)

    def _get_device_scanner(self, device_type: str, ip: str) -> Optional[BaseDevice]:
        """Get appropriate device scanner instance"""
        scanners = {
            "android": lambda: self._import_scanner("android", "AndroidDevice", ip),
            "windows": lambda: self._import_scanner("windows", "WindowsDevice", ip),
            "macos": lambda: self._import_scanner("macos", "MacOSDevice", ip),
            "ios": lambda: self._import_scanner("ios", "IOSDevice", ip),
            "appletv": lambda: self._import_scanner("appletv", "AppleTVDevice", ip),
            "smartdevice": lambda: self._import_scanner("smartdevice", "SmartDevice", ip),
        }

        scanner_factory = scanners.get(device_type)
        if scanner_factory:
            return scanner_factory()
        return None

    def _import_scanner(self, module_name: str, class_name: str, ip: str) -> Optional[BaseDevice]:
        """Dynamically import device scanner"""
        try:
            module = __import__(f"aasfa.device_types.{module_name}_device", fromlist=[class_name])
            scanner_class = getattr(module, class_name)
            return scanner_class(ip)
        except (ImportError, AttributeError):
            return None

    def run(self) -> None:
        """Run the interactive menu"""
        self.show_header()

        while self.running:
            self.show_main_menu()

            choice = self.get_user_choice(
                Language.MAIN_MENU_PROMPT,
                ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
                default="7"  # Default to auto-diagnosis
            )

            if choice == "0":
                print("\n" + yellow("Спасибо за использование МАЯК!"))
                self.running = False

            elif choice == "1":
                self.handle_device_scan("android")

            elif choice == "2":
                self.handle_device_scan("windows")

            elif choice == "3":
                self.handle_device_scan("macos")

            elif choice == "4":
                self.handle_device_scan("ios")

            elif choice == "5":
                self.handle_device_scan("appletv")

            elif choice == "6":
                self.handle_device_scan("smartdevice")

            elif choice == "7":
                self.handle_auto_diagnosis()

            elif choice == "8":
                self.show_scan_history()

            elif choice == "9":
                self.show_settings()

            # Pause before showing menu again
            if self.running:
                input("\nНажми Enter для продолжения...")
                self.show_header()


def launch_interactive_menu():
    """Launch the interactive menu (entry point)"""
    menu = InteractiveMenu()
    try:
        menu.run()
    except KeyboardInterrupt:
        print("\n" + yellow("Спасибо за использование МАЯК!"))
        sys.exit(0)
