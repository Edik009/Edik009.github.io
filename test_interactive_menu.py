#!/usr/bin/env python3
"""Test script to verify interactive menu loads correctly"""

import sys

print("Testing AASFA Scanner v5.0 Interactive Menu...")
print()

# Test 1: Import modules
print("[+] Testing imports...")
try:
    from aasfa.cli.colors import Colors, red, green, yellow, blue, bold
    print("    ✓ Colors module imported")
except ImportError as e:
    print(f"    ✗ Colors module: {e}")
    sys.exit(1)

try:
    from aasfa.cli.language import Language
    print("    ✓ Language module imported")
except ImportError as e:
    print(f"    ✗ Language module: {e}")
    sys.exit(1)

try:
    from aasfa.device_types.base_device import BaseDevice
    print("    ✓ BaseDevice class imported")
except ImportError as e:
    print(f"    ✗ BaseDevice: {e}")
    sys.exit(1)

try:
    from aasfa.device_types.android_device import AndroidDevice
    print("    ✓ AndroidDevice class imported")
except ImportError as e:
    print(f"    ✗ AndroidDevice: {e}")
    sys.exit(1)

try:
    from aasfa.device_types.device_detector import DeviceDetector
    print("    ✓ DeviceDetector class imported")
except ImportError as e:
    print(f"    ✗ DeviceDetector: {e}")
    sys.exit(1)

try:
    from aasfa.results.result_formatter import ResultFormatter
    print("    ✓ ResultFormatter class imported")
except ImportError as e:
    print(f"    ✗ ResultFormatter: {e}")
    sys.exit(1)

try:
    from aasfa.results.export_handler import ExportHandler
    print("    ✓ ExportHandler class imported")
except ImportError as e:
    print(f"    ✗ ExportHandler: {e}")
    sys.exit(1)

try:
    from aasfa.results.scan_history import ScanHistory
    print("    ✓ ScanHistory class imported")
except ImportError as e:
    print(f"    ✗ ScanHistory: {e}")
    sys.exit(1)

try:
    from aasfa.cli.interactive_menu import InteractiveMenu
    print("    ✓ InteractiveMenu class imported")
except ImportError as e:
    print(f"    ✗ InteractiveMenu: {e}")
    sys.exit(1)

print()
print("[+] All modules imported successfully!")
print()

# Test 2: Display sample header
print("[+] Testing ASCII art header...")
menu = InteractiveMenu()
menu.show_header()
print()

# Test 3: Check device types
print("[+] Testing device type configurations...")
device_types = Language.DEVICE_TYPES
print(f"    Available device types: {list(device_types.keys())}")
print()

# Test 4: Check scan modes
print("[+] Testing scan mode configurations...")
scan_modes = Language.SCAN_MODES
for mode, description in scan_modes.items():
    print(f"    {mode}: {description[:30]}...")
print()

# Test 5: Test color output
print("[+] Testing color output...")
print(f"    {red('Red text')}")
print(f"    {green('Green text')}")
print(f"    {yellow('Yellow text')}")
print(f"    {blue('Blue text')}")
print(f"    {bold('Bold text')}")
print()

print("[✓] All tests passed! The interactive menu is ready to use.")
print()
print("To launch the interactive menu, run:")
print("    python main.py")
