"""
AASFA Scanner v5.0 - Complete Rewrite
Pure console output, multifactor verification, real device identification
"""

import sys
import argparse
import time
from typing import Optional

from aasfa.utils.config import ScanConfig
from aasfa.utils.logger import init_logger
from aasfa.utils.validators import validate_ip
from aasfa.core.multifactor_scanner import MultifactorScanner, VectorScheduler
from aasfa.core.device_identifier import identify_device_real
from aasfa.core.result_aggregator import ResultAggregator
from aasfa.output.clean_formatter import CleanTextFormatter


def interactive_device_identification():
    """Real device identification (not a stub)"""
    print(CleanTextFormatter.format_header())
    print("DEVICE IDENTIFICATION MODE")
    print("=" * 70)
    print()
    
    target_ip = input("Enter target IP address: ").strip()
    
    if not validate_ip(target_ip):
        print(f"\nERROR: Invalid IP address: {target_ip}")
        print("=" * 70)
        input("\nPress Enter to return to main menu...")
        return
    
    print(f"\nScanning device at {target_ip}...")
    print("=" * 70)
    print()
    
    config = ScanConfig(
        target_ip=target_ip,
        adb_port=5555,
        mode='deep',
        output_file=None,
        verbose=False,
        no_network=False,
        adb_only=False,
        remote_only=True,
        timeout=5,
        threads=10,
        debug_level=0,
        thread_timeout=10,
        port_scan_timeout=2,
        timing_samples=30,
        enrichment_mode='offline',
        baseline_db='aasfa/data/baseline.json',
        packet_capture_enabled=False
    )
    
    try:
        # Perform real device identification
        device_info = identify_device_real(config)
        
        # Display results
        print(CleanTextFormatter.format_device_identification(device_info))
        
        # Quick security assessment
        aggregator = ResultAggregator()
        scanner = MultifactorScanner(config, aggregator)
        
        print("Performing quick security check...")
        print("=" * 70)
        print()
        
        # Run critical checks
        critical_checks = [
            scanner.check_open_port_23_telnet(),
            scanner.check_open_port_21_ftp(),
            scanner.check_ssh_weak_ciphers(),
            scanner.check_adb_debugging_enabled() if device_info.get('device_type') == 'Android Device' else None,
            scanner.check_weak_ssl_tls()
        ]
        
        vulnerable_count = 0
        for result in critical_checks:
            if result and result.vulnerable:
                vulnerable_count += 1
                print(f"  [FOUND] VECTOR_{result.vector_id:03d}: {result.vector_name}")
        
        print()
        print("=" * 70)
        print()
        
        if vulnerable_count == 0:
            print("Device appears to be SECURE")
        elif vulnerable_count <= 2:
            print("Device has MINOR security issues")
        elif vulnerable_count <= 4:
            print("Device has MODERATE security vulnerabilities")
        else:
            print("Device is CRITICALLY vulnerable")
        
        print("=" * 70)
        
    except Exception as e:
        print(f"\nERROR: Device identification failed: {str(e)}")
    
    print()
    input("Press Enter to return to main menu...")


def run_full_scan(target_ip: str, mode: str = 'deep', verbose: bool = False):
    """Run full multifactor security scan"""
    print(CleanTextFormatter.format_header())
    
    config = ScanConfig(
        target_ip=target_ip,
        adb_port=5555,
        mode=mode,
        output_file=None,
        verbose=verbose,
        no_network=False,
        adb_only=False,
        remote_only=True,
        timeout=5,
        threads=20,
        debug_level=1 if verbose else 0,
        thread_timeout=10,
        port_scan_timeout=2,
        timing_samples=30,
        enrichment_mode='offline',
        baseline_db='aasfa/data/baseline.json',
        packet_capture_enabled=False
    )
    
    start_time = time.time()
    
    try:
        # Identify device first
        print("Phase 1: Device Identification...")
        print("=" * 70)
        device_info = identify_device_real(config)
        print(CleanTextFormatter.format_device_identification(device_info))
        
        # Run multifactor scan
        print("Phase 2: Multifactor Security Scan...")
        print("=" * 70)
        
        aggregator = ResultAggregator()
        aggregator.add_device_info(device_info)
        
        scheduler = VectorScheduler(MultifactorScanner(config, aggregator), config)
        scheduler.execute_all(aggregator)
        
        scan_duration = time.time() - start_time
        
        # Display comprehensive results
        print(CleanTextFormatter.format_summary(aggregator, scan_duration))
        
        # Critical vulnerabilities exit with code 2
        severity_counts = aggregator.get_severity_counts()
        if severity_counts.get('CRITICAL', 0) > 0:
            sys.exit(2)
        
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n\nERROR: Scan failed: {str(e)}")
        sys.exit(1)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="AASFA Scanner v5.0 - Universal Security Scanner with Multifactor Verification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main_new.py                         # Interactive device identification
  python main_new.py -t 192.168.1.100        # Quick device scan
  python main_new.py -t 192.168.1.100 -m deep # Full multifactor scan
  python main_new.py -t 192.168.1.100 -v     # Verbose output

Security Assessment Only:
  This tool identifies vulnerabilities but does NOT exploit them.
  All checks are read-only and safe for production networks.
        """
    )
    
    parser.add_argument(
        '-t', '--target',
        type=str,
        help='Target IP address for CLI scan mode'
    )
    
    parser.add_argument(
        '-m', '--mode',
        choices=['fast', 'full', 'deep'],
        default='deep',
        help='Scan depth: fast (basic checks), full (standard), deep (all vectors)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output with detailed information'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=20,
        help='Number of parallel scan threads (default: 20)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=5,
        help='Connection timeout in seconds (default: 5)'
    )
    
    return parser.parse_args()


def interactive_menu():
    """Interactive Russian menu"""
    while True:
        print(CleanTextFormatter.format_header())
        print("ГЛАВНОЕ МЕНЮ")
        print("=" * 70)
        print()
        print("1. Узнать что это за устройство (быстрая диагностика)")
        print("2. Запустить полное сканирование безопасности")
        print("3. Настройки")
        print("4. Выход")
        print()
        print("=" * 70)
        
        try:
            choice = input("\nВыберите действие (1-4): ").strip()
            
            if choice == '1':
                interactive_device_identification()
            elif choice == '2':
                target = input("\nВведите IP адрес цели: ").strip()
                if validate_ip(target):
                    run_full_scan(target, mode='deep')
                    input("\nСканирование завершено. Нажмите Enter...")
                else:
                    print("\nОШИБКА: Неверный IP адрес!")
                    input("Нажмите Enter...")
            elif choice == '3':
                print("\nНастройки пока недоступны в этой версии.")
                input("Нажмите Enter...")
            elif choice == '4':
                print("\nСпасибо за использование AASFA Scanner!")
                sys.exit(0)
            else:
                print("\nНеверный выбор!")
                time.sleep(1)
        
        except KeyboardInterrupt:
            print("\n\nСпасибо за использование AASFA Scanner!")
            sys.exit(0)
        except Exception as e:
            print(f"\n\nОШИБКА: {str(e)}")
            input("Нажмите Enter...")


def main():
    """Main entry point"""
    # If no arguments, show interactive menu
    if len(sys.argv) == 1:
        try:
            interactive_menu()
        except KeyboardInterrupt:
            print("\n\nСпасибо за использование AASFA Scanner!")
            sys.exit(0)
    else:
        # CLI mode
        args = parse_arguments()
        
        if not args.target:
            print("ERROR: Target IP address required for CLI mode")
            print("Use: python main_new.py -t <IP_ADDRESS>")
            sys.exit(1)
        
        if not validate_ip(args.target):
            print(f"ERROR: Invalid IP address: {args.target}")
            sys.exit(1)
        
        run_full_scan(args.target, mode=args.mode, verbose=args.verbose)


if __name__ == "__main__":
    main()