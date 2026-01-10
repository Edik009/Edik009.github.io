#!/usr/bin/env python3
"""
AASFA Scanner v3.0 - Android Attack Surface & Feasibility Assessment
Main entry point
"""
import sys
import argparse

from aasfa.utils.config import ScanConfig
from aasfa.utils.logger import init_logger
from aasfa.utils.validators import validate_ip
from aasfa.core.scanner_engine import ScannerEngine
from aasfa.output.formatter import OutputFormatter
from aasfa.output.report_generator import ReportGenerator


def parse_arguments():
    """Парсинг аргументов командной строки"""
    parser = argparse.ArgumentParser(
        description="AASFA Scanner v3.0 - Android Attack Surface & Feasibility Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py -t 192.168.1.100
  python3 main.py -t 192.168.1.100 -m deep -o report.txt
  python3 main.py -t 192.168.1.100 -m deep --threads 20
  python3 main.py -t 192.168.1.100 -m fast -v

Scanner performs feasibility assessment only and does not exploit vulnerabilities.
Remote analysis only, no USB/ADB required.
        """
    )

    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target device IP address (required)'
    )

    parser.add_argument(
        '-m', '--mode',
        choices=['fast', 'full', 'deep'],
        default='deep',
        help='Scan mode: fast (priority 1-2), full (priority 1-3), deep (all vectors) (default: deep)'
    )

    parser.add_argument(
        '-o', '--output',
        help='Save report to file (txt or json)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )

    parser.add_argument(
        '--timeout',
        type=int,
        default=5,
        help='Check timeout in seconds (default: 5)'
    )

    parser.add_argument(
        '--threads',
        type=int,
        default=20,
        help='Number of threads for parallel scanning (default: 20)'
    )

    parser.add_argument(
        '--thread-timeout',
        type=int,
        default=10,
        help='Per-vector timeout inside thread pool in seconds (default: 10)'
    )

    parser.add_argument(
        '--port-scan-timeout',
        type=int,
        default=2,
        help='Port scan socket timeout in seconds (default: 2)'
    )

    parser.add_argument(
        '-d', '--debug',
        action='count',
        default=0,
        help='Enable debug mode (use -d for level 1, -dd for level 2)'
    )

    return parser.parse_args()


def validate_arguments(args) -> bool:
    """Валидация аргументов"""
    if not validate_ip(args.target):
        print(f"[!] Error: Invalid IP address: {args.target}")
        return False

    if args.threads < 1 or args.threads > 50:
        print(f"[!] Error: Threads must be between 1 and 50")
        return False

    if args.timeout < 1:
        print(f"[!] Error: Timeout must be at least 1 second")
        return False

    if args.thread_timeout < 1:
        print(f"[!] Error: Thread timeout must be at least 1 second")
        return False

    if args.port_scan_timeout < 1:
        print(f"[!] Error: Port scan timeout must be at least 1 second")
        return False

    return True


def main():
    """Главная функция"""
    args = parse_arguments()

    if not validate_arguments(args):
        sys.exit(1)

    config = ScanConfig(
        target_ip=args.target,
        adb_port=5555,  # Not used, but required by ScanConfig
        mode=args.mode,
        output_file=args.output,
        verbose=args.verbose,
        no_network=False,  # Always do network checks
        adb_only=False,  # Never do ADB-only
        remote_only=True,  # Always remote-only
        timeout=args.timeout,
        threads=args.threads,
        debug_level=args.debug,
        thread_timeout=args.thread_timeout,
        port_scan_timeout=args.port_scan_timeout,
    )

    if not config.validate():
        print("[!] Error: Invalid configuration")
        sys.exit(1)

    log_file = "aasfa_scan.log" if args.verbose else None
    logger = init_logger(args.verbose, log_file)

    print(OutputFormatter.format_header())

    try:
        engine = ScannerEngine(config)
        aggregator = engine.scan()

        print(OutputFormatter.format_summary(aggregator))

        vulnerabilities = aggregator.get_vulnerabilities()
        if vulnerabilities and args.verbose:
            print(OutputFormatter.format_vulnerability_details(vulnerabilities))

        if args.output:
            ReportGenerator.save_report(aggregator, args.output)
            logger.info(f"[+] Report saved to: {args.output}")

        critical_count = aggregator.get_severity_counts().get('CRITICAL', 0)
        if critical_count > 0:
            sys.exit(2)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)

    except Exception as e:
        logger.error(f"[!] Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
