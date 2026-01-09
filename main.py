#!/usr/bin/env python3
"""
AASFA Scanner - Android Attack Surface & Feasibility Assessment
Main entry point
"""
import sys
import argparse

from aasfa.utils.config import ScanConfig
from aasfa.utils.logger import init_logger
from aasfa.utils.validators import validate_ip, validate_port
from aasfa.core.scanner_engine import ScannerEngine
from aasfa.output.formatter import OutputFormatter
from aasfa.output.report_generator import ReportGenerator


def parse_arguments():
    """Парсинг аргументов командной строки"""
    parser = argparse.ArgumentParser(
        description="AASFA Scanner - Android Attack Surface & Feasibility Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py -t 192.168.1.100
  python3 main.py -t 192.168.1.100 -m deep -o report.txt
  python3 main.py -t 192.168.1.100 --adb-only --threads 5
  python3 main.py -t 192.168.1.100 -m fast --no-network -v
        """
    )
    
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target device IP address (required)'
    )
    
    parser.add_argument(
        '-p', '--port',
        type=int,
        default=5555,
        help='ADB port (default: 5555)'
    )
    
    parser.add_argument(
        '-m', '--mode',
        choices=['fast', 'full', 'deep'],
        default='full',
        help='Scan mode: fast (priority 1-2), full (priority 1-3), deep (all vectors) (default: full)'
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
        '--no-network',
        action='store_true',
        help='Skip network-level checks'
    )
    
    parser.add_argument(
        '--adb-only',
        action='store_true',
        help='Only ADB-based checks'
    )

    parser.add_argument(
        '--remote-only',
        action='store_true',
        help='Only remote/network checks (NO USB REQUIRED)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Check timeout in seconds (default: 30)'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=10,
        help='Number of threads for parallel scanning (default: 10)'
    )
    
    return parser.parse_args()


def validate_arguments(args) -> bool:
    """Валидация аргументов"""
    if not validate_ip(args.target):
        print(f"[!] Error: Invalid IP address: {args.target}")
        return False
    
    if not validate_port(args.port):
        print(f"[!] Error: Invalid port: {args.port}")
        return False
    
    if args.threads < 1 or args.threads > 50:
        print(f"[!] Error: Threads must be between 1 and 50")
        return False
    
    if args.timeout < 1:
        print(f"[!] Error: Timeout must be at least 1 second")
        return False

    if args.remote_only and (args.adb_only or args.no_network):
        print("[!] Error: --remote-only cannot be combined with --adb-only or --no-network")
        return False
    
    return True


def main():
    """Главная функция"""
    args = parse_arguments()
    
    if not validate_arguments(args):
        sys.exit(1)
    
    config = ScanConfig(
        target_ip=args.target,
        adb_port=args.port,
        mode=args.mode,
        output_file=args.output,
        verbose=args.verbose,
        no_network=args.no_network,
        adb_only=args.adb_only,
        remote_only=args.remote_only,
        timeout=args.timeout,
        threads=args.threads
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
