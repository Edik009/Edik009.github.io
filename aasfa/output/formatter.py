"""Output formatter for console output.

v2.0 formatting requirements:
- No timestamps in console
- ASCII header
- Unified result symbols: [+] found, [-] not found, [*] info, [!] warning
- Summary with Risk Score
- Mandatory assessment-only disclaimer
"""

from __future__ import annotations

import sys
from typing import List

from ..core.result_aggregator import ScanResult, ResultAggregator
from ..utils.config import COLORS


ASSESSMENT_ONLY_DISCLAIMER = (
    "Scanner performs feasibility assessment only and does not exploit vulnerabilities."
)


def _use_colors() -> bool:
    return sys.stdout.isatty()


def _c(key: str) -> str:
    if not _use_colors():
        return ""
    return COLORS.get(key, "")


class OutputFormatter:
    """Форматтер вывода"""

    @staticmethod
    def format_header() -> str:
        """Форматирование заголовка"""
        return (
            f"{_c('BOLD')}"
            "╔══════════════════════════════════════════════════════════════╗\n"
            "║         AASFA Scanner - Android Attack Surface Scanner       ║\n"
            "║              Pre-Attack Assessment Tool v2.0                 ║\n"
            "║        Scanner performs feasibility assessment only          ║\n"
            "║         and does not exploit vulnerabilities.                ║\n"
            f"╚══════════════════════════════════════════════════════════════╝{_c('RESET')}\n"
        )

    @staticmethod
    def format_scan_context(target: str, mode: str, total_checks: int) -> str:
        return (
            f"\n[*] Target: {target}\n"
            f"[*] Mode: {mode}\n"
            f"[*] Total checks: {total_checks}\n"
            "[*] Starting scan...\n"
        )

    @staticmethod
    def format_result_line(vector_id: int, vector_name: str, *, status: str, severity: str | None = None) -> str:
        """Format a single result line.

        status: one of '+', '-', '*', '!'
        """
        symbol = f"[{status}]"
        if severity:
            return f"{symbol} VECTOR_{vector_id:03d}: {vector_name} [{severity}]"
        return f"{symbol} VECTOR_{vector_id:03d}: {vector_name}"

    @staticmethod
    def format_summary(aggregator: ResultAggregator) -> str:
        """Форматирование итоговой сводки"""
        summary = aggregator.get_summary()
        vulns = sorted(aggregator.get_vulnerabilities(), key=lambda r: (r.severity, r.vector_id))

        risk_score = aggregator.get_risk_score()
        risk_level = "LOW"
        if risk_score >= 75:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"

        output = "\n" + "=" * 70 + "\n"
        output += " " * 25 + "SCAN SUMMARY\n"
        output += "=" * 70 + "\n\n"

        output += f"Total checks performed: {summary['total_checks']}\n"
        output += f"Scan duration: {summary['duration_seconds']:.2f} seconds\n"
        output += f"Vulnerabilities found: {summary['vulnerabilities_found']}\n\n"

        if vulns:
            for v in vulns:
                output += OutputFormatter.format_result_line(v.vector_id, v.vector_name, status='+', severity=v.severity) + "\n"
        else:
            output += "[-] No vulnerabilities found\n"

        output += "\n"
        output += f"Risk Score: {risk_score}/100 [{risk_level}]\n\n"
        output += ASSESSMENT_ONLY_DISCLAIMER + "\n"
        output += "=" * 70 + "\n"
        return output

    @staticmethod
    def format_vulnerability_details(vulnerabilities: List[ScanResult]) -> str:
        """Детальное форматирование уязвимостей (verbose)"""
        if not vulnerabilities:
            return "\nNo vulnerabilities to display.\n"

        output = "\n" + "=" * 70 + "\n"
        output += " " * 18 + "VULNERABILITY DETAILS\n"
        output += "=" * 70 + "\n\n"

        for vuln in vulnerabilities:
            output += f"[{vuln.severity}] VECTOR_{vuln.vector_id:03d}: {vuln.vector_name}\n"
            output += f"Details: {vuln.details}\n"
            output += f"Timestamp: {vuln.timestamp}\n\n"

        return output
