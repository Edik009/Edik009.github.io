"""Output formatter for console output.

v3.0 formatting requirements (MSF-style):
- No timestamps in console
- ASCII header with legal disclaimers
- Unified result symbols: [+] confirmed, [*] info, [!] warning
- Summary with Risk Score
- Mandatory assessment-only disclaimer
- Only show CONFIRMED results
"""

from __future__ import annotations

import sys
from typing import List

from ..core.result_aggregator import ScanResult, ResultAggregator
from ..utils.config import COLORS


ASSESSMENT_ONLY_DISCLAIMER = (
    "Scanner performs feasibility assessment only and does not exploit vulnerabilities.\n"
    "Remote analysis only, no USB/ADB required."
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
        """Форматирование заголовка - MSF style"""
        return (
            f"{_c('BOLD')}"
            "╔═══════════════════════════════════════════════════════════════╗\n"
            "║          AASFA Scanner v3.0 - Android Attack Surface          ║\n"
            "║              Pre-Attack Feasibility Assessment                ║\n"
            "║                                                               ║\n"
            "║ Scanner performs feasibility assessment only and does not    ║\n"
            "║ exploit vulnerabilities. Remote analysis only, no USB/ADB.   ║\n"
            f"╚═══════════════════════════════════════════════════════════════╝{_c('RESET')}\n"
        )

    @staticmethod
    def format_scan_context(target: str, mode: str, total_checks: int) -> str:
        return (
            f"\n[*] Target: {target}\n"
            f"[*] Mode: {mode}\n"
            f"[*] Starting analysis...\n"
        )

    @staticmethod
    def format_result_line(vector_id: int, vector_name: str, *, status: str, severity: str | None = None) -> str:
        """Format a single result line - MSF style

        status: one of '+', '*', '!' (no '-' for not found)
        """
        symbol = f"[{status}]"
        if severity:
            return f"{symbol} VECTOR_{vector_id:03d}: {vector_name} [{severity}]"
        return f"{symbol} VECTOR_{vector_id:03d}: {vector_name}"

    @staticmethod
    def format_summary(aggregator: ResultAggregator) -> str:
        """Форматирование итоговой сводки - MSF style"""
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
        output += f"Scan duration: {summary['duration_seconds']:.2f} seconds\n\n"

        output += f"Vulnerabilities found: {summary['vulnerabilities_found']}\n\n"

        if vulns:
            for v in vulns:
                output += f"[*] VECTOR_{v.vector_id:03d}: {v.vector_name} [{v.severity}]\n"
                output += f"    Evidence:\n"
                for evidence in v.details.split("; "):
                    output += f"    - {evidence}\n"
                output += "\n"
        else:
            output += "[-] No vulnerabilities found\n\n"

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
            output += f"Evidence:\n"
            for evidence in vuln.details.split("; "):
                output += f"    - {evidence}\n"
            output += "\n"

        return output
