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

from ..core.result_aggregator import ScanResult, VectorResult, ResultAggregator
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
            "║          AASFA Scanner v4.0 - Feasibility Assessment      ║\n"
            "║              Complete Attack Surface Analysis              ║\n"
            "║                                                               ║\n"
            "║ Scanner performs feasibility assessment only and does not    ║\n"
            "║ exploit vulnerabilities. Remote analysis only, no USB/ADB.   ║\n"
            "╚═══════════════════════════════════════════════════════════════╝{_c('RESET')}\n"
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
        """Форматирование итоговой сводки - MSF style v4.0"""
        summary = aggregator.get_summary()
        
        # Separate by layers
        layer1_vectors = []    # Original Network Vectors (1-550+)
        layer2_vectors = []    # Multifactor Vectors (1001-1030)
        layer3_vectors = []    # Side-Channel Vectors (101-200)
        
        for vuln in aggregator.get_vulnerabilities():
            if isinstance(vuln, VectorResult):
                if 1001 <= vuln.vector_id <= 1030:
                    layer2_vectors.append(vuln)
                elif 101 <= vuln.vector_id <= 200:
                    layer3_vectors.append(vuln)
                else:
                    layer1_vectors.append(vuln)
            else:
                layer1_vectors.append(vuln)

        # Sort by layer and severity
        layer1_vectors.sort(key=lambda v: (v.severity, v.vector_id))
        layer2_vectors.sort(key=lambda v: (v.severity, v.vector_id))
        layer3_vectors.sort(key=lambda v: (v.severity, v.vector_id))

        risk_score = aggregator.get_risk_score()
        risk_level = "LOW"
        if risk_score >= 75:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"

        output = "\n" + "=" * 70 + "\n"
        output += " " * 20 + "FEASIBILITY ASSESSMENT REPORT\n"
        output += "=" * 70 + "\n\n"

        output += f"[*] Target: {summary.get('target', 'Unknown')}\n"
        output += f"[*] Scan Duration: {summary['duration_seconds']:.2f} seconds\n"
        output += f"[*] Layers: Network ({len(layer1_vectors)}) + Multifactor ({len(layer2_vectors)}) + Side-Channel ({len(layer3_vectors)})\n"
        output += f"[*] Total Vectors: {summary['total_checks']}\n\n"

        output += f"[*] Vulnerabilities Found: {summary['vulnerabilities_found']} "
        
        # Count by severity
        all_vulns = layer1_vectors + layer2_vectors + layer3_vectors
        critical_count = sum(1 for v in all_vulns if v.severity == 'CRITICAL')
        high_count = sum(1 for v in all_vulns if v.severity == 'HIGH')
        medium_count = sum(1 for v in all_vulns if v.severity == 'MEDIUM')
        low_count = sum(1 for v in all_vulns if v.severity == 'LOW')
        
        if critical_count + high_count + medium_count + low_count > 0:
            output += f"({critical_count} CRITICAL, {high_count} HIGH, {medium_count} MEDIUM)"
        output += "\n\n"

        # Layer 2: Multifactor Vectors
        if layer2_vectors:
            output += "=" * 70 + "\n"
            output += " LAYER 2: MULTIFACTOR CRYPTOGRAPHIC VECTORS \n"
            output += "=" * 70 + "\n\n"
            
            for vuln in layer2_vectors:
                output += f"[+] {vuln.vector_id:03d}. {vuln.vector_name} [{vuln.severity}] ({vuln.confidence:.0f}% confidence)\n"
                output += vuln.format_details() + "\n"

        # Layer 3: Side-Channel Vectors  
        if layer3_vectors:
            output += "=" * 70 + "\n"
            output += " LAYER 3: SIDE-CHANNEL BEHAVIORAL VECTORS \n"
            output += "=" * 70 + "\n\n"
            
            for vuln in layer3_vectors:
                output += f"[+] {vuln.vector_id:03d}. {vuln.vector_name} [{vuln.severity}] ({vuln.confidence:.0f}% confidence)\n"
                output += vuln.format_details() + "\n"

        # Layer 1: Original Network Vectors (legacy)
        if layer1_vectors:
            output += "=" * 70 + "\n"
            output += " LAYER 1: NETWORK VECTORS \n"
            output += "=" * 70 + "\n\n"
            
            for vuln in layer1_vectors:
                if isinstance(vuln, VectorResult):
                    output += f"[+] {vuln.vector_id:03d}. {vuln.vector_name} [{vuln.severity}] ({vuln.confidence:.0f}% confidence)\n"
                    output += vuln.format_details() + "\n"
                else:
                    output += f"[+] VECTOR_{vuln.vector_id:03d}: {vuln.vector_name} [{vuln.severity}]\n"
                    output += f"    {vuln.details}\n\n"

        # Remediation section
        output += "=" * 70 + "\n"
        output += " REMEDIATION & NOTES \n"
        output += "=" * 70 + "\n\n"
        
        output += "[!] Note: This is FEASIBILITY ASSESSMENT only\n"
        output += "[!] No vulnerabilities were exploited\n"
        output += "[!] Assessment identifies attack surface, not vulnerabilities\n"
        output += "[!] Results are for authorized testing only\n\n"

        output += f"[*] Risk Score: {risk_score}/100 [{risk_level}]\n\n"
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
            if isinstance(vuln, VectorResult):
                # Multifactor vulnerability format
                output += f"[{vuln.severity}] VECTOR_{vuln.vector_id:03d}: {vuln.vector_name}\n"
                output += f"Confidence: {vuln.confidence:.1f}% ({vuln.checks_passed}/{vuln.checks_total} checks passed)\n"
                output += f"Evidence:\n"
                output += vuln.format_details() + "\n\n"
            else:
                # Legacy vulnerability format
                output += f"[{vuln.severity}] VECTOR_{vuln.vector_id:03d}: {vuln.vector_name}\n"
                output += f"Evidence:\n"
                for evidence in vuln.details.split("; "):
                    output += f"    - {evidence}\n"
                output += "\n"

        return output