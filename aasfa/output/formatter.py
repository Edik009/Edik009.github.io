"""
Output formatter for Metasploit-style console output
"""
from typing import List, Dict, Any
from ..core.result_aggregator import ScanResult, ResultAggregator
from ..utils.config import COLORS


class OutputFormatter:
    """Форматтер вывода в стиле Metasploit"""
    
    @staticmethod
    def format_header(target: str) -> str:
        """Форматирование заголовка"""
        return f"""
{COLORS['BOLD']}╔══════════════════════════════════════════════════════════════╗
║         AASFA Scanner - Android Attack Surface Scanner       ║
║              Pre-Attack Assessment Tool v1.0                 ║
╚══════════════════════════════════════════════════════════════╝{COLORS['RESET']}

[*] Target: {target}
"""
    
    @staticmethod
    def format_vulnerability(result: ScanResult) -> str:
        """Форматирование уязвимости"""
        color = COLORS.get(result.severity, COLORS['INFO'])
        symbol = {
            "CRITICAL": "[!]",
            "HIGH": "[+]",
            "MEDIUM": "[*]",
            "LOW": "[-]",
        }.get(result.severity, "[*]")
        
        return f"{color}{symbol} VECTOR_{result.vector_id:03d}: {result.vector_name} [{result.severity}]{COLORS['RESET']}\n    {result.details}"
    
    @staticmethod
    def format_summary(aggregator: ResultAggregator) -> str:
        """Форматирование итоговой сводки"""
        summary = aggregator.get_summary()
        severity_counts = summary['severity_breakdown']
        
        output = f"\n{COLORS['BOLD']}{'='*70}\n"
        output += f"                      SCAN SUMMARY                           \n"
        output += f"{'='*70}{COLORS['RESET']}\n\n"
        
        output += f"Total checks performed: {summary['total_checks']}\n"
        output += f"Scan duration: {summary['duration_seconds']:.2f} seconds\n\n"
        
        output += f"{COLORS['BOLD']}Vulnerabilities found:{COLORS['RESET']}\n"
        
        if severity_counts.get('CRITICAL', 0) > 0:
            output += f"  {COLORS['CRITICAL']}CRITICAL: {severity_counts['CRITICAL']}{COLORS['RESET']}\n"
        if severity_counts.get('HIGH', 0) > 0:
            output += f"  {COLORS['HIGH']}HIGH: {severity_counts['HIGH']}{COLORS['RESET']}\n"
        if severity_counts.get('MEDIUM', 0) > 0:
            output += f"  {COLORS['MEDIUM']}MEDIUM: {severity_counts['MEDIUM']}{COLORS['RESET']}\n"
        if severity_counts.get('LOW', 0) > 0:
            output += f"  {COLORS['LOW']}LOW: {severity_counts['LOW']}{COLORS['RESET']}\n"
        
        if summary['vulnerabilities_found'] == 0:
            output += f"  {COLORS['LOW']}No vulnerabilities found{COLORS['RESET']}\n"
        
        risk_score = aggregator.get_risk_score()
        risk_level = "LOW"
        if risk_score >= 75:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        
        risk_color = COLORS.get(risk_level, COLORS['INFO'])
        output += f"\n{COLORS['BOLD']}Risk Score: {risk_color}{risk_score}/100 [{risk_level}]{COLORS['RESET']}\n"
        
        if summary['device_info']:
            output += f"\n{COLORS['BOLD']}Device Information:{COLORS['RESET']}\n"
            for key, value in summary['device_info'].items():
                output += f"  {key}: {value}\n"
        
        output += f"\n{COLORS['BOLD']}{'='*70}{COLORS['RESET']}\n"
        
        return output
    
    @staticmethod
    def format_vulnerability_details(vulnerabilities: List[ScanResult]) -> str:
        """Детальное форматирование уязвимостей"""
        if not vulnerabilities:
            return "\nNo vulnerabilities to display.\n"
        
        output = f"\n{COLORS['BOLD']}{'='*70}\n"
        output += f"                  VULNERABILITY DETAILS                      \n"
        output += f"{'='*70}{COLORS['RESET']}\n\n"
        
        for vuln in vulnerabilities:
            output += OutputFormatter.format_vulnerability(vuln) + "\n\n"
        
        return output
