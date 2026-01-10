"""Enhanced result formatter with Russian explanations"""

from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path

from ..cli.language import Language
from ..cli.colors import Colors, use_colors, colorize, bold, yellow, red
from ..core.result_aggregator import ResultAggregator, VectorResult, ScanResult


class ResultFormatter:
    """Format scan results in Russian with detailed explanations"""

    def __init__(self, device_type: str):
        self.device_type = device_type
        self.vector_descriptions = self._load_vector_descriptions()

    def format_results(
        self,
        aggregator: ResultAggregator,
        ip: str,
        start_time: datetime,
        end_time: datetime,
        mode: str
    ) -> str:
        """Format complete scan results with Russian explanations"""
        output = self._format_header(ip, start_time, end_time)
        output += self._format_summary(aggregator, start_time, end_time)
        output += self._format_vulnerabilities(aggregator, mode)
        output += self._format_recommendations(aggregator)

        return output

    def _format_header(self, ip: str, start_time: datetime, end_time: datetime) -> str:
        """Format report header"""
        date_str = end_time.strftime("%Y-%m-%d %H:%M")

        if use_colors():
            print(f"{Colors.BOLD}{Colors.CYAN}")
        header = f"\n╔" + "═" * 64 + "╗\n"
        header += "║" + " " * 64 + "║\n"
        header += f"║{Language.SCAN_RESULTS_TITLE.center(64)}║\n"
        header += f"║{f'{ip} - {Language.DEVICE_TYPES.get(self.device_type, self.device_type)}'.center(64)}║\n"
        header += f"║{f'Дата: {date_str}'.center(64)}║\n"
        header += "║" + " " * 64 + "║\n"
        header += "╚" + "═" * 64 + "╝"
        if use_colors():
            header += Colors.RESET

        return header + "\n"

    def _format_summary(
        self,
        aggregator: ResultAggregator,
        start_time: datetime,
        end_time: datetime
    ) -> str:
        """Format scan summary"""
        vulnerabilities = aggregator.get_vulnerabilities()
        severity_counts = aggregator.get_severity_counts()

        total_vulns = len(vulnerabilities)
        critical = severity_counts.get('CRITICAL', 0)
        high = severity_counts.get('HIGH', 0)
        medium = severity_counts.get('MEDIUM', 0)
        low = severity_counts.get('LOW', 0)

        duration = (end_time - start_time).total_seconds()
        minutes = int(duration // 60)
        seconds = int(duration % 60)

        risk_score = aggregator.get_risk_score()
        status = self._get_status_label(risk_score)

        output = f"\n{bold(Language.SUMMARY_STATS)}\n"
        output += f"  {Language.SCAN_TIME} {minutes} минут {seconds} секунд\n"
        output += f"  {Language.VECTORS_CHECKED} 850+ уязвимостей\n"
        output += f"  {Language.FOUND_ISSUES} {total_vulns} проблемы "

        if total_vulns > 0:
            parts = []
            if critical > 0:
                parts.append(f"{critical} {Language.SEVERITY_CRITICAL}")
            if high > 0:
                parts.append(f"{high} ВЫСОКИХ")
            if medium > 0:
                parts.append(f"{medium} СРЕДНИХ")
            if low > 0:
                parts.append(f"{low} НИЗКИХ")
            output += f"({', '.join(parts)})"

        output += "\n"
        output += f"  {Language.STATUS_INFO} {status}\n"

        return output + "\n" + "═" * 70 + "\n"

    def _format_vulnerabilities(self, aggregator: ResultAggregator, mode: str) -> str:
        """Format detailed vulnerability explanations"""
        vulnerabilities = aggregator.get_vulnerabilities()

        if not vulnerabilities:
            return yellow("\n✅ Уязвимостей не найдено!\n")

        output = ""

        # Group by severity
        by_severity = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': []
        }

        for vuln in vulnerabilities:
            severity = vuln.severity if isinstance(vuln, VectorResult) else vuln.severity
            if severity in by_severity:
                by_severity[severity].append(vuln)

        # Output by severity (critical first)
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            vulns = by_severity[severity]
            if not vulns:
                continue

            for vuln in vulns:
                output += self._format_single_vulnerability(vuln, severity, mode)
                output += "\n"

        return output

    def _format_single_vulnerability(
        self,
        vuln: ScanResult,
        severity: str,
        mode: str
    ) -> str:
        """Format a single vulnerability with detailed explanation"""
        vector_id = vuln.vector_id if isinstance(vuln, VectorResult) else vuln.vector_id
        vector_name = vuln.vector_name if isinstance(vuln, VectorResult) else vuln.vector_name

        # Get description from database
        description = self.vector_descriptions.get(vector_id, {})

        output = f"{bold(f'[{Language.get_severity_label(severity)}]')} Vector {vector_id} - {vector_name}\n\n"

        if mode == "learning" or description:
            output += self._format_explanation_sections(description, vector_id)
        else:
            # Brief format
            details = vuln.details if isinstance(vuln, VectorResult) else vuln.details
            output += f"    {details}\n"

        return output

    def _format_explanation_sections(self, description: dict, vector_id: int) -> str:
        """Format explanation sections in learning mode"""
        output = ""

        sections = [
            ("what_is_it", Language.WHAT_IS_IT),
            ("where_is_it", Language.WHERE_IS_IT),
            ("what_can_happen", Language.WHAT_CAN_HAPPEN),
            ("how_to_fix", Language.HOW_TO_FIX),
        ]

        for key, title in sections:
            content = description.get(key)
            if content:
                output += f"    {title}\n"
                output += f"    └─ {content}\n"
                output += "\n"

        # Risk level
        risk_level = description.get("risk_level", "MEDIUM")
        risk_label = self._get_risk_label(risk_level)
        output += f"    {Language.RISK_LEVEL} {risk_label}\n"

        return output

    def _get_risk_label(self, risk_level: str) -> str:
        """Get Russian label for risk level"""
        labels = {
            "CRITICAL": Language.CRITICAL_RISK,
            "HIGH": Language.HIGH_RISK,
            "MEDIUM": Language.MEDIUM_RISK,
            "LOW": Language.LOW_RISK
        }
        return labels.get(risk_level, risk_level)

    def _format_recommendations(self, aggregator: ResultAggregator) -> str:
        """Format general recommendations"""
        severity_counts = aggregator.get_severity_counts()
        critical = severity_counts.get('CRITICAL', 0)
        high = severity_counts.get('HIGH', 0)

        if critical == 0 and high == 0:
            return ""

        output = f"\n{bold(Language.GENERAL_RECOMMENDATIONS)}\n"

        if critical > 0 or high > 0:
            output += f"\n{yellow(Language.ATTENTION)}\n"
            output += f"{Language.IMMEDIATELY}\n"
            output += "  └─ Отключи Telnet и FTP\n"
            output += "  └─ Отключи любой удалённый доступ\n"
            output += "  └─ Не используй это устройство для чувствительных данных\n"

            output += f"\n{Language.SOON}\n"
            output += "  └─ Попробуй найти обновление Android\n"
            output += "  └─ Если не работает - ищи кастомную ROM\n"
            output += "  └─ Установи VPN для защиты в интернете\n"

            output += f"\n{Language.IDEALLY}\n"
            output += "  └─ Замени на новое устройство (Android 10+)\n"

        return output + "\n" + "═" * 70 + "\n"

    def _get_status_label(self, risk_score: int) -> str:
        """Get status label based on risk score"""
        if risk_score >= 75:
            return Language.STATUS_HIGH_RISK
        elif risk_score >= 50:
            return "ВЫСОКИЙ РИСК"
        elif risk_score >= 25:
            return "СРЕДНИЙ РИСК"
        else:
            return "ОТЛИЧНО"

    def _load_vector_descriptions(self) -> Dict[int, Dict[str, str]]:
        """Load Russian vector descriptions from JSON file"""
        descriptions = {}
        description_file = Path(__file__).parent.parent / "vectors" / "descriptions" / "android_desc.json"

        if description_file.exists():
            try:
                import json
                with open(description_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Convert string keys to int
                    descriptions = {int(k): v for k, v in data.items()}
            except Exception as e:
                pass

        # If no descriptions loaded, return empty dict
        return descriptions
