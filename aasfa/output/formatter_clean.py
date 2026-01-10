"""
Clean Output Formatter - Plain text without ANSI codes or emojis
New implementation for AASFA v5.0
"""

from typing import List
from datetime import datetime

from ..core.result_aggregator import ResultAggregator


class CleanTextFormatter:
    """Clean text formatter without special characters"""

    @staticmethod
    def format_header() -> str:
        """Format clean header without ANSI codes"""
        return """====================================================================
                    AASFA SCANNER v5.0
         Universal Security Assessment & Analysis System
====================================================================
WARNING: This tool performs security assessment only.
         No actual exploitation is performed.
         For authorized testing purposes only.
====================================================================

"""

    @staticmethod
    def format_device_identification(device_info: dict) -> str:
        """Format device identification results"""
        if not device_info:
            return "Device information not available\n"
        
        output = "\n"
        output += "====================================================================\n"
        output += "                    DEVICE IDENTIFICATION RESULTS\n"
        output += "====================================================================\n\n"
        
        output += f"Target IP:        {device_info.get('ip_address', 'Unknown')}\n"
        output += f"Device Type:      {device_info.get('device_type', 'Unknown')}\n"
        output += f"Manufacturer:     {device_info.get('manufacturer', 'Unknown')}\n"
        output += f"Model:            {device_info.get('model', 'Unknown')}\n"
        output += f"Operating System: {device_info.get('os_name', 'Unknown')}\n"
        output += f"OS Version:       {device_info.get('os_version', 'Unknown')}\n"
        output += f"Open Ports:       {device_info.get('open_ports', 0)}\n"
        output += f"Vulnerable:       {device_info.get('vulnerable_status', 'Unknown')}\n"
        
        output += "\n====================================================================\n"
        return output

    @staticmethod
    def format_scan_context(target: str, mode: str, total_checks: int) -> str:
        """Format scan context information"""
        return f"""
Scan Configuration
====================================================================
Target:        {target}
Mode:          {mode}
Total Vectors: {total_checks}
Timestamp:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Starting scan...

"""

    @staticmethod
    def format_result_line(vector_id: int, vector_name: str, *, status: str, severity: str = None) -> str:
        """Format a single result line with plain text symbols"""
        symbol = f"[{status}]"
        if severity:
            return f"{symbol} VECTOR_{vector_id:03d}: {vector_name} [{severity}]"
        return f"{symbol} VECTOR_{vector_id:03d}: {vector_name}"

    @staticmethod
    def format_summary(aggregator: ResultAggregator, scan_duration: float) -> str:
        """Format comprehensive scan summary"""
        summary = aggregator.get_summary()
        severity_counts = aggregator.get_severity_counts()
        
        # Calculate risk level
        risk_score = aggregator.get_risk_score()
        if risk_score >= 75:
            risk_level = "КРИТИЧНЫЙ"
        elif risk_score >= 50:
            risk_level = "ВЫСОКИЙ"
        elif risk_score >= 25:
            risk_level = "СРЕДНИЙ"
        elif risk_score >= 10:
            risk_level = "НИЗКИЙ"
        else:
            risk_level = "МИНИМАЛЬНЫЙ"
        
        output = "\n"
        output += "====================================================================\n"
        output += "                    ИТОГИ СКАНИРОВАНИЯ\n"
        output += "====================================================================\n\n"
        
        # Device information
        if aggregator.device_info:
            output += "Целевое устройство:\n"
            output += f"  IP:     {aggregator.device_info.get('ip_address', 'Unknown')}\n"
            output += f"  Тип:    {aggregator.device_info.get('device_type', 'Unknown')}\n"
            output += f"  Модель: {aggregator.device_info.get('model', 'Unknown')}\n"
            output += f"  ОС:     {aggregator.device_info.get('os_name', 'Unknown')}"
            if aggregator.device_info.get('os_version'):
                output += f" {aggregator.device_info['os_version']}"
            output += "\n\n"
        
        # Scan statistics
        minutes = int(scan_duration // 60)
        seconds = int(scan_duration % 60)
        
        output += "Статистика сканирования:\n"
        output += f"  Всего проверено векторов: {summary.get('total_checks', 0)}\n"
        output += f"  Найдено уязвимостей: {summary.get('vulnerabilities_found', 0)}\n"
        output += f"  - CRITICAL: {severity_counts.get('CRITICAL', 0)}\n"
        output += f"  - HIGH:     {severity_counts.get('HIGH', 0)}\n"
        output += f"  - MEDIUM:   {severity_counts.get('MEDIUM', 0)}\n"
        output += f"  - LOW:      {severity_counts.get('LOW', 0)}\n"
        output += f"  - INFO:     {severity_counts.get('INFO', 0)}\n\n"
        
        output += f"Время сканирования: {minutes} минут {seconds} секунд\n"
        output += f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        output += f"Общий риск: {risk_level} ({risk_score}/100)\n\n"
        
        vulnerabilities = aggregator.get_vulnerabilities()
        if vulnerabilities:
            output += "Найденные уязвимости:\n"
            output += "====================================================================\n"
            for vuln in vulnerabilities:
                status = "НАЙДЕНА" if vuln.vulnerable else "НЕ НАЙДЕНА"
                output += f"  VECTOR_{vuln.vector_id:03d}: {vuln.vector_name}\n"
                output += f"    Severity: {vuln.severity} | Status: {status}\n"
            output += "\n"
        else:
            output += "Уязвимости не найдены.\n\n"
        
        output += "====================================================================\n\n"
        
        # Remediation recommendations
        output += "РЕКОМЕНДАЦИИ ПО УСТРАНЕНИЮ:\n"
        output += "====================================================================\n\n"
        
        if severity_counts.get('CRITICAL', 0) > 0:
            output += "КРИТИЧЕСКИЕ ДЕЙСТВИЯ (приоритет 1):\n"
            output += "  - Немедленно отключите устройство от сети\n"
            output += "  - Измените все пароли и ключи доступа\n"
            output += "  - Проведите полный аудит безопасности\n"
            output += "  - Примените критические патчи безопасности\n\n"
        
        if severity_counts.get('HIGH', 0) > 0:
            output += "ВАЖНЫЕ ДЕЙСТВИЯ (приоритет 2):\n"
            output += "  - Обновите все устаревшие компоненты\n"
            output += "  - Включите многофакторную аутентификацию\n"
            output += "  - Закройте неиспользуемые порты и сервисы\n"
            output += "  - Настройте правильное шифрование\n\n"
        
        if severity_counts.get('MEDIUM', 0) > 0:
            output += "РЕКОМЕНДУЕМЫЕ ДЕЙСТВИЯ (приоритет 3):\n"
            output += "  - Проведите регулярное сканирование безопасности\n"
            output += "  - Мониторьте логи на предозрительную активность\n"
            output += "  - Ограничьте доступ по принципу минимальных привилегий\n"
            output += "  - Обучите персонал безопасности\n\n"
        
        if summary.get('vulnerabilities_found', 0) == 0:
            output += "Отлично! Критических уязвимостей не обнаружено.\n"
            output += "Рекомендуется регулярное сканирование для поддержания безопасности.\n\n"
        
        output += "====================================================================\n\n"
        
        # Legal disclaimer
        output += "ВАЖНОЕ ПРЕДУПРЕЖДЕНИЕ:\n"
        output += "====================================================================\n\n"
        output += "Данный инструмент предназначен ТОЛЬКО для авторизованного\n"
        output += "тестирования безопасности. Незаконное использование может\n"
        output += "преследоваться по закону. Сканирование не эксплуатирует\n"
        output += "найденные уязвимости, а только определяет их наличие.\n\n"
        
        output += "====================================================================\n"
        
        return output

    @staticmethod
    def format_vulnerability_details(vulnerabilities: List) -> str:
        """Format detailed vulnerability information"""
        if not vulnerabilities:
            return "\nNo vulnerabilities to display.\n"
        
        output = "\n"
        output += "====================================================================\n"
        output += "                    DETAILED VULNERABILITY REPORT\n"
        output += "====================================================================\n\n"
        
        for vuln in vulnerabilities:
            output += f"ID: VECTOR_{vuln.vector_id:03d}\n"
            output += f"Name: {vuln.vector_name}\n"
            output += f"Severity: {vuln.severity}\n"
            output += f"Vulnerable: {'YES' if vuln.vulnerable else 'NO'}\n"
            
            if hasattr(vuln, 'confidence'):
                output += f"Confidence: {vuln.confidence:.1f}%\n"
            
            if hasattr(vuln, 'details') and vuln.details:
                output += f"Details:\n"
                if isinstance(vuln.details, list):
                    for detail in vuln.details:
                        output += f"  - {detail}\n"
                else:
                    output += f"  {vuln.details}\n"
            
            output += "\n"
        
        output += "====================================================================\n"
        return output


# Export as OutputFormatter for compatibility
OutputFormatter = CleanTextFormatter