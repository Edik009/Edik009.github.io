"""
Clean Text Output Formatter - Pure ASCII format without ANSI codes or emojis
"""

import sys
from typing import List, Dict, Any
from datetime import datetime

from ..core.result_aggregator import VectorResult, ResultAggregator


class CleanTextFormatter:
    """Pure ASCII text formatter without any special characters"""
    
    @staticmethod
    def format_header() -> str:
        """Format clean header"""
        return """
====================================================================
                    AASFA SCANNER v5.0
         Universal Security Assessment & Analysis System
====================================================================
WARNING: This tool performs security assessment only.
         No actual exploitation is performed.
         For authorized testing purposes only.
====================================================================

"""
    
    @staticmethod
    def format_device_identification(device_info: Dict[str, Any]) -> str:
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
        output += f"Architecture:     {device_info.get('architecture', 'Unknown')}\n"
        output += f"Kernel Version:   {device_info.get('kernel_version', 'Unknown')}\n"
        output += f"MAC Address:      {device_info.get('mac_address', 'Unknown')}\n"
        output += f"Open Ports:       {device_info.get('open_ports', 0)}\n"
        output += f"Vulnerable:       {device_info.get('vulnerable_status', 'Unknown')}\n"
        
        output += "\n====================================================================\n\n"
        return output
    
    @staticmethod
    def format_scan_start(target: str, mode: str, total_vectors: int) -> str:
        """Format scan start information"""
        return f"""
Starting Security Assessment
====================================================================
Target:           {target}
Scan Mode:        {mode}
Total Vectors:    {total_vectors}
Timestamp:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
====================================================================

"""
    
    @staticmethod
    def format_vector_result(vector_result: VectorResult) -> str:
        """Format a single vector result with detailed information"""
        status = "НАЙДЕНА" if vector_result.vulnerable else "НЕ НАЙДЕНА"
        
        output = "\n"
        output += "====================================================================\n"
        output += f"ID: VECTOR_{vector_result.vector_id:03d}\n"
        output += f"Название: {vector_result.vector_name}\n"
        output += f"Тип: {vector_result.vector_type if hasattr(vector_result, 'vector_type') else 'Общий'}\n"
        output += f"Статус: {status}\n"
        output += f"Severity: {vector_result.severity}\n"
        output += "====================================================================\n\n"
        
        # Description section
        if hasattr(vector_result, 'description') and vector_result.description:
            output += "Описание:\n"
            output += f"{vector_result.description}\n\n"
        
        # What attacker can extract
        if hasattr(vector_result, 'attacker_extraction') and vector_result.attacker_extraction:
            output += "Что может извлечь атакующий:\n"
            output += f"{vector_result.attacker_extraction}\n\n"
        
        # Exploitation path
        if hasattr(vector_result, 'exploitation_path') and vector_result.exploitation_path:
            output += "Путь эксплуатации:\n"
            output += f"{vector_result.exploitation_path}\n\n"
        
        # Remediation
        if hasattr(vector_result, 'remediation') and vector_result.remediation:
            output += "Рекомендация по исправлению:\n"
            output += f"{vector_result.remediation}\n\n"
        
        # Technical details
        if hasattr(vector_result, 'technical_details') and vector_result.technical_details:
            output += "Технические детали:\n"
            output += f"{vector_result.technical_details}\n\n"
        
        # Evidence and checks
        output += f"Confidence: {vector_result.confidence:.1f}% ({vector_result.checks_passed}/{vector_result.checks_total} checks passed)\n\n"
        
        if vector_result.details:
            output += "Evidence:\n"
            for detail in vector_result.details:
                output += f"  - {detail}\n"
            output += "\n"
        
        output += "====================================================================\n"
        return output
    
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
            output += f"  IP:    {aggregator.device_info.get('ip_address', 'Unknown')}\n"
            output += f"  Тип:   {aggregator.device_info.get('device_type', 'Unknown')}\n"
            output += f"  Модель: {aggregator.device_info.get('model', 'Unknown')}\n"
            output += f"  ОС:    {aggregator.device_info.get('os_name', 'Unknown')} {aggregator.device_info.get('os_version', '')}\n\n"
        
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
        
        # Show vulnerabilities found
        vulnerabilities = aggregator.get_vulnerabilities()
        if vulnerabilities:
            output += "Найденные уязвимости:\n"
            output += "====================================================================\n"
            for vuln in vulnerabilities:
                status = "НАЙДЕНА" if (hasattr(vuln, 'vulnerable') and vuln.vulnerable) or (hasattr(vuln, 'vulnerable') and vuln.vulnerable) else "НЕ НАЙДЕНА"
                output += f"  VECTOR_{vuln.vector_id:03d}: {vuln.vector_name} [{vuln.severity}] - {status}\n"
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
            output += "  - Мониторьте логи на предмет подозрительной активности\n"
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
    def format_progress(current: int, total: int, vector_name: str = "") -> str:
        """Format progress bar without special characters"""
        percentage = (current / total) * 100
        filled = int(percentage / 2)
        bar = "[" + "=" * filled + "-" * (50 - filled) + "]"
        
        return f"\rProgress: {bar} {percentage:5.1f}% ({current}/{total}) - {vector_name[:40]:<40}"


# Alias for easier import
OutputFormatter = CleanTextFormatter