"""
Result Aggregator - агрегация и анализ результатов сканирования
"""
from typing import Dict, List, Any
from datetime import datetime
from collections import defaultdict


class VectorResult:
    """Результат многофакторной проверки вектора"""
    
    def __init__(self, vector_id: int, vector_name: str, checks_passed: int, 
                 checks_total: int, confidence: float, vulnerable: bool,
                 details: List[str], severity: str = "INFO", timestamp: str = None):
        self.vector_id = vector_id
        self.vector_name = vector_name
        self.checks_passed = checks_passed
        self.checks_total = checks_total
        self.confidence = confidence
        self.vulnerable = vulnerable
        self.details = details
        self.severity = severity
        self.timestamp = timestamp or datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        return {
            "vector_id": self.vector_id,
            "vector_name": self.vector_name,
            "checks_passed": self.checks_passed,
            "checks_total": self.checks_total,
            "confidence": f"{self.confidence:.1f}%",
            "vulnerable": self.vulnerable,
            "details": self.details,
            "severity": self.severity,
            "timestamp": self.timestamp,
        }

    def format_details(self) -> str:
        """Форматирование деталей для вывода"""
        if not self.details:
            return "No details available"
        
        lines = []
        for detail in self.details:
            if detail.startswith("✓"):
                lines.append(f"    {detail}")
            elif detail.startswith("✗"):
                lines.append(f"    {detail}")
            else:
                lines.append(f"    {detail}")
        
        return "\n".join(lines)


class ScanResult:
    """Результат одной проверки (legacy для обратной совместимости)"""
    
    def __init__(self, vector_id: int, vector_name: str, vulnerable: bool, 
                 details: str, severity: str = "INFO", timestamp: str = None):
        self.vector_id = vector_id
        self.vector_name = vector_name
        self.vulnerable = vulnerable
        self.details = details
        self.severity = severity
        self.timestamp = timestamp or datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        return {
            "vector_id": self.vector_id,
            "vector_name": self.vector_name,
            "vulnerable": self.vulnerable,
            "details": self.details,
            "severity": self.severity,
            "timestamp": self.timestamp,
        }


class ResultAggregator:
    """Агрегатор результатов сканирования"""
    
    def __init__(self):
        self.results: List[ScanResult] = []
        self.vector_results: List[VectorResult] = []  # NEW: Для многофакторных векторов
        self.all_checks_performed: List[ScanResult] = []
        self.start_time = datetime.now()
        self.end_time = None
        self.device_info = {}
    
    def add_result(self, result: ScanResult):
        """Добавление результата"""
        self.results.append(result)
        self.all_checks_performed.append(result)
    
    def add_vector_result(self, result: VectorResult):
        """Добавление результата многофакторной проверки"""
        self.vector_results.append(result)
        # Для обратной совместимости добавляем как ScanResult
        scan_result = ScanResult(
            result.vector_id, 
            result.vector_name, 
            result.vulnerable,
            f"Confidence: {result.confidence:.1f}% ({result.checks_passed}/{result.checks_total} checks)",
            result.severity
        )
        self.all_checks_performed.append(scan_result)
    
    def add_check_performed(self, result: ScanResult):
        """Добавление информации о выполненной проверке (включая неуязвимые)"""
        self.all_checks_performed.append(result)
    
    def add_device_info(self, info: Dict[str, Any]):
        """Добавление информации об устройстве"""
        self.device_info.update(info)
    
    def finish(self):
        """Завершение сканирования"""
        self.end_time = datetime.now()
    
    def get_duration(self) -> float:
        """Получение длительности сканирования"""
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()
    
    def get_vulnerable_count(self) -> int:
        """Количество найденных уязвимостей"""
        count = sum(1 for r in self.results if r.vulnerable)
        count += sum(1 for r in self.vector_results if r.vulnerable)
        return count
    
    def get_severity_counts(self) -> Dict[str, int]:
        """Подсчет уязвимостей по severity"""
        counts = defaultdict(int)
        
        # Legacy results
        for result in self.results:
            if result.vulnerable:
                counts[result.severity] += 1
        
        # New multifactor results
        for result in self.vector_results:
            if result.vulnerable:
                counts[result.severity] += 1
        
        return dict(counts)
    
    def get_vulnerabilities(self) -> List[Any]:
        """Получение всех найденных уязвимостей"""
        vulnerabilities = []
        
        # Legacy vulnerabilities (single check)
        for result in self.results:
            if result.vulnerable:
                vulnerabilities.append(result)
        
        # New multifactor vulnerabilities
        for result in self.vector_results:
            if result.vulnerable:
                vulnerabilities.append(result)
        
        return vulnerabilities

    def get_vulnerabilities_multifactor(self) -> List[VectorResult]:
        """Получение только многофакторных уязвимостей"""
        return [result for result in self.vector_results if result.vulnerable]

    def get_vulnerabilities_by_severity(self, severity: str) -> List[Any]:
        """Получение уязвимостей по severity"""
        vulnerabilities = []
        
        # Legacy vulnerabilities
        for result in self.results:
            if result.vulnerable and result.severity == severity:
                vulnerabilities.append(result)
        
        # New multifactor vulnerabilities
        for result in self.vector_results:
            if result.vulnerable and result.severity == severity:
                vulnerabilities.append(result)
        
        return vulnerabilities

    def get_critical_vulnerabilities(self) -> List[Any]:
        """Получение критических уязвимостей"""
        return self.get_vulnerabilities_by_severity("CRITICAL")
    
    def get_high_vulnerabilities(self) -> List[Any]:
        """Получение высоких уязвимостей"""
        return self.get_vulnerabilities_by_severity("HIGH")
    
    def get_summary(self) -> Dict[str, Any]:
        """Сводка по результатам"""
        severity_counts = self.get_severity_counts()
        
        return {
            "total_checks": len(self.all_checks_performed),
            "vulnerabilities_found": self.get_vulnerable_count(),
            "severity_breakdown": severity_counts,
            "critical": severity_counts.get("CRITICAL", 0),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0),
            "duration_seconds": self.get_duration(),
            "device_info": self.device_info,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Полная конвертация в словарь"""
        return {
            "summary": self.get_summary(),
            "vulnerabilities": [r.to_dict() for r in self.get_vulnerabilities()],
            "all_results": [r.to_dict() for r in self.results],
        }
    
    def get_risk_score(self) -> int:
        """Расчет риск-скора (0-100)"""
        severity_weights = {
            "CRITICAL": 25,
            "HIGH": 10,
            "MEDIUM": 3,
            "LOW": 1,
        }
        
        score = 0
        severity_counts = self.get_severity_counts()
        
        for severity, weight in severity_weights.items():
            count = severity_counts.get(severity, 0)
            score += count * weight
        
        return min(score, 100)
