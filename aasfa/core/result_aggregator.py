"""
Result Aggregator - агрегация и анализ результатов сканирования
"""
from typing import Dict, List, Any
from datetime import datetime
from collections import defaultdict


class ScanResult:
    """Результат одной проверки"""
    
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
        self.start_time = datetime.now()
        self.end_time = None
        self.device_info = {}
    
    def add_result(self, result: ScanResult):
        """Добавление результата"""
        self.results.append(result)
    
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
        return sum(1 for r in self.results if r.vulnerable)
    
    def get_severity_counts(self) -> Dict[str, int]:
        """Подсчет уязвимостей по severity"""
        counts = defaultdict(int)
        for result in self.results:
            if result.vulnerable:
                counts[result.severity] += 1
        return dict(counts)
    
    def get_vulnerabilities(self) -> List[ScanResult]:
        """Получение всех уязвимостей"""
        return [r for r in self.results if r.vulnerable]
    
    def get_vulnerabilities_by_severity(self, severity: str) -> List[ScanResult]:
        """Получение уязвимостей по severity"""
        return [r for r in self.results if r.vulnerable and r.severity == severity]
    
    def get_critical_vulnerabilities(self) -> List[ScanResult]:
        """Получение критических уязвимостей"""
        return self.get_vulnerabilities_by_severity("CRITICAL")
    
    def get_high_vulnerabilities(self) -> List[ScanResult]:
        """Получение высоких уязвимостей"""
        return self.get_vulnerabilities_by_severity("HIGH")
    
    def get_summary(self) -> Dict[str, Any]:
        """Сводка по результатам"""
        severity_counts = self.get_severity_counts()
        
        return {
            "total_checks": len(self.results),
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
