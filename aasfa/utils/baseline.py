"""
Baseline Database Manager for AASFA Scanner v4.0
Phase 1 Infrastructure for side-channel analysis
"""
import json
import os
from typing import Dict, Any, Optional, List
from ..utils.logger import get_logger


class BaselineManager:
    """Менеджер baseline database для fingerprinting и comparison"""

    def __init__(self, baseline_path: str = "aasfa/data/baseline.json"):
        self.baseline_path = baseline_path
        self.logger = get_logger()
        self._cache = None
        self._load_baseline()

    def _load_baseline(self):
        """Загрузка baseline database"""
        try:
            if os.path.exists(self.baseline_path):
                with open(self.baseline_path, 'r', encoding='utf-8') as f:
                    self._cache = json.load(f)
                self.logger.debug(f"Loaded baseline database: {self.baseline_path}")
            else:
                self.logger.warning(f"Baseline file not found: {self.baseline_path}")
                self._cache = {"baseline": {}, "patterns": {}}
        except Exception as e:
            self.logger.error(f"Failed to load baseline: {e}")
            self._cache = {"baseline": {}, "patterns": {}}

    def get_device_fingerprint(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Получение fingerprint'а устройства из baseline"""
        if not self._cache:
            return None
        return self._cache.get("baseline", {}).get(device_id)

    def get_all_devices(self) -> List[str]:
        """Получение списка всех известных устройств"""
        if not self._cache:
            return []
        return list(self._cache.get("baseline", {}).keys())

    def match_ja3_signature(self, ja3_signature: str) -> List[str]:
        """Поиск совпадений JA3 сигнатуры в baseline"""
        if not self._cache:
            return []
        
        matches = []
        for device_id, device_data in self._cache.get("baseline", {}).items():
            if device_data.get("ja3") == ja3_signature:
                matches.append(device_id)
        
        return matches

    def match_ja4_signature(self, ja4_signature: str) -> List[str]:
        """Поиск совпадений JA4 сигнатуры в baseline"""
        if not self._cache:
            return []
        
        matches = []
        for device_id, device_data in self._cache.get("baseline", {}).items():
            if device_data.get("ja4") == ja4_signature:
                matches.append(device_id)
        
        return matches

    def match_header_order(self, headers_order: List[str]) -> List[str]:
        """Поиск совпадений порядка HTTP заголовков"""
        if not self._cache:
            return []
        
        matches = []
        for device_id, device_data in self._cache.get("baseline", {}).items():
            if device_data.get("headers_order") == headers_order:
                matches.append(device_id)
        
        return matches

    def compare_timing_pattern(self, timing_stats: Dict[str, Any]) -> Dict[str, Any]:
        """Сравнение timing статистики с baseline паттернами"""
        if not self._cache:
            return {"match": False, "confidence": 0.0}
        
        device_timing_mean = timing_stats.get("mean", 0)
        device_timing_stdev = timing_stats.get("stdev", 0)
        
        best_match = {"device": None, "confidence": 0.0, "details": ""}
        
        for device_id, device_data in self._cache.get("baseline", {}).items():
            baseline_mean = device_data.get("timing_mean_ms", 0)
            baseline_stdev = device_data.get("timing_stdev_ms", 0)
            pattern_type = device_data.get("timing_pattern", "unknown")
            
            # Вычисляем similarity
            mean_diff = abs(device_timing_mean - baseline_mean)
            stdev_diff = abs(device_timing_stdev - baseline_stdev)
            
            # Normalized confidence (0-1)
            mean_similarity = max(0, 1 - (mean_diff / max(baseline_mean, 1)))
            stdev_similarity = max(0, 1 - (stdev_diff / max(baseline_stdev, 1)))
            
            overall_confidence = (mean_similarity + stdev_similarity) / 2
            
            if overall_confidence > best_match["confidence"]:
                best_match = {
                    "device": device_id,
                    "confidence": overall_confidence,
                    "details": f"Mean diff: {mean_diff:.1f}ms, Stdev diff: {stdev_diff:.1f}ms, Pattern: {pattern_type}"
                }
        
        return best_match

    def get_endpoint_config(self, endpoint_name: str) -> Optional[Dict[str, Any]]:
        """Получение конфигурации endpoint'а для анализа"""
        if not self._cache:
            return None
        return self._cache.get("endpoints", {}).get(endpoint_name)

    def get_pattern_info(self, pattern_type: str) -> Optional[Dict[str, Any]]:
        """Получение информации о паттерне"""
        if not self._cache:
            return None
        return self._cache.get("patterns", {}).get(pattern_type)

    def add_device_to_baseline(self, device_id: str, device_data: Dict[str, Any]):
        """Добавление нового устройства в baseline (для будущих обновлений)"""
        if not self._cache:
            self._cache = {"baseline": {}}
        
        if "baseline" not in self._cache:
            self._cache["baseline"] = {}
        
        self._cache["baseline"][device_id] = device_data
        self.logger.info(f"Added device {device_id} to baseline")

    def save_baseline(self):
        """Сохранение baseline database в файл"""
        if self._cache:
            try:
                os.makedirs(os.path.dirname(self.baseline_path), exist_ok=True)
                with open(self.baseline_path, 'w', encoding='utf-8') as f:
                    json.dump(self._cache, f, indent=2, ensure_ascii=False)
                self.logger.debug(f"Saved baseline database: {self.baseline_path}")
            except Exception as e:
                self.logger.error(f"Failed to save baseline: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Получение статистики baseline database"""
        if not self._cache:
            return {"total_devices": 0, "endpoints": 0, "patterns": 0}
        
        return {
            "total_devices": len(self._cache.get("baseline", {})),
            "endpoints": len(self._cache.get("endpoints", {})),
            "patterns": len(self._cache.get("patterns", {})),
            "ja3_devices": len([d for d in self._cache.get("baseline", {}).values() if d.get("ja3")]),
            "ja4_devices": len([d for d in self._cache.get("baseline", {}).values() if d.get("ja4")])
        }


def load_baseline_db(baseline_path: str = "aasfa/data/baseline.json") -> BaselineManager:
    """Удобная функция для загрузки baseline database"""
    return BaselineManager(baseline_path)