"""
Timing and Statistical Analysis for Side-Channel Assessment
Phase 1 Infrastructure for AASFA Scanner v4.0
"""
import time
import statistics
import requests
from dataclasses import dataclass
from typing import List, Tuple, Any, Optional
from ..utils.logger import get_logger

_timing_warning_shown = False  # Track if warning was already shown


@dataclass
class TimingStats:
    """Статистика timing samples для side-channel анализа"""
    mean: float
    stdev: float
    min: float
    max: float
    anomalies: List[Tuple[int, float, float]]  # (index, value, z_score)
    variance_coefficient: float
    sample_count: int
    endpoint: str = ""

    def to_dict(self) -> dict:
        """Конвертация в словарь для сериализации"""
        return {
            "mean": self.mean,
            "stdev": self.stdev,
            "min": self.min,
            "max": self.max,
            "variance_coefficient": self.variance_coefficient,
            "sample_count": self.sample_count,
            "endpoint": self.endpoint,
            "anomaly_count": len(self.anomalies)
        }


def collect_timing_samples(target: str, endpoint: str, samples: int = 30, timeout: int = 10) -> TimingStats:
    """Собрать timing samples и вернуть статистику"""
    logger = get_logger()
    rtts = []
    variances = []
    
    logger.debug(f"Collecting {samples} timing samples for {target}{endpoint}")
    
    global _timing_warning_shown
    
    for i in range(samples):
        try:
            t_start = time.perf_counter()
            response = requests.get(f"https://{target}{endpoint}", timeout=timeout, verify=False)
            t_end = time.perf_counter()
            rtt = (t_end - t_start) * 1000  # ms
            rtts.append(rtt)
            
        except Exception as e:
            logger.debug(f"Failed to collect sample {i+1}: {e}")
            continue
    
    if len(rtts) < 5 and len(rtts) > 0:
        if not _timing_warning_shown:
            logger.warning(f"Only {len(rtts)} valid samples collected, analysis may be unreliable")
            _timing_warning_shown = True
    elif len(rtts) == 0:
        logger.debug("No valid timing samples collected (target not responding)")
    
    # Вычислить статистику
    if not rtts:
        raise ValueError("No valid timing samples collected")
        
    mean = statistics.mean(rtts)
    stdev = statistics.stdev(rtts) if len(rtts) > 1 else 0.0
    
    # Z-score анализ аномалий
    anomalies = []
    if stdev > 0:
        for i, rtt in enumerate(rtts):
            z_score = (rtt - mean) / stdev
            if abs(z_score) > 2.5:  # аномалия если > 2.5σ
                anomalies.append((i, rtt, z_score))
    
    return TimingStats(
        mean=mean,
        stdev=stdev,
        min=min(rtts),
        max=max(rtts),
        anomalies=anomalies,
        variance_coefficient=stdev / mean if mean > 0 else 0,
        sample_count=len(rtts),
        endpoint=endpoint
    )


def analyze_timing_correlation(stats_list: List[TimingStats]) -> dict:
    """Анализ корреляции между разными endpoints"""
    if len(stats_list) < 2:
        return {"correlation": "insufficient_data"}
    
    # Извлекаем mean values
    means = [stats.mean for stats in stats_list]
    stdevs = [stats.stdev for stats in stats_list]
    
    # Простой анализ корреляции
    correlation_analysis = {
        "endpoints_analyzed": len(stats_list),
        "mean_range": {"min": min(means), "max": max(means)},
        "stdev_range": {"min": min(stdevs), "max": max(stdevs)},
        "high_variance_endpoints": [s.endpoint for s in stats_list if s.variance_coefficient > 0.3],
        "anomaly_prone_endpoints": [s.endpoint for s in stats_list if len(s.anomalies) > 2],
    }
    
    return correlation_analysis


def detect_timing_side_channel(stats: TimingStats) -> dict:
    """Определение потенциальных side-channel уязвимостей на основе timing"""
    indicators = []
    
    # Высокая дисперсия может указывать на state machine
    if stats.variance_coefficient > 0.3:
        indicators.append({
            "type": "high_variance",
            "severity": "HIGH" if stats.variance_coefficient > 0.5 else "MEDIUM",
            "description": f"Response variance CV={stats.variance_coefficient:.2%} (abnormal, expected <15%)",
            "confidence": min(0.8, stats.variance_coefficient)
        })
    
    # Аномалии могут указывать на timing-based attacks
    if len(stats.anomalies) > 3:
        indicators.append({
            "type": "timing_anomalies",
            "severity": "MEDIUM",
            "description": f"Multiple timing anomalies detected: {len(stats.anomalies)} outliers",
            "confidence": min(0.7, len(stats.anomalies) * 0.1)
        })
    
    # Разность между min и max может указывать на conditional timing
    timing_range = stats.max - stats.min
    if timing_range > stats.mean * 0.5:
        indicators.append({
            "type": "conditional_timing",
            "severity": "MEDIUM",
            "description": f"Timing range {timing_range:.1f}ms suggests conditional logic",
            "confidence": min(0.6, timing_range / (stats.mean * 2))
        })
    
    return {
        "indicators": indicators,
        "overall_confidence": max([i["confidence"] for i in indicators]) if indicators else 0.0,
        "is_suspicious": len(indicators) > 0
    }