"""
Analysis Pipeline - Signal Collection → Normalization → Scoring → Correlation → Decision
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
import statistics


@dataclass
class VectorSignal:
    """Signal collected during analysis"""
    source: str  # network, timing, protocol, behavior
    value: float  # 0-1 normalized
    confidence: float  # 0-1 confidence level
    timestamp: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "source": self.source,
            "value": self.value,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class VectorResult:
    """Result of vector analysis"""
    status: str  # CONFIRMED, NOT_FOUND, INCONCLUSIVE
    confidence: float  # 0-1 overall confidence
    signals: List[VectorSignal]
    evidence: List[str]
    correlation_score: float  # 0-1 correlation between signals

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "status": self.status,
            "confidence": self.confidence,
            "signals": [s.to_dict() for s in self.signals],
            "evidence": self.evidence,
            "correlation_score": self.correlation_score,
        }


class AnalysisPipeline:
    """Analysis pipeline for vector evaluation"""

    def __init__(self):
        self.collectors = []
        self.min_signals = 2  # Each vector needs at least 2 signals

    def add_collector(self, collector):
        """Add a signal collector"""
        self.collectors.append(collector)

    def analyze(self, target: str, vector_config: Dict[str, Any]) -> VectorResult:
        """Run full pipeline for a vector"""
        # Step 1: Signal Collection
        signals = self._collect_signals(target, vector_config)

        if len(signals) < self.min_signals:
            return self._not_found_result("Insufficient signals collected")

        # Step 2: Signal Normalization
        normalized = self._normalize_signals(signals)

        # Step 3: Feature Extraction
        features = self._extract_features(normalized)

        # Step 4: Scoring
        score = self._score_features(features, vector_config)

        # Step 5: Correlation
        correlation = self._calculate_correlation(normalized)

        # Step 6: Decision Making
        return self._make_decision(score, correlation, normalized, vector_config)

    def _collect_signals(self, target: str, config: Dict[str, Any]) -> List[VectorSignal]:
        """Collect signals from all collectors"""
        signals = []
        for collector in self.collectors:
            try:
                collected = collector.collect(target, config)
                signals.extend(collected)
            except Exception as e:
                pass  # Silently fail on collection errors
        return signals

    def _normalize_signals(self, signals: List[VectorSignal]) -> List[VectorSignal]:
        """Normalize signal values to 0-1 range"""
        normalized = []
        for signal in signals:
            # Already normalized by collectors
            normalized.append(signal)
        return normalized

    def _extract_features(self, signals: List[VectorSignal]) -> Dict[str, Any]:
        """Extract features from signals"""
        values = [s.value for s in signals]
        confidences = [s.confidence for s in signals]

        return {
            "mean_value": statistics.mean(values) if values else 0,
            "std_value": statistics.stdev(values) if len(values) > 1 else 0,
            "max_value": max(values) if values else 0,
            "min_value": min(values) if values else 0,
            "mean_confidence": statistics.mean(confidences) if confidences else 0,
            "signal_count": len(signals),
        }

    def _score_features(self, features: Dict[str, Any], config: Dict[str, Any]) -> float:
        """Score features to produce overall score"""
        # Weighted scoring
        weights = config.get("weights", {
            "mean_value": 0.4,
            "max_value": 0.3,
            "signal_count": 0.2,
            "mean_confidence": 0.1,
        })

        score = 0.0
        for feature, weight in weights.items():
            score += features.get(feature, 0) * weight

        return score

    def _calculate_correlation(self, signals: List[VectorSignal]) -> float:
        """Calculate correlation between signals"""
        if len(signals) < 2:
            return 0.0

        # Simple correlation: how similar are the values?
        values = [s.value for s in signals]
        mean = statistics.mean(values)

        # Variance-based correlation
        variance = statistics.variance(values) if len(values) > 1 else 0
        correlation = 1.0 - min(variance, 1.0)

        return correlation

    def _make_decision(
        self,
        score: float,
        correlation: float,
        signals: List[VectorSignal],
        config: Dict[str, Any]
    ) -> VectorResult:
        """Make final decision based on score and correlation"""
        # Thresholds from config or defaults
        confirmed_threshold = config.get("confirmed_threshold", 0.7)
        inconclusive_threshold = config.get("inconclusive_threshold", 0.4)

        overall_confidence = (score + correlation) / 2

        if overall_confidence >= confirmed_threshold:
            status = "CONFIRMED"
            evidence = self._generate_evidence(signals, status)
        elif overall_confidence >= inconclusive_threshold:
            status = "INCONCLUSIVE"
            evidence = self._generate_evidence(signals, status)
        else:
            status = "NOT_FOUND"
            evidence = []

        return VectorResult(
            status=status,
            confidence=overall_confidence,
            signals=signals,
            evidence=evidence,
            correlation_score=correlation,
        )

    def _not_found_result(self, reason: str) -> VectorResult:
        """Generate NOT_FOUND result"""
        return VectorResult(
            status="NOT_FOUND",
            confidence=0.0,
            signals=[],
            evidence=[reason],
            correlation_score=0.0,
        )

    def _generate_evidence(self, signals: List[VectorSignal], status: str) -> List[str]:
        """Generate evidence list from signals"""
        evidence = []
        for signal in signals:
            if signal.value > 0.5:  # Only meaningful signals
                source_desc = {
                    "network": "Network signal detected",
                    "timing": "Timing anomaly observed",
                    "protocol": "Protocol behavior confirmed",
                    "behavior": "Behavioral pattern identified",
                }.get(signal.source, f"{signal.source} signal detected")

                evidence.append(source_desc)

        return evidence
