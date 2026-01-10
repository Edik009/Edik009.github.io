"""
J. AI / System Intelligence Vectors (1061-1200)

On-device AI, machine learning, and system intelligence analysis.
"""

from __future__ import annotations

from typing import Any, Dict, List


_RAW_VECTOR_NAMES = """
On-device intelligence API probing
PCC fallback inference
AI scheduling timing leak
Model execution latency fingerprint
Feature activation without UI
AI-driven network behavior
Smart system adaptation profiling
Federated client role inference
Local learning window detection
ML feature gating behavior
Contextual engine trust scope
Cross-surface AI data reuse
Inference warm-up detection
Model hot-swap behavior
Silent model update detection
Transformer attention patterns
Embedding space collapses
Token embedding consistency
Positional encoding leakage
Layer normalization timing
Activation function patterns
Gradient accumulation timing
Backpropagation latency
Loss computation timing
Optimizer state size inference
Momentum accumulation patterns
Adaptive learning rate changes
Batch normalization timing
Dropout rate inference
Regularization strength detection
Early stopping patterns
Cross-validation procedures
Hyperparameter tuning traces
Model ensemble detection
Boosting iteration count
Bagging sampling patterns
Stacking meta-learner detection
Feature selection methods
Dimensionality reduction signals
Clustering assignment patterns
Distance metric usage
Similarity threshold inference
Outlier detection sensitivity
Anomaly score threshold
Novelty detection boundaries
One-class classification inference
Semi-supervised learning traces
Self-training patterns
Active learning queries
Data augmentation techniques
Transfer learning fingerprint
Domain adaptation signals
Few-shot learning detection
Zero-shot capability inference
Meta-learning patterns
Continual learning detection
Catastrophic forgetting prevention
Replay buffer usage
Experience consolidation
Knowledge retention patterns
Forgetting curve analysis
Spacing effect detection
Interleaving patterns
Contextual similarity grouping
Temporal proximity clustering
Semantic similarity patterns
Syntactic pattern matching
Pragmatic inference methods
Discourse coherence patterns
Anaphora resolution detection
Coreference clustering
Entity linking patterns
Relation extraction signals
Event detection methods
Temporal relation inference
Causal link detection
Contrastive learning patterns
Similarity learning traces
Metric learning usage
Prototype learning detection
Exemplar-based inference
Memory-augmented patterns
Attention mechanism usage
Self-attention patterns
Cross-attention signals
Multi-head attention size
Query key value projection
Attention mask patterns
Positional attention bias
Relative position encoding
Rotary position embedding
Alibi attention patterns
Local attention windows
Sparse attention patterns
Linear attention approximation
Performer kernel methods
Efficient transformer variants
Sequence length scaling
Batch size impact patterns
Token embedding dimension
Hidden layer dimension
Intermediate feed-forward size
Number of attention heads
Number of transformer layers
Vocabulary size inference
Token frequency patterns
Subword tokenization type
Vocabulary coverage analysis
Out-of-vocabulary handling
Special token usage
Byte-pair encoding patterns
Wordpiece tokenization
Sentence piece detection
Character-level patterns
Unigram model usage
BPE subword splitting
Word vocabulary size
Sentence vocabulary usage
Subword vocabulary overlap
Unknown token handling
Padding token patterns
End of sequence tokens
Start of sequence tokens
Separator tokens
Mask token usage
Control tokens
Special character tokens
Unicode tokenization
Normalization techniques
Lowercase handling
Accented character handling
Emoji tokenization
Whitespace tokenization
Number tokenization
Punctuation handling
Diacritic removal
Unicode normalization
NFKC normalization
NFD normalization
Character encoding detection
UTF-8 byte handling
Multi-byte sequences
Invalid character handling
Surrogate pair handling
Grapheme cluster handling
Emoji zero-width handling
""".strip()

_VECTOR_NAMES: List[str] = [line.strip() for line in _RAW_VECTOR_NAMES.splitlines() if line.strip()]

# Trim to exactly 140 vectors
_VECTOR_NAMES = _VECTOR_NAMES[:140]


def get_ai_system_vectors() -> Dict[int, Dict[str, Any]]:
    """Возвращает все AI / System Intelligence векторы (1061-1200)"""

    vectors: Dict[int, Dict[str, Any]] = {}

    start_id = 1061
    for offset, name in enumerate(_VECTOR_NAMES):
        vector_id = start_id + offset

        # Assign severity based on vector type
        severity = "LOW"
        if any(word in name.lower() for word in ["leak", "leakage", "inference", "without ui", "silent"]):
            severity = "MEDIUM"
        elif any(word in name.lower() for word in ["pattern", "behavior", "timing", "detection"]):
            severity = "LOW"

        vectors[vector_id] = {
            "id": vector_id,
            "category": "J",
            "name": name,
            "description": f"AI/System Intelligence analysis: {name}",
            "check_functions": [f"check_vector_{vector_id}"],
            "requires_adb": False,
            "requires_network": True,
            "priority": 4,
            "depends_on": [],
            "tags": ["ai", "ml", "system-intelligence"],
            "severity": severity,
            "weights": {
                "mean_value": 0.3,
                "max_value": 0.3,
                "signal_count": 0.2,
                "mean_confidence": 0.2,
            },
            "confirmed_threshold": 0.7,
            "inconclusive_threshold": 0.4,
            "check_count": 1,  # Single check for now
        }

    return vectors
