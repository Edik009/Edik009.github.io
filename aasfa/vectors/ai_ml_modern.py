"""G. AI/ML/Modern Vectors (521-900)

Primarily on-device and system intelligence checks.
"""

from __future__ import annotations

from typing import Any, Dict, List


_RAW_VECTOR_NAMES = """
On-device ML extraction
Model inversion
Training data leak
Federated learning cache
Gradient leakage
Prompt cache leak
On-device LLM logs
AI suggestion memory
Smart reply context
Voice assistant cache
Wake word trigger
Wake word spoof
Speech model reuse
Voiceprint fallback
AI keyboard cache
AI clipboard analysis
OCR cache leak
Screenshot ML analysis
Gallery ML metadata
Photo semantic indexing
Video content indexing
Recommendation engine
Cross-app ML sharing
Cross-profile ML leak
Work profile ML isolation
Personal profile ML bleed
Multi-user ML isolation
Guest profile residue
Cross-device ML sync
Wearable ML sync
Automotive ML sync
Smart home ML sync
Health ML leak
Fitness ML inference
Sleep tracking data
Motion pattern inference
Behavioral fingerprinting
Usage pattern inference
App usage models
Battery optimization
Location prediction
Contextual awareness
System intelligence
Private Compute Core config
PCC fallback
PCC logging
PCC data egress
AI sandbox escape
AI plugin isolation
AI extension trust
AI update channel
AI model rollback
AI model poisoning
AI prompt injection
AI action execution
AI intent invocation
AI system API exposure
AI permission escalation
AI decision override
AI fallback heuristics
Neural network extraction
AI inference cache poisoning
AI quantization bypass
AI pruning reversibility
AI compression artifact leak
Ensemble fingerprinting
Multi-model orchestration abuse
Cross-model info leak
Model architecture inference
Activation pattern analysis
Confidence score manipulation
Backdoor activation vectors
Trojan trigger patterns
Adversarial example generation
OOD detection bypass
Model explanation leak
Saliency map inference
Feature attribution abuse
SHAP value extraction
LIME explanation exploit
Decision boundary extraction
Gradient-based inference
Layer activation analysis
Attention weight leak
Embedding space extraction
Vector quantization bypass
Sparse representation leak
Low-rank approximation
Tensor decomposition
Knowledge distillation reverse
Transfer learning fingerprint
Fine-tuning data leak
Adapter model abuse
LoRA weight extraction
Prefix tuning bypass
Prompt learning cache
In-context learning abuse
Few-shot learning fallback
Zero-shot inference
Multi-modal model leak
Vision transformer exposure
CLIP model abuse
Stable diffusion cache
Generative model prompt leak
Diffusion process exposure
Latent space extraction
Tokenizer vocabulary leak
BPE encoding abuse
Subword unit inference
Token sequence pattern
Language model bias
Stereotype inference
Demographic info leak
Privacy attribute inference
Gender classification bypass
Age estimation leak
Ethnicity inference
Identity inference
Relationship inference
Location inference
Movement pattern leak
Timeline reconstruction
Social graph inference
Contact graph extraction
Communication pattern leak
Interaction frequency
Relationship strength
Community detection bypass
Network centrality leak
Influence score exposure
Recommendation system abuse
Personalization profile extraction
User preference inference
Collaborative filtering leak
Content-based filtering bias
Hybrid recommender abuse
Cold-start exploitation
Filter bubble creation
Echo chamber amplification
Manipulation vulnerability
Ranking algorithm inference
Sorting criterion extraction
Quality score leak
Relevance metric exposure
Search result poisoning
Query log exposure
Search history reconstruction
Autocomplete leak
Correction pattern inference
Spell checker extraction
Grammar correction cache
Language identification bypass
Script recognition leak
Encoding detection flaw
Charset inference
Locale detection bypass
Time zone inference
Calendar event analysis
Schedule pattern extraction
Productivity metric leak
Work-life balance inference
Stress level detection
Emotional state inference
Sentiment analysis leak
Opinion mining exposure
Review writing pattern
Rating behavior analysis
Purchase prediction
Shopping cart analysis
Browsing history inference
Click stream pattern
Dwell time analysis
Scroll depth inference
Interaction depth leak
Engagement score extraction
Retention rate inference
Churn prediction
Lifetime value exposure
Segment assignment leak
Clustering assignment exposure
Centroid position inference
Silhouette score leak
Dendrogram structure extraction
Hierarchical structure inference
Outlier detection exposure
Anomaly score leak
Isolation forest structure
Local outlier factor
Density-based detection leak
Isolation path extraction
Proximity measure inference
Distance metric exposure
Similarity threshold leak
Variance explanation leak
Dimension reduction bypass
PCA component extraction
SVD singular value leak
ICA component inference
Manifold learning structure
t-SNE structure exposure
UMAP embedding extraction
Autoencoder latent space
VAE latent distribution
Generative model bias
Discriminator loss exposure
Adversarial training bypass
Robust model weakness
Certified defense bypass
Fairness metric exposure
Bias detection bypass
Disparate impact inference
Allocation fairness leak
Calibration metric exposure
Equalized odds inference
Demographic parity leak

Synthetic data leakage
Model watermark removal
Model fingerprint collision
Embedding poisoning
Retrieval-augmented prompt injection
RAG index disclosure
RAG cache leak
Toolformer action override
Agent memory exfiltration
Agent tool permission creep
Background model download
Model update MITM
Model provenance spoof
Model registry takeover
On-device inference timing leak
Inference power side-channel
Inference thermal side-channel
GPU kernel side-channel
NPU scheduling leak
Quantized model decompilation
Secure inference enclave fallback
Trusted execution model key leak
Model key reuse
API key in model config
Prompt template disclosure
System prompt leak
Safety policy bypass
Jailbreak resilience gap
Multi-turn jailbreak escalation
Hidden instruction injection
UI-to-agent injection
Voice prompt injection
Image prompt injection
QR prompt injection
Document prompt injection
Cross-app prompt bridging
Clipboard-to-prompt leakage
Notification-to-prompt leakage
Accessibility-to-agent injection
Agent file write capability
Agent shell command capability
Agent network pivot capability
Agent calendar write abuse
Agent contacts read abuse
Agent SMS send abuse
Agent call initiation abuse
Agent payment initiation abuse
Agent location sharing abuse
Agent camera activation abuse
Agent microphone activation abuse
Agent screen capture abuse
Agent screenshot exfiltration
Agent keystore access attempt
Agent permission request spam
Agent background execution abuse

Federated client metadata leak
Federated model aggregation poisoning
Federated label leakage
Federated update replay
Federated update inversion
Differential privacy misconfig
DP budget exhaustion
DP noise removal
Secure aggregation bypass
Cross-silo federated leakage
Cross-device federated leakage

AI telemetry opt-out bypass
AI telemetry endpoint exposure
AI telemetry config leak
AI diagnostic dump leak
AI crash report leak
AI feature flag leak
AI canary model leak
AI staging model leak
AI test tenant leak
AI shadow endpoint leak

Membership inference attack
Embedding membership inference
Attribute inference via embeddings
Property inference attack
Dataset reconstruction via gradients
Hidden layer leakage
Token probability leakage
Logit lens exposure
Temperature manipulation
Top-k sampling manipulation
Safety classifier bypass
RLHF reward model extraction
Reward hacking feasibility
Prompt router bypass
Prompt routing policy leak
Tool selection policy leak
Agent planning trace leak
Chain-of-thought leak
CoT suppression bypass
Function calling schema injection
JSON mode bypass
Output parser confusion
LLM eval data leakage
Benchmark overfitting leak
Adversarial suffix attack
Unicode homoglyph prompt injection
Right-to-left override injection
Markdown link injection
HTML injection into prompt
Sandbox boundary confusion
System settings exfiltration
Device policy exfiltration
Enterprise secrets inference
Work profile contacts inference
Work calendar inference
Health record inference
Medical diagnosis inference
Biometric template inference
Voice embedding theft
Face embedding theft
Location embedding inference
Browsing interest inference
Purchase history inference
Keyboard embedding inference
Cross-app embedding reuse
Shared embedding service exposure
Embedding API unauth access
Embedding index enumeration
Vector store metadata leak
Vector store tenant isolation
Vector store distance leak
Vector store ANN params leak
Index rebuild exposure
Cache key prediction
Prompt cache key prediction
Response cache poisoning
Embedding cache poisoning
Model selection hijack
Multi-tenant model mixup
Cross-tenant context bleed
Agent session fixation
Agent auth token leak
OAuth token in prompt
API token in prompt
Cookie in prompt
Headers in prompt
Prompt logging in analytics
Prompt redaction bypass
Local model file permissions
Model file world-readable
Model file backup leak
Model file sync leak
Model quantization artifact fingerprint
LoRA adapter mixing
Adapter collision
Adapter sandbox escape
Plugin signature verification bypass
Plugin update rollback
Plugin dependency confusion
Model marketplace impersonation
On-device inference service exposed
Inference RPC unauth access
Inference RPC debug endpoints
Inference RPC reflection
AI IPC permission misconfig
AI shared memory exposure
AI temp file leakage
AI cache directory traversal
AI log retention misconfig
""".strip()

_VECTOR_NAMES: List[str] = [line.strip() for line in _RAW_VECTOR_NAMES.splitlines() if line.strip()]


def get_ai_ml_vectors() -> Dict[int, Dict[str, Any]]:
    """Возвращает все AI/ML/Modern векторы (521-900)"""

    if len(_VECTOR_NAMES) != 380:
        raise ValueError(f"Category G must contain exactly 380 vectors, got {len(_VECTOR_NAMES)}")

    vectors: Dict[int, Dict[str, Any]] = {}

    start_id = 521
    for offset, name in enumerate(_VECTOR_NAMES):
        vector_id = start_id + offset
        vectors[vector_id] = {
            "id": vector_id,
            "category": "G",
            "name": name,
            "description": name,
            "check_function": f"check_vector_{vector_id}",
            "requires_adb": True,
            "requires_network": False,
            "priority": 4,
            "depends_on": [6],
            "tags": ["ai", "ml", "modern"],
        }

    return vectors
