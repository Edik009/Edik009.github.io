"""
D. Supply Chain / Exotic Vectors (171-300)

Exotic and advanced security checks.
"""
from typing import Dict, Any, List


def get_supply_chain_vectors() -> Dict[int, Dict[str, Any]]:
    """Возвращает все Supply Chain / Exotic векторы (171-300)"""

    vectors = {}

    # Generate vectors 171-300
    for vector_id in range(171, 301):
        name = f"Exotic Vector {vector_id}"
        vectors[vector_id] = {
            "id": vector_id,
            "category": "D",
            "name": name,
            "description": f"Exotic security check: {name}",
            "check_function": f"check_vector_{vector_id}",
            "requires_adb": True,
            "requires_network": False,
            "priority": 4,
            "depends_on": [6],
            "tags": ["supply-chain", "exotic", "advanced"],
            "severity": "INFO",
            "weights": None,
            "confirmed_threshold": 0.7,
            "inconclusive_threshold": 0.4,
        }

    return vectors
