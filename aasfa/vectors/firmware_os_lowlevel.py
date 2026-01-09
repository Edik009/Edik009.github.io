"""
F. Firmware/OS/Low-level Vectors (381-520)

Firmware, operating system, and low-level security checks.
"""
from typing import Dict, Any, List


def get_firmware_os_vectors() -> Dict[int, Dict[str, Any]]:
    """Возвращает все Firmware/OS/Low-level векторы (381-520)"""

    vectors = {}

    # Generate vectors 381-520
    for vector_id in range(381, 521):
        name = f"Firmware/OS Vector {vector_id}"
        vectors[vector_id] = {
            "id": vector_id,
            "category": "F",
            "name": name,
            "description": f"Firmware/OS security check: {name}",
            "check_function": f"check_vector_{vector_id}",
            "requires_adb": True,
            "requires_network": False,
            "priority": 4,
            "depends_on": [6],
            "tags": ["firmware", "os", "low-level"],
            "severity": "INFO",
            "weights": None,
            "confirmed_threshold": 0.7,
            "inconclusive_threshold": 0.4,
        }

    return vectors
