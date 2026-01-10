"""Vector Registry - реестр всех векторов проверки."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..vectors.ai_ml_modern import get_ai_ml_vectors
from ..vectors.ai_system_intelligence import get_ai_system_vectors
from ..vectors.android_os_logic import get_android_os_vectors
from ..vectors.application_layer import get_application_vectors
from ..vectors.behavioral_correlation import get_behavioral_vectors
from ..vectors.firmware_os_lowlevel import get_firmware_os_vectors
from ..vectors.network_level import get_network_vectors
from ..vectors.network_services import get_network_services_vectors
from ..vectors.oem_supply_chain import get_oem_supply_vectors
from ..vectors.supply_chain_exotic import get_supply_chain_vectors
from ..vectors.additional_vectors import get_additional_vectors
from ..vectors.multifactor_vectors import get_multifactor_vectors
from ..vectors.side_channel_vectors import get_side_channel_vectors


@dataclass
class Vector:
    """Вектор проверки"""

    id: int
    category: str
    name: str
    description: str
    check_functions: List[str]  # ВМЕСТО check_function - список функций!
    priority: int
    depends_on: List[int]
    tags: List[str]
    requires_adb: bool = False  # Все векторы теперь network-only
    requires_network: bool = True
    severity: str = "INFO"
    weights: Dict[str, float] = None
    confirmed_threshold: float = 0.7
    inconclusive_threshold: float = 0.4
    check_count: int = 1  # сколько независимых проверок нужно

    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        return {
            "id": self.id,
            "category": self.category,
            "name": self.name,
            "description": self.description,
            "check_function": self.check_functions[0] if self.check_functions else None,  # backward compatibility
            "check_functions": self.check_functions,
            "requires_adb": self.requires_adb,
            "requires_network": self.requires_network,
            "priority": self.priority,
            "depends_on": self.depends_on,
            "tags": self.tags,
            "severity": self.severity,
            "weights": self.weights,
            "confirmed_threshold": self.confirmed_threshold,
            "inconclusive_threshold": self.inconclusive_threshold,
            "check_count": self.check_count,
        }


class VectorRegistry:
    """Реестр всех векторов проверки"""

    def __init__(self):
        self.vectors: Dict[int, Vector] = {}
        self._load_all_vectors()

    def _load_all_vectors(self):
        """Загрузка всех векторов"""
        all_vectors: Dict[int, Dict[str, Any]] = {}

        all_vectors.update(get_network_vectors())
        # REMOVED: android_os_vectors (ADB required)
        # REMOVED: application_vectors (ADB required)
        all_vectors.update(get_supply_chain_vectors())
        all_vectors.update(get_network_services_vectors())
        # REMOVED: firmware_os_vectors (ADB required)
        # REMOVED: ai_ml_vectors (ADB required)
        all_vectors.update(get_behavioral_vectors())
        all_vectors.update(get_oem_supply_vectors())
        all_vectors.update(get_ai_system_vectors())
        all_vectors.update(get_additional_vectors())
        all_vectors.update(get_multifactor_vectors())  # NEW: 30 multifactor vectors (1001-1030)
        all_vectors.update(get_side_channel_vectors())  # NEW: 50 side-channel vectors (101-200)

        seen_names: set[str] = set()
        for vector_id, vector_data in all_vectors.items():
            name = vector_data.get("name", "")
            if name in seen_names:
                vector_data = dict(vector_data)
                vector_data["name"] = f"{name} (#{vector_id})"
            seen_names.add(vector_data.get("name", ""))
            self.vectors[vector_id] = Vector(**vector_data)

    def get_vector(self, vector_id: int) -> Optional[Vector]:
        """Получение вектора по ID"""
        return self.vectors.get(vector_id)

    def get_all_vectors(self) -> List[Vector]:
        """Получение всех векторов"""
        return list(self.vectors.values())

    def get_vectors_by_category(self, category: str) -> List[Vector]:
        """Получение векторов по категории"""
        return [v for v in self.vectors.values() if v.category == category]

    def get_vectors_by_priority(self, priority: int) -> List[Vector]:
        """Получение векторов по приоритету"""
        return [v for v in self.vectors.values() if v.priority == priority]

    def get_vectors_requiring_adb(self) -> List[Vector]:
        """Получение векторов, требующих ADB"""
        return [v for v in self.vectors.values() if v.requires_adb]

    def get_vectors_requiring_network(self) -> List[Vector]:
        """Получение векторов, требующих сеть"""
        return [v for v in self.vectors.values() if v.requires_network]

    def get_dependent_vectors(self, vector_id: int) -> List[Vector]:
        """Получение векторов, зависящих от данного"""
        return [v for v in self.vectors.values() if vector_id in v.depends_on]

    def get_vectors_by_tags(self, tags: List[str]) -> List[Vector]:
        """Получение векторов по тегам"""
        result = []
        for vector in self.vectors.values():
            if any(tag in vector.tags for tag in tags):
                result.append(vector)
        return result

    def filter_vectors(self, config: Any) -> List[Vector]:
        """Фильтрация векторов по конфигурации"""
        vectors = self.get_all_vectors()

        if getattr(config, "remote_only", False):
            vectors = [v for v in vectors if v.requires_network and not v.requires_adb]
        else:
            if getattr(config, "no_network", False):
                vectors = [v for v in vectors if not v.requires_network]

            if getattr(config, "adb_only", False):
                vectors = [v for v in vectors if v.requires_adb]

        mode = getattr(config, "mode", "full")
        if mode == "fast":
            vectors = [v for v in vectors if v.priority <= 2]
        elif mode == "full":
            vectors = [v for v in vectors if v.priority <= 3]

        return vectors

    def get_statistics(self) -> Dict[str, int]:
        """Статистика по векторам"""
        return {
            "total": len(self.vectors),
            "category_A": len(self.get_vectors_by_category("A")),
            "category_B": len(self.get_vectors_by_category("B")),
            "category_C": len(self.get_vectors_by_category("C")),
            "category_D": len(self.get_vectors_by_category("D")),
            "category_E": len(self.get_vectors_by_category("E")),
            "category_F": len(self.get_vectors_by_category("F")),
            "category_G": len(self.get_vectors_by_category("G")),
            "category_H": len(self.get_vectors_by_category("H")),
            "category_I": len(self.get_vectors_by_category("I")),
            "category_J": len(self.get_vectors_by_category("J")),
            "category_M": len(self.get_vectors_by_category("M")),  # Multifactor vectors
            "category_S": len(self.get_vectors_by_category("S")),  # Side-channel vectors
            "requires_adb": len(self.get_vectors_requiring_adb()),
            "requires_network": len(self.get_vectors_requiring_network()),
        }
