"""
Vector Registry - реестр всех 300 векторов проверки
"""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from ..vectors.network_level import get_network_vectors
from ..vectors.android_os_logic import get_android_os_vectors
from ..vectors.application_layer import get_application_vectors
from ..vectors.supply_chain_exotic import get_supply_chain_vectors


@dataclass
class Vector:
    """Вектор проверки"""
    id: int
    category: str
    name: str
    description: str
    check_function: str
    requires_adb: bool
    requires_network: bool
    priority: int
    depends_on: List[int]
    tags: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        return {
            "id": self.id,
            "category": self.category,
            "name": self.name,
            "description": self.description,
            "check_function": self.check_function,
            "requires_adb": self.requires_adb,
            "requires_network": self.requires_network,
            "priority": self.priority,
            "depends_on": self.depends_on,
            "tags": self.tags,
        }


class VectorRegistry:
    """Реестр всех векторов проверки"""
    
    def __init__(self):
        self.vectors: Dict[int, Vector] = {}
        self._load_all_vectors()
    
    def _load_all_vectors(self):
        """Загрузка всех векторов"""
        all_vectors = {}
        
        all_vectors.update(get_network_vectors())
        all_vectors.update(get_android_os_vectors())
        all_vectors.update(get_application_vectors())
        all_vectors.update(get_supply_chain_vectors())
        
        for vector_id, vector_data in all_vectors.items():
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
        
        if config.no_network:
            vectors = [v for v in vectors if not v.requires_network]
        
        if config.adb_only:
            vectors = [v for v in vectors if v.requires_adb]
        
        if config.mode == "fast":
            vectors = [v for v in vectors if v.priority <= 2]
        elif config.mode == "full":
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
            "requires_adb": len(self.get_vectors_requiring_adb()),
            "requires_network": len(self.get_vectors_requiring_network()),
        }
