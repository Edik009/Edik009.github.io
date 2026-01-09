"""
Tests for vector registry and vector loading
"""
import pytest
from aasfa.core.vector_registry import VectorRegistry


class TestVectorRegistry:
    """Тесты для VectorRegistry"""
    
    def test_registry_initialization(self):
        """Тест инициализации реестра"""
        registry = VectorRegistry()
        assert len(registry.vectors) == 300
    
    def test_get_vector_by_id(self):
        """Тест получения вектора по ID"""
        registry = VectorRegistry()
        
        vector_1 = registry.get_vector(1)
        assert vector_1 is not None
        assert vector_1.id == 1
        assert vector_1.category == "A"
        
        vector_50 = registry.get_vector(50)
        assert vector_50 is not None
        assert vector_50.category == "B"
        
        vector_150 = registry.get_vector(150)
        assert vector_150 is not None
        assert vector_150.category == "C"
        
        vector_250 = registry.get_vector(250)
        assert vector_250 is not None
        assert vector_250.category == "D"
    
    def test_get_vectors_by_category(self):
        """Тест получения векторов по категории"""
        registry = VectorRegistry()
        
        category_a = registry.get_vectors_by_category("A")
        assert len(category_a) == 40
        
        category_b = registry.get_vectors_by_category("B")
        assert len(category_b) == 60
        
        category_c = registry.get_vectors_by_category("C")
        assert len(category_c) == 70
        
        category_d = registry.get_vectors_by_category("D")
        assert len(category_d) == 130
    
    def test_get_vectors_by_priority(self):
        """Тест получения векторов по приоритету"""
        registry = VectorRegistry()
        
        priority_1 = registry.get_vectors_by_priority(1)
        assert len(priority_1) == 40
        assert all(v.category == "A" for v in priority_1)
    
    def test_get_vectors_requiring_adb(self):
        """Тест получения векторов, требующих ADB"""
        registry = VectorRegistry()
        
        adb_vectors = registry.get_vectors_requiring_adb()
        assert len(adb_vectors) > 0
        assert all(v.requires_adb for v in adb_vectors)
    
    def test_get_vectors_requiring_network(self):
        """Тест получения векторов, требующих сеть"""
        registry = VectorRegistry()
        
        network_vectors = registry.get_vectors_requiring_network()
        assert len(network_vectors) == 40
        assert all(v.requires_network for v in network_vectors)
    
    def test_statistics(self):
        """Тест статистики"""
        registry = VectorRegistry()
        stats = registry.get_statistics()
        
        assert stats["total"] == 300
        assert stats["category_A"] == 40
        assert stats["category_B"] == 60
        assert stats["category_C"] == 70
        assert stats["category_D"] == 130
    
    def test_vector_structure(self):
        """Тест структуры вектора"""
        registry = VectorRegistry()
        vector = registry.get_vector(1)
        
        assert hasattr(vector, 'id')
        assert hasattr(vector, 'category')
        assert hasattr(vector, 'name')
        assert hasattr(vector, 'description')
        assert hasattr(vector, 'check_function')
        assert hasattr(vector, 'requires_adb')
        assert hasattr(vector, 'requires_network')
        assert hasattr(vector, 'priority')
        assert hasattr(vector, 'depends_on')
        assert hasattr(vector, 'tags')
        
        assert isinstance(vector.depends_on, list)
        assert isinstance(vector.tags, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
