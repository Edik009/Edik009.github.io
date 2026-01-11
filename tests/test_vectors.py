"""Tests for vector registry and vector loading.

Проект активно расширяет количество векторов, поэтому тесты проверяют:
- корректную загрузку реестра
- наличие ключевых "якорных" векторов
- базовую структуру Vector
- согласованность статистики

Важно: эти тесты intentionally фиксируют текущие ожидаемые значения,
чтобы любые изменения в наборах векторов были явными.
"""

from __future__ import annotations

from collections import Counter

from aasfa.core.vector_registry import VectorRegistry


class TestVectorRegistry:
    """Тесты для VectorRegistry"""

    def test_registry_initialization(self):
        """Тест инициализации реестра"""

        registry = VectorRegistry()
        assert len(registry.vectors) == 964

    def test_anchor_vectors_exist(self):
        """Тест наличия ключевых векторов разных подсистем."""

        registry = VectorRegistry()

        # Базовая сеть
        v1 = registry.get_vector(1)
        assert v1 is not None
        assert v1.id == 1
        assert v1.category == "A"
        assert v1.check_functions

        # Multifactor/side-channel якоря
        assert registry.get_vector(1001) is not None
        assert registry.get_vector(151) is not None

        # Comprehensive/ultra якоря (верхние диапазоны)
        assert registry.get_vector(2000) is not None
        assert registry.get_vector(4800) is not None

        # Новые crypto/api векторы (часть 2)
        v_crypto = registry.get_vector(5000)
        assert v_crypto is not None
        assert v_crypto.category == "Cryptography"

        v_api = registry.get_vector(5100)
        assert v_api is not None
        assert v_api.category == "API"

    def test_get_vectors_by_category(self):
        """Тест получения векторов по категории."""

        registry = VectorRegistry()

        assert len(registry.get_vectors_by_category("A")) == 38
        assert len(registry.get_vectors_by_category("E")) == 80
        assert len(registry.get_vectors_by_category("H")) == 80
        assert len(registry.get_vectors_by_category("I")) == 70
        assert len(registry.get_vectors_by_category("J")) == 190
        assert len(registry.get_vectors_by_category("M")) == 30
        assert len(registry.get_vectors_by_category("S")) == 50

        assert len(registry.get_vectors_by_category("Cryptography")) == 57
        assert len(registry.get_vectors_by_category("API")) == 50

    def test_statistics(self):
        """Тест статистики."""

        registry = VectorRegistry()
        stats = registry.get_statistics()

        assert stats["total"] == 964
        assert stats["category_A"] == 38
        assert stats["category_E"] == 80
        assert stats["category_F"] == 30
        assert stats["category_H"] == 80
        assert stats["category_I"] == 70
        assert stats["category_J"] == 190
        assert stats["category_M"] == 30
        assert stats["category_S"] == 50

        assert stats["requires_adb"] == 0
        assert stats["requires_network"] == 964

    def test_vector_structure(self):
        """Тест структуры Vector."""

        registry = VectorRegistry()
        vector = registry.get_vector(5000)
        assert vector is not None

        assert hasattr(vector, "id")
        assert hasattr(vector, "category")
        assert hasattr(vector, "name")
        assert hasattr(vector, "description")
        assert hasattr(vector, "check_functions")
        assert hasattr(vector, "requires_adb")
        assert hasattr(vector, "requires_network")
        assert hasattr(vector, "priority")
        assert hasattr(vector, "depends_on")
        assert hasattr(vector, "tags")

        assert isinstance(vector.depends_on, list)
        assert isinstance(vector.tags, list)
        assert isinstance(vector.check_functions, list)
        assert vector.check_functions

    def test_no_duplicate_names_after_dedup(self):
        """VectorRegistry делает dedup name при коллизиях; проверяем, что итоговые имена уникальны."""

        registry = VectorRegistry()
        names = [v.name for v in registry.get_all_vectors()]
        assert len(names) == len(set(names))

    def test_category_distribution_sanity(self):
        """Sanity-check распределения категорий."""

        registry = VectorRegistry()
        c = Counter(v.category for v in registry.get_all_vectors())

        # Минимальные ожидаемые объёмы
        assert c["J"] >= 100
        assert c["Cryptography"] >= 50
        assert c["API"] >= 50
