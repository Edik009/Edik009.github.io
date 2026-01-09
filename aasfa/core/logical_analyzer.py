"""
Logical Analyzer - chain-aware анализ зависимостей векторов
"""
from typing import Dict, List, Set, Any
from .vector_registry import VectorRegistry, Vector
from ..utils.logger import get_logger


class LogicalAnalyzer:
    """Логический анализатор для chain-aware проверок"""
    
    def __init__(self, registry: VectorRegistry):
        self.registry = registry
        self.logger = get_logger()
        self.completed_vectors: Set[int] = set()
        self.successful_vectors: Set[int] = set()
    
    def mark_completed(self, vector_id: int, success: bool):
        """Отметить вектор как выполненный"""
        self.completed_vectors.add(vector_id)
        if success:
            self.successful_vectors.add(vector_id)
    
    def can_execute(self, vector: Vector) -> bool:
        """Проверить, можно ли выполнить вектор"""
        if not vector.depends_on:
            return True
        
        for dep_id in vector.depends_on:
            if dep_id not in self.completed_vectors:
                return False
            if dep_id not in self.successful_vectors:
                self.logger.debug(f"Vector {vector.id} skipped: dependency {dep_id} failed")
                return False
        
        return True
    
    def get_next_vectors(self, pending_vectors: List[Vector]) -> List[Vector]:
        """Получить векторы, готовые к выполнению"""
        ready = []
        for vector in pending_vectors:
            if vector.id not in self.completed_vectors and self.can_execute(vector):
                ready.append(vector)
        return ready
    
    def get_execution_order(self, vectors: List[Vector]) -> List[Vector]:
        """Получить порядок выполнения векторов с учетом зависимостей"""
        sorted_vectors = []
        remaining = vectors.copy()
        completed = set()
        
        vector_ids = {v.id for v in vectors}
        
        while remaining:
            ready = []
            for vector in remaining:
                deps_in_list = [dep for dep in vector.depends_on if dep in vector_ids]
                if not deps_in_list or all(dep in completed for dep in deps_in_list):
                    ready.append(vector)
            
            if not ready:
                self.logger.debug("Some dependencies not in current vector list, skipping dependent vectors")
                for vector in remaining[:]:
                    if vector.depends_on:
                        self.logger.debug(f"Skipping vector {vector.id} due to missing dependencies")
                    else:
                        ready.append(vector)
                
                if not ready:
                    break
            
            ready.sort(key=lambda v: (v.priority, v.id))
            
            for vector in ready:
                sorted_vectors.append(vector)
                completed.add(vector.id)
                remaining.remove(vector)
        
        return sorted_vectors
    
    def get_dependency_chain(self, vector_id: int) -> List[int]:
        """Получить цепочку зависимостей"""
        chain = []
        visited = set()
        
        def traverse(vid: int):
            if vid in visited:
                return
            visited.add(vid)
            
            vector = self.registry.get_vector(vid)
            if vector and vector.depends_on:
                for dep_id in vector.depends_on:
                    traverse(dep_id)
            chain.append(vid)
        
        traverse(vector_id)
        return chain
    
    def get_impact_analysis(self, vector_id: int) -> Dict[str, Any]:
        """Анализ влияния вектора на другие"""
        dependent = self.registry.get_dependent_vectors(vector_id)
        
        return {
            "vector_id": vector_id,
            "directly_affects": len(dependent),
            "dependent_vectors": [v.id for v in dependent],
        }
    
    def get_blocked_vectors(self) -> List[Vector]:
        """Получить заблокированные векторы"""
        blocked = []
        for vector in self.registry.get_all_vectors():
            if vector.id not in self.completed_vectors and not self.can_execute(vector):
                blocked.append(vector)
        return blocked
    
    def get_statistics(self) -> Dict[str, int]:
        """Статистика выполнения"""
        total = len(self.registry.get_all_vectors())
        return {
            "total_vectors": total,
            "completed": len(self.completed_vectors),
            "successful": len(self.successful_vectors),
            "failed": len(self.completed_vectors) - len(self.successful_vectors),
            "pending": total - len(self.completed_vectors),
        }
