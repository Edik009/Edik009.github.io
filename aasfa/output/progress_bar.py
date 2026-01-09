"""
Progress bar for scan progress visualization
"""
import sys
import time
from typing import Optional


class ProgressBar:
    """Прогресс-бар для визуализации прогресса сканирования"""
    
    def __init__(self, width: int = 50):
        self.width = width
        self.total = 0
        self.current = 0
        self.start_time = 0.0
        self.enabled = sys.stdout.isatty()
    
    def start(self, total: int):
        """Запуск прогресс-бара"""
        self.total = total
        self.current = 0
        self.start_time = time.time()
        self._draw()
    
    def update(self, current: int):
        """Обновление прогресса"""
        self.current = current
        self._draw()
    
    def finish(self):
        """Завершение прогресс-бара"""
        self.current = self.total
        self._draw()
        if self.enabled:
            print()
    
    def _draw(self):
        """Отрисовка прогресс-бара"""
        if not self.enabled:
            return
        
        if self.total == 0:
            return
        
        percent = int((self.current / self.total) * 100)
        filled = int((self.current / self.total) * self.width)
        bar = '█' * filled + '░' * (self.width - filled)
        
        elapsed = time.time() - self.start_time
        if self.current > 0:
            eta = (elapsed / self.current) * (self.total - self.current)
            eta_str = self._format_time(eta)
        else:
            eta_str = "???"
        
        sys.stdout.write(f'\r[{bar}] {percent}% | {self.current}/{self.total} | ETA: {eta_str}')
        sys.stdout.flush()
    
    def _format_time(self, seconds: float) -> str:
        """Форматирование времени"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"
