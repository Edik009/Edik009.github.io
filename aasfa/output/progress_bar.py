"""
Progress bar for scan progress visualization
"""
import sys
import time


class ProgressBar:
    """Прогресс-бар для визуализации прогресса сканирования"""

    def __init__(self, width: int = 40):
        self.width = width
        self.total = 0
        self.current = 0
        self.start_time = 0.0
        self.enabled = sys.stdout.isatty()
        self._last_render_len = 0

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

    def write_line(self, message: str):
        """Печать строки поверх прогресс-бара без артефактов."""
        if not self.enabled:
            print(message)
            return

        self._clear_line()
        sys.stdout.write(message + "\n")
        sys.stdout.flush()
        self._draw()

    def _clear_line(self):
        if not self.enabled:
            return

        if self._last_render_len:
            sys.stdout.write("\r" + (" " * self._last_render_len) + "\r")
            sys.stdout.flush()

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
        
        line = f'[{bar}] {percent}% | {self.current}/{self.total} | ETA: {eta_str}'
        self._last_render_len = len(line) + 1

        sys.stdout.write(f'\r{line}')
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
