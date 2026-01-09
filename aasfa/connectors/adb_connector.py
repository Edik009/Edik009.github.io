"""
ADB connector for Android device communication
"""
import subprocess
from typing import Optional, List
from .base_connector import BaseConnector
from ..utils.helpers import execute_command


class ADBConnector(BaseConnector):
    """ADB коннектор для работы с Android устройствами"""
    
    def __init__(self, host: str, port: int = 5555, timeout: int = 30):
        super().__init__(host, port, timeout)
        self.device_id = f"{host}:{port}"
    
    def connect(self) -> bool:
        """Подключение к ADB устройству"""
        try:
            success, stdout, stderr = execute_command(
                ["adb", "connect", self.device_id],
                timeout=self.timeout
            )
            
            if success and "connected" in stdout.lower():
                self.connected = True
                self.logger.debug(f"ADB connected to {self.device_id}")
                return True
            
            self.logger.debug(f"ADB connection failed: {stderr}")
            return False
        except Exception as e:
            self.logger.error(f"ADB connection error: {e}")
            return False
    
    def disconnect(self):
        """Отключение от ADB устройства"""
        if self.connected:
            try:
                execute_command(["adb", "disconnect", self.device_id])
                self.connected = False
            except Exception as e:
                self.logger.error(f"ADB disconnect error: {e}")
    
    def execute(self, command: str) -> tuple[bool, str]:
        """Выполнение ADB команды"""
        if not self.connected:
            return False, "Not connected"
        
        try:
            success, stdout, stderr = execute_command(
                ["adb", "-s", self.device_id, "shell", command],
                timeout=self.timeout
            )
            return success, stdout if success else stderr
        except Exception as e:
            return False, str(e)
    
    def get_prop(self, prop_name: str) -> Optional[str]:
        """Получение системного свойства"""
        success, result = self.execute(f"getprop {prop_name}")
        if success:
            return result.strip()
        return None
    
    def list_packages(self) -> List[str]:
        """Список установленных пакетов"""
        success, result = self.execute("pm list packages")
        if success:
            packages = []
            for line in result.split('\n'):
                if line.startswith("package:"):
                    packages.append(line.replace("package:", "").strip())
            return packages
        return []
    
    def get_device_info(self) -> dict:
        """Получение информации об устройстве"""
        info = {}
        
        props = {
            "android_version": "ro.build.version.release",
            "sdk_version": "ro.build.version.sdk",
            "device_model": "ro.product.model",
            "manufacturer": "ro.product.manufacturer",
            "build_type": "ro.build.type",
            "secure": "ro.secure",
            "debuggable": "ro.debuggable",
            "adb_secure": "ro.adb.secure",
        }
        
        for key, prop in props.items():
            value = self.get_prop(prop)
            if value:
                info[key] = value
        
        return info
    
    def is_rooted(self) -> bool:
        """Проверка root доступа"""
        success, result = self.execute("su -c 'id'")
        return success and "uid=0" in result
    
    def check_selinux(self) -> Optional[str]:
        """Проверка статуса SELinux"""
        success, result = self.execute("getenforce")
        if success:
            return result.strip()
        return None
