"""
Scanner Engine - главный движок сканирования
"""
import signal
import importlib
from typing import Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from .vector_registry import VectorRegistry, Vector
from .logical_analyzer import LogicalAnalyzer
from .result_aggregator import ResultAggregator, ScanResult
from ..connectors.adb_connector import ADBConnector
from ..utils.config import ScanConfig
from ..utils.logger import get_logger
from ..output.progress_bar import ProgressBar


class ScannerEngine:
    """Главный движок сканирования"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.logger = get_logger()
        self.registry = VectorRegistry()
        self.analyzer = LogicalAnalyzer(self.registry)
        self.aggregator = ResultAggregator()
        self.progress_bar = ProgressBar()
        self.shutdown_requested = False
        
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Обработчик сигналов для graceful shutdown"""
        self.logger.warning("\n[!] Shutdown requested, finishing current checks...")
        self.shutdown_requested = True
    
    def _get_device_info(self) -> Dict[str, Any]:
        """Получение информации об устройстве"""
        try:
            connector = ADBConnector(self.config.target_ip, self.config.adb_port, self.config.timeout)
            if connector.connect():
                info = connector.get_device_info()
                connector.disconnect()
                return info
        except Exception as e:
            self.logger.error(f"Failed to get device info: {e}")
        return {}
    
    def _execute_check(self, vector: Vector) -> ScanResult:
        """Выполнение одной проверки"""
        try:
            check_module = self._load_check_module(vector.check_function)
            if not check_module:
                return ScanResult(
                    vector.id,
                    vector.name,
                    False,
                    "Check function not implemented",
                    "INFO"
                )
            
            result = check_module(
                self.config.target_ip,
                self.config.adb_port,
                self.config.timeout
            )
            
            vulnerable = result.get("vulnerable", False)
            details = result.get("details", "No details")
            severity = result.get("severity", "INFO")
            
            return ScanResult(vector.id, vector.name, vulnerable, details, severity)
        
        except Exception as e:
            self.logger.error(f"Error executing {vector.name}: {e}")
            return ScanResult(
                vector.id,
                vector.name,
                False,
                f"Error: {str(e)}",
                "INFO"
            )
    
    def _load_check_module(self, check_function: str):
        """Динамическая загрузка функции проверки"""
        try:
            module_map = {
                "check_vnc_availability": ("aasfa.checks.network_checks", "check_vnc_availability"),
                "check_rdp_availability": ("aasfa.checks.network_checks", "check_rdp_availability"),
                "check_ssh_open": ("aasfa.checks.network_checks", "check_ssh_open"),
                "check_telnet_presence": ("aasfa.checks.network_checks", "check_telnet_presence"),
                "check_upnp_exposure": ("aasfa.checks.network_checks", "check_upnp_exposure"),
                "check_mdns_exposure": ("aasfa.checks.network_checks", "check_mdns_exposure"),
                "check_http_admin_panels": ("aasfa.checks.network_checks", "check_http_admin_panels"),
                "check_https_without_hsts": ("aasfa.checks.network_checks", "check_https_without_hsts"),
                "check_ftp_anonymous": ("aasfa.checks.network_checks", "check_ftp_anonymous"),
                "check_mqtt_exposure": ("aasfa.checks.network_checks", "check_mqtt_exposure"),
                "check_adb_over_tcp_network": ("aasfa.checks.adb_checks", "check_adb_over_tcp"),
                "check_debuggable_build": ("aasfa.checks.adb_checks", "check_debuggable_build"),
                "check_ro_secure_misconfig": ("aasfa.checks.adb_checks", "check_ro_secure_misconfig"),
                "check_ro_adb_secure": ("aasfa.checks.adb_checks", "check_ro_adb_secure"),
                "check_test_keys": ("aasfa.checks.adb_checks", "check_test_keys"),
                "check_selinux_permissive": ("aasfa.checks.adb_checks", "check_selinux_permissive"),
                "check_userdebug_remnants": ("aasfa.checks.adb_checks", "check_userdebug_remnants"),
                "check_system_uid_leakage": ("aasfa.checks.adb_checks", "check_system_uid_leakage"),
                "check_logcat_sensitive_data": ("aasfa.checks.adb_checks", "check_logcat_sensitive_data"),
                "check_root_access": ("aasfa.checks.adb_checks", "check_root_access"),
                "check_exported_activities": ("aasfa.checks.service_checks", "check_exported_activities"),
                "check_exported_services": ("aasfa.checks.service_checks", "check_exported_services"),
                "check_exported_receivers": ("aasfa.checks.service_checks", "check_exported_receivers"),
                "check_contentprovider_exposure": ("aasfa.checks.service_checks", "check_contentprovider_exposure"),
                "check_backup_flag_enabled": ("aasfa.checks.service_checks", "check_backup_flag_enabled"),
                "check_intent_hijacking": ("aasfa.checks.service_checks", "check_intent_hijacking"),
                "check_hardware_backed_key": ("aasfa.checks.crypto_checks", "check_hardware_backed_keystore"),
                "check_verified_boot": ("aasfa.checks.crypto_checks", "check_verified_boot"),
                "check_fastboot_unlock": ("aasfa.checks.firmware_checks", "check_bootloader_unlock"),
            }
            
            if check_function in module_map:
                module_name, func_name = module_map[check_function]
                module = importlib.import_module(module_name)
                return getattr(module, func_name)
            
            # Попытка загрузить из stub_checks
            try:
                stub_module = importlib.import_module("aasfa.checks.stub_checks")
                if hasattr(stub_module, check_function):
                    return getattr(stub_module, check_function)
            except Exception:
                pass
            
            return None
        
        except Exception as e:
            self.logger.debug(f"Failed to load {check_function}: {e}")
            return None
    
    def scan(self) -> ResultAggregator:
        """Запуск сканирования"""
        self.logger.info(f"[*] Starting AASFA Scanner v1.0")
        self.logger.info(f"[*] Target: {self.config.target_ip}")
        self.logger.info(f"[*] Mode: {self.config.mode}")
        self.logger.info(f"[*] Threads: {self.config.threads}")
        
        device_info = self._get_device_info()
        if device_info:
            self.aggregator.add_device_info(device_info)
            android_version = device_info.get('android_version', 'Unknown')
            device_model = device_info.get('device_model', 'Unknown')
            self.logger.info(f"[*] Android version: {android_version}")
            self.logger.info(f"[*] Device: {device_model}")
        
        vectors_to_scan = self.registry.filter_vectors(self.config)
        sorted_vectors = self.analyzer.get_execution_order(vectors_to_scan)
        
        total_vectors = len(sorted_vectors)
        self.logger.info(f"[*] Total checks: {total_vectors}")
        self.logger.info("[*] Scanning...")
        
        self.progress_bar.start(total_vectors)
        
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            pending = sorted_vectors.copy()
            completed_count = 0
            
            while pending and not self.shutdown_requested:
                ready_vectors = self.analyzer.get_next_vectors(pending)
                
                if not ready_vectors:
                    break
                
                batch_size = min(len(ready_vectors), self.config.threads * 2)
                batch = ready_vectors[:batch_size]
                
                futures = {
                    executor.submit(self._execute_check, vector): vector
                    for vector in batch
                }
                
                for future in as_completed(futures):
                    vector = futures[future]
                    
                    try:
                        result = future.result(timeout=self.config.timeout)
                        self.aggregator.add_result(result)
                        self.analyzer.mark_completed(vector.id, not result.vulnerable or result.severity == "INFO")
                        
                        completed_count += 1
                        self.progress_bar.update(completed_count)
                        
                        if result.vulnerable:
                            severity_symbol = {
                                "CRITICAL": "[!]",
                                "HIGH": "[+]",
                                "MEDIUM": "[*]",
                                "LOW": "[-]",
                            }.get(result.severity, "[*]")
                            
                            self.logger.info(f"{severity_symbol} VECTOR_{vector.id:03d}: {vector.name} [{result.severity}]")
                    
                    except Exception as e:
                        self.logger.error(f"Error processing {vector.name}: {e}")
                        self.analyzer.mark_completed(vector.id, False)
                        completed_count += 1
                        self.progress_bar.update(completed_count)
                    
                    pending.remove(vector)
        
        self.progress_bar.finish()
        self.aggregator.finish()
        
        return self.aggregator
