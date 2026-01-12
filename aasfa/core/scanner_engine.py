"""Scanner Engine - главный движок сканирования."""

from __future__ import annotations

import concurrent.futures
import importlib
import inspect
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict

from .logical_analyzer import LogicalAnalyzer
from .result_aggregator import ResultAggregator, ScanResult, VectorResult  # NEW: VectorResult import
from .vector_registry import Vector, VectorRegistry
from ..output.formatter import OutputFormatter
from ..output.progress_bar import ProgressBar
from ..utils.config import ScanConfig
from ..utils.logger import get_logger


class ScannerEngine:
    """Главный движок сканирования"""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.logger = get_logger()
        self.debug_level = getattr(config, 'debug_level', 0)
        self.registry = VectorRegistry()
        self.analyzer = LogicalAnalyzer(self.registry)
        self.aggregator = ResultAggregator()
        self.progress_bar = ProgressBar()
        self.shutdown_requested = False

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        self.debug_log(1, "Scanner initialized")

    def _signal_handler(self, signum, frame):
        """Обработчик сигналов для graceful shutdown"""
        self.logger.warning("\n[!] Shutdown requested, finishing current checks...")
        self.shutdown_requested = True

    def debug_log(self, level: int, message: str):
        """Выводит debug логи если debug_level >= level"""
        if self.debug_level >= level:
            print(f"[DEBUG] {message}")

    def _execute_check(self, vector: Vector) -> VectorResult:
        """Выполнение многофакторной проверки вектора.

        Каждый вектор имеет список check_functions.
        Выполняем все проверки и вычисляем confidence score.
        """
        if self.shutdown_requested:
            return VectorResult(vector.id, vector.name, 0, len(vector.check_functions), 0.0, False, ["Skipped: shutdown requested"], "INFO")

        checks_passed = 0
        checks_results = []

        for check_func_name in vector.check_functions:
            try:
                check_fn = self._load_check_module(check_func_name)
                if not check_fn:
                    checks_results.append(f"✗ Check function not implemented: {check_func_name}")
                    continue

                # Выполняем проверку
                result: Any
                kwargs: Dict[str, Any] = {}
                try:
                    sig = inspect.signature(check_fn)
                    if "port_scan_timeout" in sig.parameters:
                        kwargs["port_scan_timeout"] = self.config.port_scan_timeout
                    if "debug_level" in sig.parameters:
                        kwargs["debug_level"] = self.debug_level
                    if "config" in sig.parameters:
                        kwargs["config"] = self.config
                except (TypeError, ValueError):
                    kwargs = {}

                try:
                    if kwargs:
                        result = check_fn(self.config.target_ip, self.config.adb_port, self.config.timeout, **kwargs)
                    else:
                        result = check_fn(self.config.target_ip, self.config.adb_port, self.config.timeout)
                except TypeError:
                    # Some checks may accept config as 4th positional arg
                    result = check_fn(self.config.target_ip, self.config.adb_port, self.config.timeout, self.config)

                if not isinstance(result, dict):
                    checks_results.append(f"✗ Invalid check result: {check_func_name}")
                    continue

                vulnerable = bool(result.get("vulnerable", False))
                details = str(result.get("details", "No details"))
                
                if vulnerable:
                    checks_passed += 1
                    checks_results.append(f"✓ {details}")
                else:
                    checks_results.append(f"✗ {details}")

            except (concurrent.futures.TimeoutError, TimeoutError):
                checks_results.append(f"✗ Timeout: {check_func_name} exceeded time limit")

            except Exception as e:
                self.logger.debug(f"Error executing {check_func_name}: {e}")
                checks_results.append(f"✗ Error: {str(e)}")

        # Вычисляем confidence score
        total_checks = len(vector.check_functions)
        confidence = (checks_passed / total_checks) * 100 if total_checks > 0 else 0.0
        
        # Вектор считается vulnerable, если confidence >= 1% (даже одна проверка прошла)
        vulnerable = confidence >= 1.0

        return VectorResult(
            vector_id=vector.id,
            vector_name=vector.name,
            checks_passed=checks_passed,
            checks_total=total_checks,
            confidence=confidence,
            vulnerable=vulnerable,
            details=checks_results,
            severity=vector.severity
        )

    def _load_check_module(self, check_function: str):
        """Динамическая загрузка функции проверки"""
        try:
            # NEW: Network Layer checks (vectors 152, 155, 156, 160, 2005, 2506, 4903-4908, 5102)
            network_layer_module = importlib.import_module("aasfa.checks.network_layer_checks")
            if hasattr(network_layer_module, check_function):
                return getattr(network_layer_module, check_function)
            
            # NEW: Crypto Advanced checks (vectors 4800, 4801, 4809, 4905-4907)
            crypto_advanced_module = importlib.import_module("aasfa.checks.crypto_advanced_checks")
            if hasattr(crypto_advanced_module, check_function):
                return getattr(crypto_advanced_module, check_function)
            
            # NEW: Android Advanced Security checks (vectors 2100, 2101, 2106, 2109, 2110, 2115, 3301, 3305, 3318, 3319)
            android_security_module = importlib.import_module("aasfa.checks.android_advanced_security_checks")
            if hasattr(android_security_module, check_function):
                return getattr(android_security_module, check_function)
            
            # NEW: Container/Cloud checks (vectors 3602, 3603, 3604, 2801, 2857, 4304)
            container_cloud_module = importlib.import_module("aasfa.checks.container_cloud_checks")
            if hasattr(container_cloud_module, check_function):
                return getattr(container_cloud_module, check_function)
            
            # NEW: Android Ultra Advanced checks (vectors 4000-4999)
            android_ultra_module = importlib.import_module("aasfa.checks.android_ultra_advanced_checks")
            if hasattr(android_ultra_module, check_function):
                return getattr(android_ultra_module, check_function)
            
            # NEW: Android Advanced checks (vectors 2000-3999)
            android_advanced_module = importlib.import_module("aasfa.checks.android_advanced_checks")
            if hasattr(android_advanced_module, check_function):
                return getattr(android_advanced_module, check_function)
            
            # NEW: Side-channel checks first (vectors 101-200)
            sidechannel_module = importlib.import_module("aasfa.checks.side_channel_checks")
            if hasattr(sidechannel_module, check_function):
                return getattr(sidechannel_module, check_function)

            # Additional side-channel checks (part 2)
            sidechannel_part2_module = importlib.import_module("aasfa.checks.side_channel_checks_part2")
            if hasattr(sidechannel_part2_module, check_function):
                return getattr(sidechannel_part2_module, check_function)

            # NEW: Multifactor checks first (1001-1030)
            multifactor_module = importlib.import_module("aasfa.checks.multifactor_checks")
            if hasattr(multifactor_module, check_function):
                return getattr(multifactor_module, check_function)

            # NEW: Crypto checks (5000+ vectors and shared checks)
            crypto_module = importlib.import_module("aasfa.checks.crypto_checks")
            if hasattr(crypto_module, check_function):
                return getattr(crypto_module, check_function)

            # NEW: API checks (5100+ vectors)
            api_module = importlib.import_module("aasfa.checks.api_checks")
            if hasattr(api_module, check_function):
                return getattr(api_module, check_function)

            # Try deep network checks first (vectors 901-1200)
            if check_function.startswith("check_vector_"):
                module = importlib.import_module("aasfa.checks.deep_network_checks")
                if hasattr(module, check_function):
                    return getattr(module, check_function)

            # Additional vectors (171-300) - use deep network checks
            if check_function in [
                "check_oem_apk_signature_bypass",
                "check_preinstalled_update_mechanism", 
                "check_oem_bloatware_channels",
                "check_hidden_partition_access",
                "check_oem_recovery_verification",
                "check_bootloader_unlock_mechanism",
                "check_fastboot_protocol_server",
                "check_oem_debug_remnants",
                "check_factory_image_leakage",
                "check_oem_security_patches",
                "check_vulnerability_disclosure",
                "check_cve_patch_availability",
                "check_zero_day_handling",
                "check_exploit_deployment",
                "check_intrusion_detection",
                "check_threat_hunting_infra",
                "check_info_hiding_detection",
                "check_adaptive_connectivity",
                "check_network_sleep_patterns",
                "check_background_sync_leakage",
                "check_oem_diagnostic_tcp",
                "check_vendor_diagnostic_services",
                "check_websocket_unauthorized",
                "check_rtsp_exposure_advanced",
                "check_tftp_read_advanced",
                "check_sip_exposure_advanced",
                "check_dlna_exposure_advanced",
                "check_chromecast_debug_advanced",
                "check_bluetooth_pan_advanced",
                "check_wifi_direct_abuse_advanced",
                "check_ai_model_inference",
                "check_ml_data_leakage",
                "check_nn_model_theft",
                "check_adversarial_vectors",
                "check_ai_bias_detection",
                "check_federated_learning_privacy",
                "check_edge_ai_tampering",
                "check_rl_exploits",
                "check_cv_attack_surface",
                "check_nlp_injection",
                "check_speech_bypass",
                "check_ai_anomaly_detection",
                "check_deepfake_pipeline",
                "check_ai_version_control",
                "check_intelligent_orchestration",
                "check_ai_security_monitoring",
                "check_predictive_maintenance",
                "check_smart_device_ai",
                "check_automated_decision_making",
                "check_ai_interpretability",
                "check_data_poisoning",
                "check_ai_redundancy",
                "check_intelligent_traffic",
                "check_ai_penetration_testing",
                "check_ml_security_metrics",
                "check_ai_cognitive_security",
                "check_swarm_attacks",
                "check_ai_watermarking",
                "check_intelligent_healing",
                "check_ai_cyber_defense",
                "check_automated_vuln_discovery",
                "check_ai_robustness",
                "check_intelligent_logging",
                "check_ai_social_engineering",
                "check_cognitive_computing",
                "check_ai_privacy_audit",
                "check_intelligent_incident_response",
                "check_ai_threat_intelligence",
                "check_ml_model_stealing",
                "check_ai_calibration",
                "check_intelligent_optimization",
                "check_ai_attack_automation",
                "check_nn_pruning_attacks",
                "check_ai_quantization_exploits",
                "check_intelligent_scalability",
                "check_ai_compression_vulns",
                "check_federated_inference_attacks",
                "check_ai_adversarial_training",
                "check_intelligent_load_balancing",
                "check_ai_transfer_risks",
                "check_nas_attacks",
                "check_ai_distillation_exploits",
                "check_intelligent_degradation",
                "check_ai_uncertainty",
                "check_swarm_learning_security",
                "check_ai_generalization_gap",
                "check_intelligent_fault_tolerance",
                "check_ai_explainability_attacks",
                "check_nn_ensemble_security",
                "check_ai_malware_evolution",
                "check_intelligent_autoscaling",
                "check_ai_metalearning_vulns",
                "check_rl_security",
                "check_ai_resource_management",
                "check_nn_regularization_attacks",
                "check_ai_continual_learning",
                "check_intelligent_circuit_breakers",
                "check_ai_data_augmentation",
                "check_federated_aggregation_security",
                "check_ai_behavioral_analysis",
                "check_android14_permission_escalation",
                "check_foldable_security_surface",
                "check_5g_slicing_attacks",
                "check_ar_vr_device_security",
                "check_iot_device_bridge",
                "check_android_automotive_security",
                "check_smart_tv_android_exploitation",
                "check_android_wear_security",
                "check_android_tv_security",
                "check_android_gaming_security",
                "check_project_treble_exploitation",
                "check_dynamic_system_updates",
                "check_modular_android_architecture",
                "check_neural_processing_sdk",
                "check_camera2_api_exploitation",
                "check_biometric_prompt_security",
                "check_app_bundle_security",
                "check_dynamic_feature_exploitation",
                "check_instant_apps_security",
                "check_android_enterprise_security",
                "check_zero_touch_provisioning",
                "check_managed_device_security",
                "check_work_profile_security",
                "check_android_safety_center",
                "check_privacy_indicators",
                "check_notification_privacy",
                "check_digital_wellbeing",
                "check_adaptive_battery_security",
                "check_private_compute_core",
                "check_android_security_hub"
            ]:
                module = importlib.import_module("aasfa.checks.deep_network_checks")
                if hasattr(module, check_function):
                    return getattr(module, check_function)

            # Original network checks
            module_map = {
                "check_vnc_availability": ("aasfa.checks.network_checks", "check_vnc_availability"),
                "check_rdp_availability": ("aasfa.checks.network_checks", "check_rdp_availability"),
                "check_ssh_open": ("aasfa.checks.network_checks", "check_ssh_open"),
                "check_telnet_presence": ("aasfa.checks.network_checks", "check_telnet_presence"),
                "check_adb_over_tcp_network": ("aasfa.checks.network_checks", "check_adb_over_tcp_network"),
                "check_upnp_exposure": ("aasfa.checks.network_checks", "check_upnp_exposure"),
                "check_mdns_exposure": ("aasfa.checks.network_checks", "check_mdns_exposure"),
                "check_http_admin_panels": ("aasfa.checks.network_checks", "check_http_admin_panels"),
                "check_https_without_hsts": ("aasfa.checks.network_checks", "check_https_without_hsts"),
                "check_ftp_anonymous": ("aasfa.checks.network_checks", "check_ftp_anonymous"),
                "check_mqtt_exposure": ("aasfa.checks.network_checks", "check_mqtt_exposure"),
                "check_rtsp_exposure": ("aasfa.checks.network_checks", "check_rtsp_exposure"),
                "check_websocket_unauth": ("aasfa.checks.network_checks", "check_websocket_unauth"),
                "check_tftp_read_access": ("aasfa.checks.network_checks", "check_tftp_read_access"),
                "check_sip_exposure": ("aasfa.checks.network_checks", "check_sip_exposure"),
                "check_snmp_open_community": ("aasfa.checks.network_checks", "check_snmp_open_community"),
                "check_dlna_exposure": ("aasfa.checks.network_checks", "check_dlna_exposure"),
            }

            if check_function in module_map:
                module_name, func_name = module_map[check_function]
                module = importlib.import_module(module_name)
                return getattr(module, func_name)

            # Stub checks for ADB and other checks
            stub_module = importlib.import_module("aasfa.checks.stub_checks")
            if hasattr(stub_module, check_function):
                return getattr(stub_module, check_function)

            return None

        except Exception as e:
            self.logger.debug(f"Failed to load {check_function}: {e}")
            return None

    def _dependency_satisfied(self, vector: Vector, result: ScanResult) -> bool:
        """Whether this vector satisfied dependency checks for dependent vectors."""

        if vector.id == 6:
            return bool(result.vulnerable)

        return True

    def _format_live_line(self, vector: Vector, result) -> str:
        """Format a result line for live display - handles both ScanResult and VectorResult"""
        # Only show vulnerabilities (vulnerable=True)
        if not result.vulnerable:
            return ""

        # Safely convert details to string (handles list or string)
        details_str = ""
        try:
            if hasattr(result, 'details'):
                if isinstance(result.details, list):
                    details_str = " ".join(str(d) for d in result.details) if result.details else ""
                else:
                    details_str = str(result.details)
        except Exception as e:
            details_str = f"Error formatting details: {str(e)}"
        
        details_lower = details_str.lower()

        if details_lower.startswith("skipped"):
            return OutputFormatter.format_result_line(vector.id, vector.name, status='*')

        if details_lower.startswith("error"):
            return OutputFormatter.format_result_line(vector.id, vector.name, status='!')

        if result.vulnerable:
            status = '+' if result.severity != 'INFO' else '!'
            return OutputFormatter.format_result_line(vector.id, vector.name, status=status, severity=result.severity)

        return ""

    def _execute_check_with_timeout(self, vector: Vector) -> ScanResult:
        """Wrapper for executor submission.

        Note: ThreadPoolExecutor cannot forcibly stop a stuck thread.
        This wrapper is used so we can evolve additional safeguards in one place.
        """
        return self._execute_check(vector)

    def _handle_completed_vector(self, vector: Vector, result: ScanResult, pending: list[Vector], completed_count: int) -> int:
        # Track all checks performed
        self.aggregator.add_check_performed(result)

        # Only process vulnerable results for display and aggregation
        if result.vulnerable:
            self.aggregator.add_result(result)
            live_line = self._format_live_line(vector, result)
            if live_line:
                self.progress_bar.write_line(live_line)

        self.analyzer.mark_completed(vector.id, self._dependency_satisfied(vector, result))

        if vector in pending:
            pending.remove(vector)

        completed_count += 1
        self.progress_bar.update(completed_count)
        return completed_count

    def _process_priority_batch(self, executor: ThreadPoolExecutor, batch: list[Vector], completed_count: int) -> int:
        pending = batch.copy()

        while pending and not self.shutdown_requested:
            ready_vectors = self.analyzer.get_next_vectors(pending)

            if not ready_vectors:
                for vector in pending[:]:
                    skipped = ScanResult(
                        vector.id,
                        vector.name,
                        False,
                        f"Skipped: unmet dependencies {vector.depends_on}",
                        "INFO",
                    )
                    completed_count = self._handle_completed_vector(vector, skipped, pending, completed_count)
                break

            batch_size = min(len(ready_vectors), self.config.threads * 2)
            work = ready_vectors[:batch_size]

            futures: dict[concurrent.futures.Future[ScanResult], Vector] = {}
            processed: set[concurrent.futures.Future[ScanResult]] = set()

            for vector in work:
                self.debug_log(2, f"Submitting VECTOR_{vector.id:03d} to executor")
                futures[executor.submit(self._execute_check_with_timeout, vector)] = vector

            try:
                for future in as_completed(futures, timeout=self.config.thread_timeout):
                    processed.add(future)
                    vector = futures[future]

                    try:
                        result = future.result(timeout=0)
                    except Exception as e:
                        result = ScanResult(vector.id, vector.name, False, f"Error: {e}", "INFO")

                    completed_count = self._handle_completed_vector(vector, result, pending, completed_count)

            except concurrent.futures.TimeoutError:
                # Some futures did not complete in time. Process finished ones first,
                # then mark the rest as timed out.
                for future, vector in list(futures.items()):
                    if future in processed:
                        continue

                    if future.done():
                        try:
                            result = future.result(timeout=0)
                        except Exception as e:
                            result = ScanResult(vector.id, vector.name, False, f"Error: {e}", "INFO")
                    else:
                        future.cancel()
                        result = ScanResult(
                            vector.id,
                            vector.name,
                            False,
                            "Timeout: check exceeded time limit",
                            "INFO",
                        )

                    completed_count = self._handle_completed_vector(vector, result, pending, completed_count)

        return completed_count

    def scan(self) -> ResultAggregator:
        """Запуск сканирования"""

        # STAGE 2: Loading vectors
        self.debug_log(1, "Loading vectors...")
        all_vectors = self.registry.get_all_vectors()
        if self.debug_level >= 2:
            for vector in all_vectors:
                self.debug_log(2, f"Loaded vector: {vector.id:03d} ({vector.name})")
        self.debug_log(1, f"Loaded {len(all_vectors)} vectors")

        # STAGE 3: Filtering vectors
        self.debug_log(1, "Filtering vectors...")
        vectors_to_scan = self.registry.filter_vectors(self.config)

        # ADB vectors already removed - all remaining vectors are network-only

        sorted_vectors = self.analyzer.get_execution_order(vectors_to_scan)
        total_vectors = len(sorted_vectors)
        self.debug_log(1, f"Filtered to {total_vectors} vectors (mode: {self.config.mode.upper()})")

        print(OutputFormatter.format_scan_context(self.config.target_ip, self.config.mode, total_vectors), end="")

        # STAGE 4: Starting scanner
        self.debug_log(1, "Starting scanner...")

        self.progress_bar.start(total_vectors)

        # STAGE 5: Creating thread pool
        self.debug_log(1, f"Creating thread pool ({self.config.threads} workers)")

        # Split by priority for predictable fast start
        priority_1 = [v for v in sorted_vectors if v.priority == 1]
        priority_2 = [v for v in sorted_vectors if v.priority == 2]
        priority_3 = [v for v in sorted_vectors if v.priority >= 3]

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            completed_count = 0

            # STAGE 6/7: Processing results in priority batches with timeouts
            for batch in (priority_1, priority_2, priority_3):
                if self.shutdown_requested:
                    break
                if not batch:
                    continue

                batch_prio = batch[0].priority if batch else 0
                self.debug_log(1, f"Processing priority batch {batch_prio} ({len(batch)} vectors)")
                completed_count = self._process_priority_batch(executor, batch, completed_count)

        self.progress_bar.finish()
        self.aggregator.finish()

        # STAGE 8: Completion
        self.debug_log(1, "Scan completed")

        return self.aggregator
