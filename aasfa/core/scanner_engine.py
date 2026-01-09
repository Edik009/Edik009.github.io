"""Scanner Engine - главный движок сканирования."""

from __future__ import annotations

import importlib
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict

from .logical_analyzer import LogicalAnalyzer
from .result_aggregator import ResultAggregator, ScanResult
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
                    "INFO",
                )

            result = check_module(
                self.config.target_ip,
                self.config.adb_port,
                self.config.timeout,
            )

            vulnerable = bool(result.get("vulnerable", False))
            details = str(result.get("details", "No details"))
            severity = str(result.get("severity", "INFO"))

            return ScanResult(vector.id, vector.name, vulnerable, details, severity)

        except Exception as e:
            self.logger.debug(f"Error executing {vector.name}: {e}")
            return ScanResult(
                vector.id,
                vector.name,
                False,
                f"Error: {str(e)}",
                "INFO",
            )

    def _load_check_module(self, check_function: str):
        """Динамическая загрузка функции проверки"""
        try:
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
                "check_upnp_exposure": ("aasfa.checks.network_checks", "check_upnp_exposure"),
                "check_mdns_exposure": ("aasfa.checks.network_checks", "check_mdns_exposure"),
                "check_http_admin_panels": ("aasfa.checks.network_checks", "check_http_admin_panels"),
                "check_https_without_hsts": ("aasfa.checks.network_checks", "check_https_without_hsts"),
                "check_ftp_anonymous": ("aasfa.checks.network_checks", "check_ftp_anonymous"),
                "check_mqtt_exposure": ("aasfa.checks.network_checks", "check_mqtt_exposure"),
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

    def _format_live_line(self, vector: Vector, result: ScanResult) -> str:
        # Only show vulnerabilities (vulnerable=True)
        if not result.vulnerable:
            return ""

        if result.details.lower().startswith("skipped"):
            return OutputFormatter.format_result_line(vector.id, vector.name, status='*')

        if result.details.lower().startswith("error"):
            return OutputFormatter.format_result_line(vector.id, vector.name, status='!')

        if result.vulnerable:
            status = '+' if result.severity != 'INFO' else '!'
            return OutputFormatter.format_result_line(vector.id, vector.name, status=status, severity=result.severity)

        return ""

    def scan(self) -> ResultAggregator:
        """Запуск сканирования"""

        vectors_to_scan = self.registry.filter_vectors(self.config)

        # Skip ADB vectors - network-only analysis
        vectors_to_scan = [v for v in vectors_to_scan if not v.requires_adb]

        sorted_vectors = self.analyzer.get_execution_order(vectors_to_scan)
        total_vectors = len(sorted_vectors)

        print(OutputFormatter.format_scan_context(self.config.target_ip, self.config.mode, total_vectors), end="")

        self.progress_bar.start(total_vectors)

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            pending = sorted_vectors.copy()
            completed_count = 0

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
                        self.aggregator.add_result(skipped)
                        self.analyzer.mark_completed(vector.id, False)
                        completed_count += 1
                        self.progress_bar.current = completed_count
                        self.progress_bar.write_line(self._format_live_line(vector, skipped))
                        pending.remove(vector)
                    break

                batch_size = min(len(ready_vectors), self.config.threads * 2)
                batch = ready_vectors[:batch_size]

                futures = {executor.submit(self._execute_check, vector): vector for vector in batch}

                for future in as_completed(futures):
                    vector = futures[future]

                    try:
                        result = future.result(timeout=self.config.timeout)
                    except Exception as e:
                        result = ScanResult(vector.id, vector.name, False, f"Error: {e}", "INFO")

                    # Track all checks performed
                    self.aggregator.add_check_performed(result)

                    # Only process vulnerable results for display and aggregation
                    if result.vulnerable:
                        self.aggregator.add_result(result)
                        # Display vulnerabilities in live output
                        live_line = self._format_live_line(vector, result)
                        if live_line:
                            self.progress_bar.write_line(live_line)

                    self.analyzer.mark_completed(vector.id, self._dependency_satisfied(vector, result))

                    completed_count += 1
                    self.progress_bar.current = completed_count

                    if vector in pending:
                        pending.remove(vector)

        self.progress_bar.finish()
        self.aggregator.finish()
        return self.aggregator
