"""
D. Additional Android Security Vectors (171-300)
130 новых векторов атак для Android 2026
"""
from typing import Dict, Any, List


def get_additional_vectors() -> Dict[int, Dict[str, Any]]:
    """Возвращает все дополнительные векторы (171-300)"""

    vectors = {}

    # OEM и Supply Chain безопасность (171-220, 50 векторов)
    oem_vectors = [
        (171, "OEM APK Signature Validation Bypass", "Проверка обхода валидации подписи OEM APK", "check_oem_apk_signature_bypass", "CRITICAL"),
        (172, "Pre-installed App Update Mechanism", "Анализ механизма обновления предустановленных приложений", "check_preinstalled_update_mechanism", "HIGH"),
        (173, "OEM Bloatware Update Channels", "Каналы обновления OEM bloatware", "check_oem_bloatware_channels", "HIGH"),
        (174, "Hidden Partition Access Inference", "Определение доступа к скрытым разделам", "check_hidden_partition_access", "CRITICAL"),
        (175, "OEM Recovery Image Verification", "Проверка верификации образа OEM recovery", "check_oem_recovery_verification", "CRITICAL"),
        (176, "Bootloader Unlock Mechanism", "Анализ механизма разблокировки загрузчика", "check_bootloader_unlock_mechanism", "CRITICAL"),
        (177, "Fastboot Protocol Server Presence", "Наличие сервера протокола Fastboot", "check_fastboot_protocol_server", "HIGH"),
        (178, "OEM Debug Interface Remnants", "Остатки OEM отладочных интерфейсов", "check_oem_debug_remnants", "HIGH"),
        (179, "Factory Image Distribution Leakage", "Утечка дистрибуции образов заводской установки", "check_factory_image_leakage", "MEDIUM"),
        (180, "OEM Security Patch Deployment", "Развертывание OEM патчей безопасности", "check_oem_security_patches", "HIGH"),
        (181, "Vulnerability Disclosure Patterns", "Паттерны раскрытия уязвимостей", "check_vulnerability_disclosure", "MEDIUM"),
        (182, "CVE Patch Availability Inference", "Вывод о доступности CVE патчей", "check_cve_patch_availability", "MEDIUM"),
        (183, "Zero-day Handling Procedures", "Процедуры обработки zero-day уязвимостей", "check_zero_day_handling", "LOW"),
        (184, "Exploit Deployment Detection", "Обнаружение развертывания эксплойтов", "check_exploit_deployment", "HIGH"),
        (185, "Intrusion Detection Patterns", "Паттерны обнаружения вторжений", "check_intrusion_detection", "MEDIUM"),
        (186, "Threat Hunting Infrastructure", "Инфраструктура охоты за угрозами", "check_threat_hunting_infra", "MEDIUM"),
        (187, "Information Hiding Detection", "Обнаружение сокрытия информации", "check_info_hiding_detection", "LOW"),
        (188, "Adaptive Connectivity Profiling", "Профилирование адаптивного подключения", "check_adaptive_connectivity", "MEDIUM"),
        (189, "Network Sleep Pattern Inference", "Вывод паттернов сна сети", "check_network_sleep_patterns", "MEDIUM"),
        (190, "Background Sync Cadence Leakage", "Утечка ритма фоновой синхронизации", "check_background_sync_leakage", "MEDIUM"),
        (191, "OEM Diagnostic TCP Ports", "OEM диагностические TCP порты", "check_oem_diagnostic_tcp", "HIGH"),
        (192, "Vendor Diagnostic Services", "Диагностические сервисы вендора", "check_vendor_diagnostic_services", "HIGH"),
        (193, "WebSocket Unauthorized Access", "Неавторизованный доступ к WebSocket", "check_websocket_unauthorized", "HIGH"),
        (194, "RTSP Exposure", "Экспозиция RTSP протокола", "check_rtsp_exposure_advanced", "HIGH"),
        (195, "TFTP Read Access", "Доступ для чтения через TFTP", "check_tftp_read_advanced", "HIGH"),
        (196, "SIP Exposure", "Экспозиция SIP протокола", "check_sip_exposure_advanced", "MEDIUM"),
        (197, "DLNA Exposure", "Экспозиция DLNA сервисов", "check_dlna_exposure_advanced", "MEDIUM"),
        (198, "Chromecast Debug Mode", "Режим отладки Chromecast", "check_chromecast_debug_advanced", "MEDIUM"),
        (199, "Bluetooth PAN Exposure", "Экспозиция Bluetooth PAN", "check_bluetooth_pan_advanced", "MEDIUM"),
        (200, "WiFi Direct Abuse", "Злоупотребление WiFi Direct", "check_wifi_direct_abuse_advanced", "MEDIUM"),
    ]

    # AI и System Intelligence (201-270, 70 векторов)
    ai_vectors = [
        (201, "AI Model Inference Pipeline", "Инференс пайплайн AI моделей", "check_ai_model_inference", "HIGH"),
        (202, "Machine Learning Data Leakage", "Утечка данных машинного обучения", "check_ml_data_leakage", "CRITICAL"),
        (203, "Neural Network Model Theft", "Кража моделей нейронных сетей", "check_nn_model_theft", "CRITICAL"),
        (204, "Adversarial Attack Vectors", "Векторы состязательных атак", "check_adversarial_vectors", "HIGH"),
        (205, "AI Bias Detection", "Обнаружение предвзятости AI", "check_ai_bias_detection", "MEDIUM"),
        (206, "Federated Learning Privacy", "Приватность федеративного обучения", "check_federated_learning_privacy", "HIGH"),
        (207, "Edge AI Model Tampering", "Подмена моделей Edge AI", "check_edge_ai_tampering", "HIGH"),
        (208, "Reinforcement Learning Exploits", "Эксплойты обучения с подкреплением", "check_rl_exploits", "HIGH"),
        (209, "Computer Vision Attack Surface", "Поверхность атаки компьютерного зрения", "check_cv_attack_surface", "HIGH"),
        (210, "Natural Language Processing Injection", "Инъекции в обработку естественного языка", "check_nlp_injection", "HIGH"),
        (211, "Speech Recognition Bypass", "Обход распознавания речи", "check_speech_bypass", "MEDIUM"),
        (212, "AI-Driven Anomaly Detection", "AI-обнаружение аномалий", "check_ai_anomaly_detection", "MEDIUM"),
        (213, "Deepfake Generation Pipeline", "Пайплайн генерации deepfake", "check_deepfake_pipeline", "HIGH"),
        (214, "AI Model Version Control", "Контроль версий AI моделей", "check_ai_version_control", "MEDIUM"),
        (215, "Intelligent System Orchestration", "Оркестрация интеллектуальных систем", "check_intelligent_orchestration", "HIGH"),
        (216, "AI Security Monitoring", "Мониторинг безопасности AI", "check_ai_security_monitoring", "MEDIUM"),
        (217, "Predictive Maintenance Attacks", "Атаки на предиктивное обслуживание", "check_predictive_maintenance", "HIGH"),
        (218, "Smart Device AI Integration", "AI интеграция умных устройств", "check_smart_device_ai", "MEDIUM"),
        (219, "Automated Decision Making", "Автоматизированное принятие решений", "check_automated_decision_making", "HIGH"),
        (220, "AI Model Interpretability", "Интерпретируемость AI моделей", "check_ai_interpretability", "MEDIUM"),
        (221, "Data Poisoning Detection", "Обнаружение отравления данных", "check_data_poisoning", "HIGH"),
        (222, "AI System Redundancy", "Избыточность AI систем", "check_ai_redundancy", "MEDIUM"),
        (223, "Intelligent Traffic Analysis", "Интеллектуальный анализ трафика", "check_intelligent_traffic", "MEDIUM"),
        (224, "AI-Enhanced Penetration Testing", "AI-усиленное тестирование проникновения", "check_ai_penetration_testing", "HIGH"),
        (225, "Machine Learning Security Metrics", "Метрики безопасности машинного обучения", "check_ml_security_metrics", "MEDIUM"),
        (226, "AI Cognitive Security", "Когнитивная безопасность AI", "check_ai_cognitive_security", "HIGH"),
        (227, "Swarm Intelligence Attacks", "Атаки на роевой интеллект", "check_swarm_attacks", "HIGH"),
        (228, "AI Model Watermarking", "Водяные знаки AI моделей", "check_ai_watermarking", "LOW"),
        (229, "Intelligent System Healing", "Самовосстановление интеллектуальных систем", "check_intelligent_healing", "MEDIUM"),
        (230, "AI-Driven Cyber Defense", "AI-управляемая киберзащита", "check_ai_cyber_defense", "HIGH"),
        (231, "Automated Vulnerability Discovery", "Автоматическое обнаружение уязвимостей", "check_automated_vuln_discovery", "HIGH"),
        (232, "AI Model Robustness Testing", "Тестирование устойчивости AI моделей", "check_ai_robustness", "MEDIUM"),
        (233, "Intelligent System Logging", "Интеллектуальное логирование систем", "check_intelligent_logging", "MEDIUM"),
        (234, "AI-Assisted Social Engineering", "AI-ассистированная социальная инженерия", "check_ai_social_engineering", "HIGH"),
        (235, "Cognitive Computing Security", "Безопасность когнитивных вычислений", "check_cognitive_computing", "MEDIUM"),
        (236, "AI Model Privacy Auditing", "Аудит приватности AI моделей", "check_ai_privacy_audit", "MEDIUM"),
        (237, "Intelligent Incident Response", "Интеллектуальное реагирование на инциденты", "check_intelligent_incident_response", "HIGH"),
        (238, "AI-Enhanced Threat Intelligence", "AI-усиленная разведка угроз", "check_ai_threat_intelligence", "HIGH"),
        (239, "Machine Learning Model Stealing", "Кража моделей машинного обучения", "check_ml_model_stealing", "CRITICAL"),
        (240, "AI System Calibration", "Калибровка AI систем", "check_ai_calibration", "MEDIUM"),
        (241, "Intelligent System Optimization", "Оптимизация интеллектуальных систем", "check_intelligent_optimization", "MEDIUM"),
        (242, "AI-Driven Attack Automation", "AI-управляемая автоматизация атак", "check_ai_attack_automation", "CRITICAL"),
        (243, "Neural Network Pruning Attacks", "Атаки на прореживание нейронных сетей", "check_nn_pruning_attacks", "HIGH"),
        (244, "AI Model Quantization Exploits", "Эксплойты квантизации AI моделей", "check_ai_quantization_exploits", "HIGH"),
        (245, "Intelligent System Scalability", "Масштабируемость интеллектуальных систем", "check_intelligent_scalability", "MEDIUM"),
        (246, "AI Model Compression Vulnerabilities", "Уязвимости сжатия AI моделей", "check_ai_compression_vulns", "HIGH"),
        (247, "Federated Learning Inference Attacks", "Атаки вывода федеративного обучения", "check_federated_inference_attacks", "HIGH"),
        (248, "AI System Adversarial Training", "Состязательное обучение AI систем", "check_ai_adversarial_training", "MEDIUM"),
        (249, "Intelligent System Load Balancing", "Балансировка нагрузки интеллектуальных систем", "check_intelligent_load_balancing", "MEDIUM"),
        (250, "AI Model Transfer Learning Risks", "Риски переноса обучения AI моделей", "check_ai_transfer_risks", "HIGH"),
        (251, "Neural Architecture Search Attacks", "Атаки на поиск нейронных архитектур", "check_nas_attacks", "HIGH"),
        (252, "AI Model Distillation Exploits", "Эксплойты дистилляции AI моделей", "check_ai_distillation_exploits", "HIGH"),
        (253, "Intelligent System Graceful Degradation", "Плавная деградация интеллектуальных систем", "check_intelligent_degradation", "MEDIUM"),
        (254, "AI Model Uncertainty Quantification", "Квантификация неопределенности AI моделей", "check_ai_uncertainty", "MEDIUM"),
        (255, "Swarm Learning Security", "Безопасность роевого обучения", "check_swarm_learning_security", "HIGH"),
        (256, "AI Model Generalization Gap", "Разрыв обобщения AI моделей", "check_ai_generalization_gap", "MEDIUM"),
        (257, "Intelligent System Fault Tolerance", "Отказоустойчивость интеллектуальных систем", "check_intelligent_fault_tolerance", "MEDIUM"),
        (258, "AI Model Explainability Attacks", "Атаки на объяснимость AI моделей", "check_ai_explainability_attacks", "HIGH"),
        (259, "Neural Network Ensemble Security", "Безопасность ансамблей нейронных сетей", "check_nn_ensemble_security", "HIGH"),
        (260, "AI-Driven Malware Evolution", "AI-управляемая эволюция вредоносного ПО", "check_ai_malware_evolution", "CRITICAL"),
        (261, "Intelligent System Auto-scaling", "Авто-масштабирование интеллектуальных систем", "check_intelligent_autoscaling", "MEDIUM"),
        (262, "AI Model Meta-Learning Vulnerabilities", "Уязвимости мета-обучения AI", "check_ai_metalearning_vulns", "HIGH"),
        (263, "Reinforcement Learning Security", "Безопасность обучения с подкреплением", "check_rl_security", "HIGH"),
        (264, "AI System Resource Management", "Управление ресурсами AI систем", "check_ai_resource_management", "MEDIUM"),
        (265, "Neural Network Regularization Attacks", "Атаки регуляризации нейронных сетей", "check_nn_regularization_attacks", "HIGH"),
        (266, "AI Model Continual Learning", "Непрерывное обучение AI моделей", "check_ai_continual_learning", "MEDIUM"),
        (267, "Intelligent System Circuit Breakers", "Автоматические выключатели интеллектуальных систем", "check_intelligent_circuit_breakers", "MEDIUM"),
        (268, "AI Model Data Augmentation Security", "Безопасность дополнения данных AI моделей", "check_ai_data_augmentation", "HIGH"),
        (269, "Federated Learning Aggregation Security", "Безопасность агрегации федеративного обучения", "check_federated_aggregation_security", "HIGH"),
        (270, "AI System Behavioral Analysis", "Поведенческий анализ AI систем", "check_ai_behavioral_analysis", "MEDIUM"),
    ]

    # Modern Android Security (271-300, 30 векторов)
    modern_vectors = [
        (271, "Android 14 Permission Escalation", "Эскалация разрешений Android 14", "check_android14_permission_escalation", "CRITICAL"),
        (272, "Foldable Device Security Surface", "Поверхность безопасности складных устройств", "check_foldable_security_surface", "HIGH"),
        (273, "5G Network Slicing Attacks", "Атаки на сегментацию сети 5G", "check_5g_slicing_attacks", "HIGH"),
        (274, "AR/VR Device Security", "Безопасность AR/VR устройств", "check_ar_vr_device_security", "HIGH"),
        (275, "IoT Device Bridge Exploitation", "Эксплуатация мостов IoT устройств", "check_iot_device_bridge", "HIGH"),
        (276, "Android Automotive Security", "Безопасность Android Automotive", "check_android_automotive_security", "CRITICAL"),
        (277, "Smart TV Android Exploitation", "Эксплуатация Android Smart TV", "check_smart_tv_android_exploitation", "HIGH"),
        (278, "Android Wear Security", "Безопасность Android Wear", "check_android_wear_security", "HIGH"),
        (279, "Android TV Security", "Безопасность Android TV", "check_android_tv_security", "HIGH"),
        (280, "Android Gaming Device Security", "Безопасность игровых Android устройств", "check_android_gaming_security", "MEDIUM"),
        (281, "Project Treble Exploitation", "Эксплуатация Project Treble", "check_project_treble_exploitation", "CRITICAL"),
        (282, "Dynamic System Updates", "Динамические системные обновления", "check_dynamic_system_updates", "HIGH"),
        (283, "Modular Android Architecture", "Модульная архитектура Android", "check_modular_android_architecture", "HIGH"),
        (284, "Neural Processing SDK", "SDK нейронной обработки", "check_neural_processing_sdk", "HIGH"),
        (285, "Android Camera2 API Exploitation", "Эксплуатация Camera2 API", "check_camera2_api_exploitation", "HIGH"),
        (286, "Android BiometricPrompt Security", "Безопасность BiometricPrompt", "check_biometric_prompt_security", "MEDIUM"),
        (287, "Android App Bundle Security", "Безопасность Android App Bundle", "check_app_bundle_security", "HIGH"),
        (288, "Dynamic Feature Module Exploitation", "Эксплуатация динамических модулей", "check_dynamic_feature_exploitation", "HIGH"),
        (289, "Instant Apps Security", "Безопасность Instant Apps", "check_instant_apps_security", "MEDIUM"),
        (290, "Android Enterprise Security", "Безопасность Android Enterprise", "check_android_enterprise_security", "HIGH"),
        (291, "Zero-Touch Provisioning Attacks", "Атаки автоматической подготовки", "check_zero_touch_provisioning", "HIGH"),
        (292, "Android Managed Device Security", "Безопасность управляемых устройств Android", "check_managed_device_security", "HIGH"),
        (293, "Work Profile Security", "Безопасность рабочего профиля", "check_work_profile_security", "MEDIUM"),
        (294, "Android Safety Center", "Центр безопасности Android", "check_android_safety_center", "MEDIUM"),
        (295, "Privacy Indicators", "Индикаторы приватности", "check_privacy_indicators", "LOW"),
        (296, "Notification Privacy", "Приватность уведомлений", "check_notification_privacy", "MEDIUM"),
        (297, "Android Digital Wellbeing", "Цифровое благополучие Android", "check_digital_wellbeing", "LOW"),
        (298, "Adaptive Battery Security", "Безопасность адаптивной батареи", "check_adaptive_battery_security", "MEDIUM"),
        (299, "Android Private Compute Core", "Приватное вычислительное ядро Android", "check_private_compute_core", "HIGH"),
        (300, "Android Security Hub", "Центр безопасности Android", "check_android_security_hub", "MEDIUM"),
    ]

    # Объединяем все векторы
    all_vectors = oem_vectors + ai_vectors + modern_vectors

    for vector_id, name, description, check_func, severity in all_vectors:
        # Определяем категорию
        if vector_id <= 220:
            category = "I"  # OEM & Supply Chain
        elif vector_id <= 270:
            category = "J"  # AI/System Intelligence
        else:
            category = "F"  # Modern Android

        vectors[vector_id] = {
            "id": vector_id,
            "category": category,
            "name": name,
            "description": description,
            "check_functions": [check_func],  # Single check for now
            "requires_adb": False,
            "requires_network": True,
            "priority": 1,
            "depends_on": [],
            "tags": ["advanced", "android2026", "modern"],
            "severity": severity,
            "weights": None,
            "confirmed_threshold": 0.7,
            "inconclusive_threshold": 0.4,
            "check_count": 1,  # Single check for now
        }

    return vectors