"""
C. Application Layer Vectors (101-170)
"""
from typing import Dict, Any


def get_application_vectors() -> Dict[int, Dict[str, Any]]:
    """Возвращает все Application Layer векторы (101-170)"""
    
    vectors = {}
    
    base_vectors = [
        (101, "Hardcoded API Keys", "Захардкоженные API ключи", "check_hardcoded_api_keys"),
        (102, "Hardcoded Secrets", "Захардкоженные секреты", "check_hardcoded_secrets"),
        (103, "OAuth Misconfiguration", "OAuth неправильно настроен", "check_oauth_misconfig"),
        (104, "Token Reuse", "Повторное использование токенов", "check_token_reuse"),
        (105, "JWT Weak Signing", "JWT слабое подписывание", "check_jwt_weak_signing"),
        (106, "JWT None Algorithm", "JWT алгоритм none", "check_jwt_none_alg"),
        (107, "Session Fixation", "Session fixation", "check_session_fixation"),
        (108, "CSRF Absent", "CSRF защита отсутствует", "check_csrf_absent"),
        (109, "Insecure Deeplinks", "Небезопасные deeplinks", "check_insecure_deeplinks"),
        (110, "App Link Hijacking", "App link hijacking", "check_app_link_hijacking"),
        (111, "Custom Scheme Abuse", "Custom scheme abuse", "check_custom_scheme_abuse"),
        (112, "WebView MITM", "WebView MITM уязвимость", "check_webview_mitm"),
        (113, "SSL Pinning Absent", "SSL pinning отсутствует", "check_ssl_pinning_absent"),
        (114, "SSL Pinning Bypass", "SSL pinning bypass возможен", "check_ssl_pinning_bypass"),
        (115, "TrustManager Misconfiguration", "TrustManager неправильно настроен", "check_trustmanager_misconfig"),
        (116, "HostnameVerifier Disabled", "HostnameVerifier отключен", "check_hostnameverifier_disabled"),
        (117, "Insecure Crypto Modes", "Небезопасные криптографические режимы", "check_insecure_crypto_modes"),
        (118, "ECB Usage", "Использование ECB", "check_ecb_usage"),
        (119, "Weak Random", "Слабая генерация случайных чисел", "check_weak_random"),
        (120, "Predictable UUID", "Предсказуемый UUID", "check_predictable_uuid"),
        (121, "Insecure Deserialization", "Небезопасная десериализация", "check_insecure_deserialization"),
        (122, "Unsafe Native Libs", "Небезопасные native библиотеки", "check_unsafe_native_libs"),
        (123, "JNI Boundary Abuse", "JNI boundary abuse", "check_jni_boundary_abuse"),
        (124, "Format String Native", "Format string в native коде", "check_format_string_native"),
        (125, "Use After Free Native", "Use after free в native коде", "check_use_after_free_native"),
        (126, "Race Condition Native", "Race condition в native коде", "check_race_condition_native"),
        (127, "Clipboard Leakage", "Утечка через clipboard", "check_clipboard_leakage"),
        (128, "Screenshot Protection", "Screenshot protection отсутствует", "check_screenshot_protection"),
        (129, "Overlay Attack", "Overlay attack возможна", "check_overlay_attack"),
        (130, "Accessibility Abuse", "Accessibility abuse", "check_accessibility_abuse"),
        (131, "Notification Leak", "Утечка через уведомления", "check_notification_leak"),
        (132, "Intent Extra Leak", "Утечка через Intent extras", "check_intent_extra_leak"),
        (133, "Broadcast Sniffing", "Broadcast sniffing", "check_broadcast_sniffing"),
        (134, "Debug Logging", "Debug логирование включено", "check_debug_logging"),
        (135, "Crash Report Leak", "Утечка через crash reports", "check_crash_report_leak"),
        (136, "Third Party SDK Leak", "Утечка через сторонние SDK", "check_third_party_sdk"),
        (137, "Analytics Leak", "Утечка через analytics", "check_analytics_leak"),
        (138, "Ad SDK Privilege", "Ad SDK излишние привилегии", "check_ad_sdk_privilege"),
        (139, "WebRTC IP Leak", "WebRTC IP утечка", "check_webrtc_ip_leak"),
        (140, "Camera Misuse", "Неправильное использование камеры", "check_camera_misuse"),
        (141, "Microphone Misuse", "Неправильное использование микрофона", "check_mic_misuse"),
        (142, "Sensor Side Channel", "Sensor side channel", "check_sensor_side_channel"),
        (143, "Gyro Keystroke Inference", "Gyro keystroke inference", "check_gyro_keystroke"),
        (144, "Motion Sensor Leak", "Motion sensor утечка", "check_motion_sensor"),
        (145, "Power Inference", "Power inference", "check_power_inference"),
        (146, "Cache Timing Leak", "Cache timing утечка", "check_cache_timing_leak"),
        (147, "ML Model Extraction", "ML model extraction", "check_ml_model_extraction"),
        (148, "Model Inversion", "Model inversion атака", "check_model_inversion"),
        (149, "Local AI Abuse", "Local AI abuse", "check_local_ai_abuse"),
        (150, "LLM Data Leak", "LLM data утечка", "check_llm_data_leak"),
        (151, "Clipboard History", "Clipboard history утечка", "check_clipboard_history"),
        (152, "Autofill Abuse", "Autofill abuse", "check_autofill_abuse"),
        (153, "Password Manager Injection", "Password manager injection", "check_password_manager_injection"),
        (154, "Screenshot OCR", "Screenshot OCR атака", "check_screenshot_ocr"),
        (155, "PDF Renderer Abuse", "PDF renderer abuse", "check_pdf_renderer_abuse"),
        (156, "Media Codec Fuzzing", "Media codec fuzzing", "check_media_codec_fuzz"),
        (157, "Image Parser Attack", "Image parser атака", "check_image_parser_attack"),
        (158, "Audio Codec Attack", "Audio codec атака", "check_audio_codec_attack"),
        (159, "Video Codec Attack", "Video codec атака", "check_video_codec_attack"),
        (160, "Bluetooth App Misuse", "Bluetooth app misuse", "check_bluetooth_app_misuse"),
        (161, "NFC App Misuse", "NFC app misuse", "check_nfc_app_misuse"),
        (162, "Wallet Intent Abuse", "Wallet intent abuse", "check_wallet_intent_abuse"),
        (163, "Payment Deeplink Abuse", "Payment deeplink abuse", "check_payment_deeplink_abuse"),
        (164, "UPI Hijacking", "UPI hijacking", "check_upi_hijacking"),
        (165, "QR Code Abuse", "QR code abuse", "check_qr_code_abuse"),
        (166, "Barcode Scanner Abuse", "Barcode scanner abuse", "check_barcode_scanner_abuse"),
        (167, "Wearable Sync Abuse", "Wearable sync abuse", "check_wearable_sync_abuse"),
        (168, "CarPlay/AA Abuse", "CarPlay/Android Auto abuse", "check_carplay_aa_abuse"),
        (169, "IoT Companion Abuse", "IoT companion abuse", "check_iot_companion_abuse"),
        (170, "App to App Trust", "App to app trust уязвимость", "check_app_to_app_trust"),
    ]
    
    for vector_id, name, description, check_func in base_vectors:
        vectors[vector_id] = {
            "id": vector_id,
            "category": "C",
            "name": name,
            "description": description,
            "check_function": check_func,
            "requires_adb": True,
            "requires_network": False,
            "priority": 3,
            "depends_on": [6],
            "tags": ["application", "app", "software"],
        }
    
    return vectors
