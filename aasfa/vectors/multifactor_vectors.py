"""
Многофакторные векторы (1001-1030)

30 новых многофакторных векторов для professional feasibility assessment.
Каждый вектор имеет 3-7 независимых методов проверки.
"""
from typing import Dict, Any, List


def get_multifactor_vectors() -> Dict[int, Dict[str, Any]]:
    """Возвращает все многофакторные векторы (1001-1030)"""

    vectors = {}

    # Vector 101: Weak SSL/TLS Handshake Detection (5 методов)
    vectors[1001] = {
        "id": 1001,
        "category": "M",
        "name": "Weak SSL/TLS Handshake Detection",
        "description": "Обнаружение слабых TLS handshake конфигураций",
        "check_functions": [
            "check_tls_version_negotiation",
            "check_cipher_preference_order", 
            "check_entropy_clienthello",
            "check_fallback_behavior",
            "check_session_resumption"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["ssl", "tls", "cryptography"],
        "severity": "HIGH",
        "check_count": 5,
    }

    # Vector 102: Weak Cipher Suites (4 метода)
    vectors[1002] = {
        "id": 1002,
        "category": "M", 
        "name": "Weak Cipher Suites",
        "description": "Обнаружение слабых cipher suites",
        "check_functions": [
            "check_deprecated_ciphers",
            "check_cipher_strength",
            "check_grease_handling",
            "check_alpn_consistency"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["ssl", "tls", "cipher"],
        "severity": "HIGH",
        "check_count": 4,
    }

    # Vector 103: HTTP Response Splitting (4 метода)
    vectors[1003] = {
        "id": 1003,
        "category": "M",
        "name": "HTTP Response Splitting",
        "description": "Проверка HTTP response splitting уязвимостей",
        "check_functions": [
            "check_crlf_injection",
            "check_header_folding",
            "check_proxy_discrepancy",
            "check_caching_behavior"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["http", "injection"],
        "severity": "HIGH",
        "check_count": 4,
    }

    # Vector 104: Broken Session Management (5 методов)
    vectors[1004] = {
        "id": 1004,
        "category": "M",
        "name": "Broken Session Management",
        "description": "Обнаружение проблем в управлении сессиями",
        "check_functions": [
            "check_session_fixation",
            "check_cookie_regeneration",
            "check_parallel_sessions",
            "check_token_entropy",
            "check_idle_timeout"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["session", "authentication"],
        "severity": "CRITICAL",
        "check_count": 5,
    }

    # Vector 105: Subdomain Takeover Feasibility (5 методов)
    vectors[1005] = {
        "id": 1005,
        "category": "M",
        "name": "Subdomain Takeover Feasibility",
        "description": "Анализ возможности захвата поддоменов",
        "check_functions": [
            "check_dangling_dns",
            "check_cdn_fingerprint",
            "check_404_patterns",
            "check_tls_san_mismatch",
            "check_cname_orphaning"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["dns", "subdomain", "takeover"],
        "severity": "HIGH",
        "check_count": 5,
    }

    # Vector 106: CSRF Protection Absence (4 метода)
    vectors[1006] = {
        "id": 1006,
        "category": "M",
        "name": "CSRF Protection Absence",
        "description": "Отсутствие защиты от CSRF атак",
        "check_functions": [
            "check_csrf_token_presence",
            "check_csrf_token_entropy",
            "check_origin_referer_logic",
            "check_samesite_cookie"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["csrf", "web", "protection"],
        "severity": "HIGH",
        "check_count": 4,
    }

    # Vector 107: Broken Access Control (5 методов)
    vectors[1007] = {
        "id": 1007,
        "category": "M",
        "name": "Broken Access Control",
        "description": "Нарушения в контроле доступа",
        "check_functions": [
            "check_horizontal_privilege",
            "check_vertical_privilege",
            "check_id_predictability",
            "check_response_size_diff",
            "check_error_semantics"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["authorization", "access", "control"],
        "severity": "CRITICAL",
        "check_count": 5,
    }

    # Vector 108: Directory Traversal (5 методов)
    vectors[1008] = {
        "id": 1008,
        "category": "M",
        "name": "Directory Traversal",
        "description": "Уязвимости directory traversal",
        "check_functions": [
            "check_encoded_traversal",
            "check_unicode_normalization",
            "check_path_canonicalization",
            "check_timing_differences",
            "check_backend_os_inference"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["path", "traversal", "injection"],
        "severity": "HIGH",
        "check_count": 5,
    }

    # Vector 109: XXE Feasibility (4 метода)
    vectors[1009] = {
        "id": 1009,
        "category": "M",
        "name": "XXE Feasibility",
        "description": "Возможность XXE атак",
        "check_functions": [
            "check_xml_parser_behavior",
            "check_entity_resolution_timing",
            "check_oob_callback",
            "check_error_inference"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["xxe", "xml", "injection"],
        "severity": "HIGH",
        "check_count": 4,
    }

    # Vector 110: IDOR - Insecure Direct Object Reference (5 методов)
    vectors[1010] = {
        "id": 1010,
        "category": "M",
        "name": "IDOR - Insecure Direct Object Reference",
        "description": "Небезопасные прямые ссылки на объекты",
        "check_functions": [
            "check_object_id_predictability",
            "check_token_reuse",
            "check_indirect_reference",
            "check_authz_gap",
            "check_data_volume"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["idor", "authorization", "injection"],
        "severity": "CRITICAL",
        "check_count": 5,
    }

    # Vector 111: XSS - Reflected (3 метода)
    vectors[1011] = {
        "id": 1011,
        "category": "M",
        "name": "XSS - Reflected",
        "description": "Отраженные XSS уязвимости",
        "check_functions": [
            "check_html_context",
            "check_javascript_context",
            "check_attribute_context"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["xss", "reflected", "injection"],
        "severity": "HIGH",
        "check_count": 3,
    }

    # Vector 112: XSS - Stored (3 метода)
    vectors[1012] = {
        "id": 1012,
        "category": "M",
        "name": "XSS - Stored",
        "description": "Сохраненные XSS уязвимости",
        "check_functions": [
            "check_persistence",
            "check_reflection_on_output",
            "check_encoding"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["xss", "stored", "injection"],
        "severity": "HIGH",
        "check_count": 3,
    }

    # Vector 113: XSS - DOM (3 метода)
    vectors[1013] = {
        "id": 1013,
        "category": "M",
        "name": "XSS - DOM",
        "description": "DOM-based XSS уязвимости",
        "check_functions": [
            "check_source_sink_pair",
            "check_javascript_execution",
            "check_prototype_pollution"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["xss", "dom", "injection"],
        "severity": "HIGH",
        "check_count": 3,
    }

    # Vector 114: RFI - Remote File Inclusion (3 метода)
    vectors[1014] = {
        "id": 1014,
        "category": "M",
        "name": "RFI - Remote File Inclusion",
        "description": "Удаленное включение файлов",
        "check_functions": [
            "check_file_inclusion",
            "check_remote_scheme",
            "check_wrapper_usage"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["rfi", "inclusion", "injection"],
        "severity": "CRITICAL",
        "check_count": 3,
    }

    # Vector 115: LFI - Local File Inclusion (4 метода)
    vectors[1015] = {
        "id": 1015,
        "category": "M",
        "name": "LFI - Local File Inclusion",
        "description": "Локальное включение файлов",
        "check_functions": [
            "check_directory_traversal_in_inclusion",
            "check_null_byte",
            "check_filter_bypass",
            "check_log_poisoning"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["lfi", "inclusion", "injection"],
        "severity": "HIGH",
        "check_count": 4,
    }

    # Vector 116: Insecure API Key Storage (3 метода)
    vectors[1016] = {
        "id": 1016,
        "category": "M",
        "name": "Insecure API Key Storage",
        "description": "Небезопасное хранение API ключей",
        "check_functions": [
            "check_keys_in_requests",
            "check_keys_in_headers",
            "check_keys_in_responses"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["api", "key", "storage"],
        "severity": "MEDIUM",
        "check_count": 3,
    }

    # Vector 117: Misconfigured HTTP Headers (4 метода)
    vectors[1017] = {
        "id": 1017,
        "category": "M",
        "name": "Misconfigured HTTP Headers",
        "description": "Неправильная настройка HTTP заголовков",
        "check_functions": [
            "check_missing_hsts",
            "check_missing_csp",
            "check_missing_x_frame_options",
            "check_missing_cors_headers"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["http", "headers", "security"],
        "severity": "MEDIUM",
        "check_count": 4,
    }

    # Vector 118: Open Redirect (3 метода)
    vectors[1018] = {
        "id": 1018,
        "category": "M",
        "name": "Open Redirect",
        "description": "Открытые редиректы",
        "check_functions": [
            "check_redirect_parameter",
            "check_javascript_redirect",
            "check_meta_refresh"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["redirect", "open", "injection"],
        "severity": "LOW",
        "check_count": 3,
    }

    # Vector 119: OAuth Flow Misbinding (4 метода)
    vectors[1019] = {
        "id": 1019,
        "category": "M",
        "name": "OAuth Flow Misbinding",
        "description": "Неправильная привязка OAuth потоков",
        "check_functions": [
            "check_state_parameter",
            "check_scope_integrity",
            "check_token_reuse",
            "check_redirect_uri_validation"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["oauth", "authentication", "flow"],
        "severity": "HIGH",
        "check_count": 4,
    }

    # Vector 120: Broken Encryption (3 метода)
    vectors[1020] = {
        "id": 1020,
        "category": "M",
        "name": "Broken Encryption",
        "description": "Сломанное шифрование",
        "check_functions": [
            "check_encryption_algorithm",
            "check_iv_reuse",
            "check_key_derivation"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["encryption", "broken", "crypto"],
        "severity": "HIGH",
        "check_count": 3,
    }

    # Vector 121: Weak Password Hashing (3 метода)
    vectors[1021] = {
        "id": 1021,
        "category": "M",
        "name": "Weak Password Hashing",
        "description": "Слабое хеширование паролей",
        "check_functions": [
            "check_hash_algorithm",
            "check_salt_presence",
            "check_iteration_count"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["password", "hashing", "crypto"],
        "severity": "HIGH",
        "check_count": 3,
    }

    # Vector 122: Insecure Password Storage (3 метода)
    vectors[1022] = {
        "id": 1022,
        "category": "M",
        "name": "Insecure Password Storage",
        "description": "Небезопасное хранение паролей",
        "check_functions": [
            "check_plaintext_passwords",
            "check_reversible_encryption",
            "check_hardcoded_passwords"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["password", "storage", "security"],
        "severity": "CRITICAL",
        "check_count": 3,
    }

    # Vector 123: Sensitive Data Exposure (4 метода)
    vectors[1023] = {
        "id": 1023,
        "category": "M",
        "name": "Sensitive Data Exposure",
        "description": "Раскрытие чувствительных данных",
        "check_functions": [
            "check_https_enforcement",
            "check_caching_sensitive_data",
            "check_logs_contain_sensitive",
            "check_error_messages_leakage"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["sensitive", "data", "exposure"],
        "severity": "HIGH",
        "check_count": 4,
    }

    # Vector 124: Cross-Profile Data Leakage (4 метода)
    vectors[1024] = {
        "id": 1024,
        "category": "M",
        "name": "Cross-Profile Data Leakage",
        "description": "Утечка данных между профилями",
        "check_functions": [
            "check_profile_isolation",
            "check_shared_storage_access",
            "check_intent_exposure",
            "check_broadcast_leakage"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["profile", "leakage", "android"],
        "severity": "HIGH",
        "check_count": 4,
    }

    # Vector 125: Unencrypted Communications (3 метода)
    vectors[1025] = {
        "id": 1025,
        "category": "M",
        "name": "Unencrypted Communications",
        "description": "Незашифрованные коммуникации",
        "check_functions": [
            "check_http_usage",
            "check_unencrypted_protocols",
            "check_mixed_content"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["encryption", "communication", "protocol"],
        "severity": "HIGH",
        "check_count": 3,
    }

    # Vector 126: Insecure Session Tokens (4 метода)
    vectors[1026] = {
        "id": 1026,
        "category": "M",
        "name": "Insecure Session Tokens",
        "description": "Небезопасные токены сессий",
        "check_functions": [
            "check_token_entropy",
            "check_token_length",
            "check_token_reusability",
            "check_token_expiration"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["session", "token", "security"],
        "severity": "MEDIUM",
        "check_count": 4,
    }

    # Vector 127: Unintended File Access (4 метода)
    vectors[1027] = {
        "id": 1027,
        "category": "M",
        "name": "Unintended File Access",
        "description": "Непреднамеренный доступ к файлам",
        "check_functions": [
            "check_backup_files",
            "check_hidden_files",
            "check_source_maps",
            "check_directory_listing"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["file", "access", "discovery"],
        "severity": "LOW",
        "check_count": 4,
    }

    # Vector 128: Unprotected Sensitive Files (4 метода)
    vectors[1028] = {
        "id": 1028,
        "category": "M",
        "name": "Unprotected Sensitive Files",
        "description": "Незащищенные чувствительные файлы",
        "check_functions": [
            "check_config_file_access",
            "check_database_files",
            "check_private_key_files",
            "check_credentials_files"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["files", "sensitive", "access"],
        "severity": "HIGH",
        "check_count": 4,
    }

    # Vector 129: Insecure Backups (3 метода)
    vectors[1029] = {
        "id": 1029,
        "category": "M",
        "name": "Insecure Backups",
        "description": "Небезопасные резервные копии",
        "check_functions": [
            "check_backup_location",
            "check_backup_encryption",
            "check_backup_integrity"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["backup", "security", "data"],
        "severity": "MEDIUM",
        "check_count": 3,
    }

    # Vector 130: Insecure API Endpoints (4 метода)
    vectors[1030] = {
        "id": 1030,
        "category": "M",
        "name": "Insecure API Endpoints",
        "description": "Небезопасные API endpoints",
        "check_functions": [
            "check_missing_auth",
            "check_missing_rate_limiting",
            "check_version_disclosure",
            "check_debug_endpoints"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["api", "endpoint", "security"],
        "severity": "HIGH",
        "check_count": 4,
    }

    return vectors