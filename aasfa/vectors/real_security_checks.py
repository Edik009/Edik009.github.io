"""
Real Security Checks Vectors - Definitions for real security vulnerability checks.

This file contains vector definitions for the new real security check implementations
that perform actual network operations, analysis, and testing instead of stubs.
"""

from typing import Dict, Any

from ..checks.network_layer_checks import (
    check_vector_152_tls_extension_order_fingerprinting,
    check_vector_155_packet_size_pattern_analysis,
    check_vector_156_api_error_semantic_analysis,
    check_vector_160_dns_over_https_fallback_behavior,
    check_vector_2005_arp_spoofing_vulnerability,
    check_vector_2506_api_rate_limiting,
    check_vector_4903_packet_fragmentation_attack,
    check_vector_4904_ip_spoofing_vulnerability,
    check_vector_4907_syn_flood_protection,
    check_vector_4908_udp_flood_vulnerability,
    check_vector_5102_no_rate_limiting
)

from ..checks.crypto_advanced_checks import (
    check_vector_4800_quantum_resistant_crypto,
    check_vector_4809_post_quantum_cryptography,
    check_vector_4905_weak_encryption_strength,
    check_vector_4906_weak_dh_parameters,
    check_vector_4907_tls_hardening_issues,
    check_vector_4801_certificate_chain_analysis
)

from ..checks.android_advanced_security_checks import (
    check_vector_2100_sideload_enabled,
    check_vector_2101_developer_mode_active,
    check_vector_2106_root_access_detected,
    check_vector_2109_old_android_version,
    check_vector_2110_outdated_security_patches,
    check_vector_2115_backup_enabled,
    check_vector_3301_debuggable_apps,
    check_vector_3305_backup_agent_vulnerability,
    check_vector_3318_safetynet_attestation,
    check_vector_3319_play_integrity_api
)

from ..checks.container_cloud_checks import (
    check_vector_3602_container_escape,
    check_vector_3603_privileged_container,
    check_vector_3604_docker_socket_mount,
    check_vector_2801_no_2fa,
    check_vector_2857_side_channel_info_leak,
    check_vector_4304_timing_covert_channel
)


# Real Network Security Vectors
REAL_NETWORK_VECTORS = {
    'VECTOR_152': {
        'name': 'TLS Extension Order Fingerprinting',
        'type': 'Network',
        'severity': 'LOW',
        'check': check_vector_152_tls_extension_order_fingerprinting,
        'description': 'Анализ порядка TLS расширений в ClientHello для определения клиента/браузера.',
        'attacker_can_extract': 'Информацию о типе клиента, версии браузера, используемых библиотеках.',
        'exploitation': 'Создание уникальных TLS отпечатков для отслеживания пользователей.',
        'remediation': 'Стандартизация порядка TLS расширений или использование Tor Browser.'
    },
    'VECTOR_155': {
        'name': 'Packet Size Pattern Analysis',
        'type': 'Network',
        'severity': 'MEDIUM',
        'check': check_vector_155_packet_size_pattern_analysis,
        'description': 'Анализ паттернов размеров пакетов для определения активности.',
        'attacker_can_extract': 'Информацию о типе трафика, приложениях, поведении пользователя.',
        'exploitation': 'Traffic analysis для определения активности даже при шифровании.',
        'remediation': 'Использование padding для выравнивания размеров пакетов.'
    },
    'VECTOR_156': {
        'name': 'API Error Semantic Analysis',
        'type': 'Network',
        'severity': 'HIGH',
        'check': check_vector_156_api_error_semantic_analysis,
        'description': 'Анализ семантики ошибок API для получения информации о системе.',
        'attacker_can_extract': 'Информацию о структуре БД, валидации, системных компонентах.',
        'exploitation': 'Timing attacks, error-based injection, enumeration attacks.',
        'remediation': 'Стандартизация сообщений об ошибках, устранение деталей.'
    },
    'VECTOR_160': {
        'name': 'DNS-over-HTTPS Fallback Behavior',
        'type': 'Network',
        'severity': 'MEDIUM',
        'check': check_vector_160_dns_over_https_fallback_behavior,
        'description': 'Проверка поведения при откате с DoH на plaintext DNS.',
        'attacker_can_extract': 'DNS запросы, если происходит fallback на незашифрованный DNS.',
        'exploitation': 'Блокировка DoH серверов для принудительного fallback.',
        'remediation': 'Настройка fallback политик или блокировка plaintext DNS.'
    },
    'VECTOR_2005': {
        'name': 'ARP Spoofing Vulnerability',
        'type': 'Network',
        'severity': 'MEDIUM',
        'check': check_vector_2005_arp_spoofing_vulnerability,
        'description': 'Проверка уязвимости к ARP spoofing атакам.',
        'attacker_can_extract': 'Трафик между сегментами сети, возможность MITM атак.',
        'exploitation': 'Отправка поддельных ARP пакетов для перехвата трафика.',
        'remediation': 'Использование ARP spoofing protection, static ARP entries.'
    },
    'VECTOR_2506': {
        'name': 'API Rate Limiting',
        'type': 'Network',
        'severity': 'LOW',
        'check': check_vector_2506_api_rate_limiting,
        'description': 'Проверка наличия rate limiting в API endpoints.',
        'attacker_can_extract': 'Возможность brute force атак, enumeration, resource exhaustion.',
        'exploitation': 'Массовые запросы для исчерпания ресурсов или перебора.',
        'remediation': 'Реализация rate limiting, throttling, request queuing.'
    },
    'VECTOR_4903': {
        'name': 'Packet Fragmentation Attack',
        'type': 'Network',
        'severity': 'MEDIUM',
        'check': check_vector_4903_packet_fragmentation_attack,
        'description': 'Проверка обработки фрагментированных пакетов.',
        'attacker_can_extract': 'Возможность обхода IDS/IPS, crash систем, информационные утечки.',
        'exploitation': 'Отправка overlapping или malformed fragments.',
        'remediation': 'Правильная обработка фрагментов, проверка reassembly.'
    },
    'VECTOR_4904': {
        'name': 'IP Spoofing Vulnerability',
        'type': 'Network',
        'severity': 'MEDIUM',
        'check': check_vector_4904_ip_spoofing_vulnerability,
        'description': 'Проверка уязвимости к IP spoofing.',
        'attacker_can_extract': 'Возможность DDoS amplification, bypass фильтров.',
        'exploitation': 'Отправка пакетов с поддельным source IP.',
        'remediation': 'Валидация source IP, ingress filtering, RPF checks.'
    },
    'VECTOR_4907': {
        'name': 'SYN Flood Protection',
        'type': 'Network',
        'severity': 'MEDIUM',
        'check': check_vector_4907_syn_flood_protection,
        'description': 'Проверка защиты от SYN flood атак.',
        'attacker_can_extract': 'Возможность исчерпания ресурсов, service denial.',
        'exploitation': 'Отправка большого количества SYN пакетов без завершения handshake.',
        'remediation': 'SYN cookies, connection limiting, SYN protection.'
    },
    'VECTOR_4908': {
        'name': 'UDP Flood Vulnerability',
        'type': 'Network',
        'severity': 'MEDIUM',
        'check': check_vector_4908_udp_flood_vulnerability,
        'description': 'Проверка уязвимости к UDP flood атакам.',
        'attacker_can_extract': 'Возможность исчерпания ресурсов, bandwidth exhaustion.',
        'exploitation': 'Отправка большого объема UDP пакетов.',
        'remediation': 'Rate limiting, connection tracking, UDP protection.'
    },
    'VECTOR_5102': {
        'name': 'No Rate Limiting',
        'type': 'Network',
        'severity': 'MEDIUM',
        'check': check_vector_5102_no_rate_limiting,
        'description': 'Проверка отсутствия brute force protection.',
        'attacker_can_extract': 'Возможность перебора паролей, credential stuffing.',
        'exploitation': 'Быстрая последовательность запросов к login endpoints.',
        'remediation': 'Rate limiting, account lockout, CAPTCHA, IP blocking.'
    }
}

# Real Cryptographic Security Vectors
REAL_CRYPTO_VECTORS = {
    'VECTOR_4800': {
        'name': 'Quantum Resistant Crypto',
        'type': 'Crypto',
        'severity': 'LOW',
        'check': check_vector_4800_quantum_resistant_crypto,
        'description': 'Проверка использования квантово-устойчивой криптографии.',
        'attacker_can_extract': 'Уязвимость к будущим квантовым компьютерам.',
        'exploitation': 'Harvest now, decrypt later атаки на зашифрованные данные.',
        'remediation': 'Миграция на post-quantum алгоритмы (CRYSTALS-Kyber, Dilithium).'
    },
    'VECTOR_4801': {
        'name': 'Certificate Chain Analysis',
        'type': 'Crypto',
        'severity': 'MEDIUM',
        'check': check_vector_4801_certificate_chain_analysis,
        'description': 'Анализ цепочки сертификатов на уязвимости.',
        'attacker_can_extract': 'Слабые алгоритмы, short keys, неправильную конфигурацию.',
        'exploitation': 'Эксплуатация слабых алгоритмов в цепочке сертификатов.',
        'remediation': 'Использование strong алгоритмов, правильную настройку chain.'
    },
    'VECTOR_4809': {
        'name': 'Post-Quantum Cryptography',
        'type': 'Crypto',
        'severity': 'LOW',
        'check': check_vector_4809_post_quantum_cryptography,
        'description': 'Проверка реализации post-quantum криптографии.',
        'attacker_can_extract': 'Уязвимость к квантовым компьютерам.',
        'exploitation': 'Будущие атаки на RSA/ECDSA с помощью квантовых алгоритмов.',
        'remediation': 'Внедрение PQC алгоритмов, hybrid подходы.'
    },
    'VECTOR_4905': {
        'name': 'Weak Encryption Strength',
        'type': 'Crypto',
        'severity': 'MEDIUM',
        'check': check_vector_4905_weak_encryption_strength,
        'description': 'Проверка слабой криптографической конфигурации.',
        'attacker_can_extract': 'Возможность взлома слабых шифров, short keys.',
        'exploitation': 'Brute force атаки на weak encryption, алгоритмы.',
        'remediation': 'Использование strong шифров, достаточных key sizes.'
    },
    'VECTOR_4906': {
        'name': 'Weak DH Parameters',
        'type': 'Crypto',
        'severity': 'MEDIUM',
        'check': check_vector_4906_weak_dh_parameters,
        'description': 'Проверка слабых Diffie-Hellman параметров.',
        'attacker_can_extract': 'Возможность атак на DH key exchange.',
        'exploitation': 'Атаки на DH parameters, logjam attacks.',
        'remediation': 'Strong DH parameters (2048+ bits), perfect forward secrecy.'
    },
    'VECTOR_4907': {
        'name': 'TLS Hardening Issues',
        'type': 'Crypto',
        'severity': 'MEDIUM',
        'check': check_vector_4907_tls_hardening_issues,
        'description': 'Проверка TLS hardening настроек.',
        'attacker_can_extract': 'Weak ciphers, deprecated protocols, security headers.',
        'exploitation': 'Downgrade атаки, exploitation слабых cipher suites.',
        'remediation': 'Strong TLS configuration, security headers, modern protocols.'
    }
}

# Real Android Security Vectors
REAL_ANDROID_VECTORS = {
    'VECTOR_2100': {
        'name': 'Sideload Enabled',
        'type': 'Android',
        'severity': 'MEDIUM',
        'check': check_vector_2100_sideload_enabled,
        'description': 'Проверка разрешения sideload APK файлов.',
        'attacker_can_extract': 'Возможность установки вредоносных приложений.',
        'exploitation': 'Физический доступ для установки malicious APKs.',
        'remediation': 'Отключение sideload, проверка источников приложений.'
    },
    'VECTOR_2101': {
        'name': 'Developer Mode Active',
        'type': 'Android',
        'severity': 'MEDIUM',
        'check': check_vector_2101_developer_mode_active,
        'description': 'Проверка активного режима разработчика.',
        'attacker_can_extract': 'Расширенные возможности отладки, доступ к debug функциям.',
        'exploitation': 'Использование debug возможностей для analysis.',
        'remediation': 'Отключение developer mode, ограничение debug функций.'
    },
    'VECTOR_2106': {
        'name': 'Root Access Detected',
        'type': 'Android',
        'severity': 'CRITICAL',
        'check': check_vector_2106_root_access_detected,
        'description': 'Обнаружение root доступа на устройстве.',
        'attacker_can_extract': 'Полный контроль над системой, доступ к protected data.',
        'exploitation': 'Эксплуатация root privileges для bypass security.',
        'remediation': 'Удаление root, блокировка bootloader.'
    },
    'VECTOR_2109': {
        'name': 'Old Android Version',
        'type': 'Android',
        'severity': 'HIGH',
        'check': check_vector_2109_old_android_version,
        'description': 'Проверка устаревшей версии Android.',
        'attacker_can_extract': 'Известные уязвимости в старых версиях Android.',
        'exploitation': 'Эксплуатация CVEs в outdated Android versions.',
        'remediation': 'Обновление до latest Android version.'
    },
    'VECTOR_2110': {
        'name': 'Outdated Security Patches',
        'type': 'Android',
        'severity': 'HIGH',
        'check': check_vector_2110_outdated_security_patches,
        'description': 'Проверка устаревших security patches.',
        'attacker_can_extract': 'Known security vulnerabilities без патчей.',
        'exploitation': 'Эксплуатация unpatched security issues.',
        'remediation': 'Установка latest security patches.'
    },
    'VECTOR_2115': {
        'name': 'Backup Enabled',
        'type': 'Android',
        'severity': 'MEDIUM',
        'check': check_vector_2115_backup_enabled,
        'description': 'Проверка включенного backup без шифрования.',
        'attacker_can_extract': 'Sensitive data в unencrypted backups.',
        'exploitation': 'Access к backup данным без encryption.',
        'remediation': 'Включение backup encryption или отключение backup.'
    },
    'VECTOR_3301': {
        'name': 'Debuggable Apps',
        'type': 'Android',
        'severity': 'MEDIUM',
        'check': check_vector_3301_debuggable_apps,
        'description': 'Проверка debuggable приложений.',
        'attacker_can_extract': 'Sensitive data через debug интерфейсы.',
        'exploitation': 'Debugging приложений для extraction данных.',
        'remediation': 'Отключение debug mode в production apps.'
    },
    'VECTOR_3305': {
        'name': 'Backup Agent Vulnerability',
        'type': 'Android',
        'severity': 'MEDIUM',
        'check': check_vector_3305_backup_agent_vulnerability,
        'description': 'Проверка уязвимостей backup agent.',
        'attacker_can_extract': 'Sensitive data через insecure backup mechanisms.',
        'exploitation': 'Exploitation backup agent vulnerabilities.',
        'remediation': 'Secure backup configuration, encryption.'
    },
    'VECTOR_3318': {
        'name': 'SafetyNet Attestation',
        'type': 'Android',
        'severity': 'MEDIUM',
        'check': check_vector_3318_safetynet_attestation,
        'description': 'Проверка SafetyNet attestation failure.',
        'attacker_can_extract': 'Bypass integrity checks для malicious apps.',
        'exploitation': 'Exploitation attestation bypass techniques.',
        'remediation': 'Proper SafetyNet integration, integrity verification.'
    },
    'VECTOR_3319': {
        'name': 'Play Integrity API',
        'type': 'Android',
        'severity': 'MEDIUM',
        'check': check_vector_3319_play_integrity_api,
        'description': 'Проверка Play Integrity API failure.',
        'attacker_can_extract': 'Bypass integrity checks для modified/modded devices.',
        'exploitation': 'Exploitation integrity API bypass.',
        'remediation': 'Proper Play Integrity API usage, device verification.'
    }
}

# Real Container/Cloud Security Vectors
REAL_CONTAINER_VECTORS = {
    'VECTOR_2801': {
        'name': 'No 2FA',
        'type': 'Authentication',
        'severity': 'MEDIUM',
        'check': check_vector_2801_no_2fa,
        'description': 'Проверка отсутствия двухфакторной аутентификации.',
        'attacker_can_extract': 'Возможность credential theft, account compromise.',
        'exploitation': 'Password attacks, credential stuffing, phishing.',
        'remediation': 'Внедрение 2FA/MFA, TOTP, SMS verification.'
    },
    'VECTOR_2857': {
        'name': 'Side-Channel Info Leak',
        'type': 'Side-Channel',
        'severity': 'MEDIUM',
        'check': check_vector_2857_side_channel_info_leak,
        'description': 'Проверка side-channel information leakage.',
        'attacker_can_extract': 'Sensitive information через power, thermal, timing.',
        'exploitation': 'Power analysis, acoustic attacks, timing analysis.',
        'remediation': 'Constant-time algorithms, noise injection, shielding.'
    },
    'VECTOR_3602': {
        'name': 'Container Escape',
        'type': 'Container',
        'severity': 'CRITICAL',
        'check': check_vector_3602_container_escape,
        'description': 'Проверка container escape vulnerabilities.',
        'attacker_can_extract': 'Host system access, other containers data.',
        'exploitation': 'Container escape techniques, kernel exploits.',
        'remediation': 'Container isolation, security profiles, kernel hardening.'
    },
    'VECTOR_3603': {
        'name': 'Privileged Container',
        'type': 'Container',
        'severity': 'HIGH',
        'check': check_vector_3603_privileged_container,
        'description': 'Проверка privileged container execution.',
        'attacker_can_extract': 'Host system access, kernel access.',
        'exploitation': 'Privilege escalation, host compromise.',
        'remediation': 'Avoid privileged containers, use security capabilities.'
    },
    'VECTOR_3604': {
        'name': 'Docker Socket Mount',
        'type': 'Container',
        'severity': 'CRITICAL',
        'check': check_vector_3604_docker_socket_mount,
        'description': 'Проверка exposed Docker socket.',
        'attacker_can_extract': 'Docker daemon access, container creation, host access.',
        'exploitation': 'Docker API exploitation, container creation with host access.',
        'remediation': 'Secure Docker socket, authentication, network isolation.'
    },
    'VECTOR_4304': {
        'name': 'Timing Covert Channel',
        'type': 'Side-Channel',
        'severity': 'LOW',
        'check': check_vector_4304_timing_covert_channel,
        'description': 'Проверка timing-based covert channels.',
        'attacker_can_extract': 'Information через timing variations.',
        'exploitation': 'Timing attacks, covert communication channels.',
        'remediation': 'Constant-time operations, timing randomization.'
    }
}


# Combine all real security vectors
REAL_SECURITY_VECTORS = {
    **REAL_NETWORK_VECTORS,
    **REAL_CRYPTO_VECTORS,
    **REAL_ANDROID_VECTORS,
    **REAL_CONTAINER_VECTORS
}


def get_real_security_vectors() -> Dict[int, Dict[str, Any]]:
    """Get all real security check vectors for registry."""
    vectors = {}
    
    for vector_name, vector_data in REAL_SECURITY_VECTORS.items():
        # Extract vector ID from name (e.g., "VECTOR_152" -> 152)
        vector_id = int(vector_name.split('_')[1])
        
        # Convert to registry format
        vectors[vector_id] = {
            'id': vector_id,
            'category': vector_data['type'],
            'name': vector_data['name'],
            'description': vector_data['description'],
            'check_functions': [vector_data['check'].__name__],
            'priority': 2,  # Medium priority
            'depends_on': [],
            'tags': [vector_data['type'].lower(), 'real-check'],
            'requires_adb': False,
            'requires_network': True,
            'severity': vector_data['severity'],
            'cvss_score': 3.0,  # Default CVSS score
            'exploitation_difficulty': 'Medium',
            'remediation': vector_data.get('remediation', ''),
            'references': []
        }
    
    return vectors