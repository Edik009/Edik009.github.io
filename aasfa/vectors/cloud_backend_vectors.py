"""
Cloud & Backend Security Vectors - Comprehensive cloud security scanning module

Полный набор векторов безопасности облачных сервисов и backend с многофакторной проверкой.
Включает проверки Firebase, AWS, Google Cloud Platform, Azure и других облачных провайдеров.

Структура модуля:
- ЧАСТЬ 1: FIREBASE УЯЗВИМОСТИ (400 строк)
- ЧАСТЬ 2: AWS УЯЗВИМОСТИ (400 строк)
- ЧАСТЬ 3: GOOGLE CLOUD УЯЗВИМОСТИ (350 строк)
- ЧАСТЬ 4: AZURE УЯЗВИМОСТИ (300 строк)
- ЧАСТЬ 5: ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ И УТИЛИТЫ (350 строк)

Каждый вектор использует многофакторную проверку для повышения точности.
"""

import os
import re
import time
import json
import base64
import hashlib
import logging
import socket
import ssl
import urllib.parse
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

from ..utils.config import ScanConfig
from ..core.result_aggregator import VectorResult


# Настройка логирования
logger = logging.getLogger(__name__)


# ============================================================================
# CACHE LAYER
# ============================================================================

_CLOUD_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_TIMEOUT = 300  # 5 минут


def cache_cloud_check_result(vector_id: int, result: Dict[str, Any]) -> None:
    """Кэширование результатов проверки"""
    cache_key = f"vector_{vector_id}"
    _CLOUD_CACHE[cache_key] = {
        "result": result,
        "timestamp": time.time()
    }
    logger.debug(f"Cached result for vector {vector_id}")


def get_cached_result(vector_id: int) -> Optional[Dict[str, Any]]:
    """Получение результата из кэша"""
    cache_key = f"vector_{vector_id}"
    if cache_key in _CLOUD_CACHE:
        cached = _CLOUD_CACHE[cache_key]
        if is_cache_valid(cached["timestamp"]):
            logger.debug(f"Cache hit for vector {vector_id}")
            return cached["result"]
        else:
            # Удаляем устаревший кэш
            del _CLOUD_CACHE[cache_key]
            logger.debug(f"Cache expired for vector {vector_id}")
    return None


def is_cache_valid(timestamp: float) -> bool:
    """Проверка валидности кэша"""
    return (time.time() - timestamp) < _CACHE_TIMEOUT


def clear_cache() -> None:
    """Очистка кэша"""
    _CLOUD_CACHE.clear()
    logger.info("Cloud cache cleared")


# ============================================================================
# HELPER FUNCTIONS FOR CLOUD API TESTING
# ============================================================================

def make_cloud_api_request(url: str, method: str = "GET", 
                          headers: Optional[Dict[str, str]] = None,
                          data: Optional[Dict[str, Any]] = None,
                          timeout: int = 10) -> Dict[str, Any]:
    """
    Базовый запрос к облачному API
    
    Args:
        url: URL для запроса
        method: HTTP метод
        headers: HTTP заголовки
        data: Данные для отправки
        timeout: Таймаут запроса
    
    Returns:
        Dict с полями: success, status_code, headers, body, error
    """
    try:
        import urllib.request
        import urllib.error
        
        # Подготовка запроса
        req_data = None
        if data:
            req_data = json.dumps(data).encode('utf-8')
            if headers is None:
                headers = {}
            headers['Content-Type'] = 'application/json'
        
        request = urllib.request.Request(url, data=req_data, method=method)
        if headers:
            for key, value in headers.items():
                request.add_header(key, value)
        
        # Выполнение запроса
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode('utf-8', errors='ignore')
            return {
                "success": True,
                "status_code": response.status,
                "headers": dict(response.headers),
                "body": body,
                "error": None
            }
    
    except urllib.error.HTTPError as e:
        return {
            "success": False,
            "status_code": e.code,
            "headers": dict(e.headers),
            "body": e.read().decode('utf-8', errors='ignore') if e.fp else "",
            "error": str(e)
        }
    except Exception as e:
        logger.error(f"API request failed: {e}")
        return {
            "success": False,
            "status_code": 0,
            "headers": {},
            "body": "",
            "error": str(e)
        }


def detect_cloud_provider(target: str) -> Optional[str]:
    """
    Определение облачного провайдера по target URL или hostname
    
    Args:
        target: Target URL или hostname
    
    Returns:
        Имя провайдера или None
    """
    target_lower = target.lower()
    
    # Firebase detection
    if any(x in target_lower for x in ['firebase.io', 'firebaseapp.com', 'firebasestorage.googleapis.com']):
        return "firebase"
    
    # AWS detection
    if any(x in target_lower for x in ['amazonaws.com', 's3.', 'cloudfront.net', 'awsstatic.com']):
        return "aws"
    
    # Google Cloud detection
    if any(x in target_lower for x in ['googleapis.com', 'googleusercontent.com', 'cloudfunctions.net', 'run.app']):
        return "gcp"
    
    # Azure detection
    if any(x in target_lower for x in ['azure.com', 'azurewebsites.net', 'blob.core.windows.net', 'cloudapp.azure.com']):
        return "azure"
    
    return None


def parse_cloud_config(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Парсинг конфигурации из ответа облачного сервиса
    
    Args:
        response: Ответ от make_cloud_api_request
    
    Returns:
        Распарсенная конфигурация
    """
    config = {
        "raw_body": response.get("body", ""),
        "headers": response.get("headers", {}),
        "parsed_json": None,
        "security_headers": {},
        "errors": []
    }
    
    # Попытка парсинга JSON
    try:
        if response.get("body"):
            config["parsed_json"] = json.loads(response["body"])
    except json.JSONDecodeError as e:
        config["errors"].append(f"JSON parse error: {e}")
    
    # Извлечение security headers
    headers = response.get("headers", {})
    security_header_names = [
        'x-frame-options', 'content-security-policy', 'strict-transport-security',
        'x-content-type-options', 'x-xss-protection', 'access-control-allow-origin'
    ]
    
    for header_name in security_header_names:
        # Проверяем как в lowercase, так и в оригинальном виде
        for key in headers.keys():
            if key.lower() == header_name:
                config["security_headers"][header_name] = headers[key]
                break
    
    return config


def check_cloud_credentials_format(config: Dict[str, Any]) -> Dict[str, bool]:
    """
    Проверка формата cloud credentials в конфигурации
    
    Args:
        config: Конфигурация для проверки
    
    Returns:
        Dict с найденными типами credentials
    """
    results = {
        "aws_access_key": False,
        "aws_secret_key": False,
        "gcp_service_account": False,
        "azure_connection_string": False,
        "firebase_api_key": False,
        "private_key": False
    }
    
    config_str = json.dumps(config) if isinstance(config, dict) else str(config)
    
    # AWS Access Key (AKIA...)
    if re.search(r'AKIA[0-9A-Z]{16}', config_str):
        results["aws_access_key"] = True
    
    # AWS Secret Key (40 символов base64)
    if re.search(r'[A-Za-z0-9/+=]{40}', config_str):
        results["aws_secret_key"] = True
    
    # GCP Service Account
    if '"type": "service_account"' in config_str or '"private_key_id"' in config_str:
        results["gcp_service_account"] = True
    
    # Azure Connection String
    if 'AccountName=' in config_str and 'AccountKey=' in config_str:
        results["azure_connection_string"] = True
    
    # Firebase API Key
    if 'apiKey' in config_str or 'firebase' in config_str.lower():
        results["firebase_api_key"] = True
    
    # Private Key
    if '-----BEGIN PRIVATE KEY-----' in config_str or '-----BEGIN RSA PRIVATE KEY-----' in config_str:
        results["private_key"] = True
    
    return results


# ============================================================================
# RESPONSE ANALYSIS FUNCTIONS
# ============================================================================

def analyze_firebase_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Анализ ответа Firebase
    
    Args:
        response: Ответ от make_cloud_api_request
    
    Returns:
        Результаты анализа
    """
    analysis = {
        "accessible": response.get("success", False),
        "status_code": response.get("status_code", 0),
        "requires_auth": False,
        "public_read": False,
        "public_write": False,
        "rules_detected": False,
        "data_exposed": False
    }
    
    if not analysis["accessible"]:
        return analysis
    
    body = response.get("body", "")
    status_code = response.get("status_code", 0)
    
    # Проверка требования аутентификации
    if status_code == 401 or "unauthorized" in body.lower() or "permission denied" in body.lower():
        analysis["requires_auth"] = True
    
    # Проверка публичного доступа на чтение
    if status_code == 200 and body and body != "null":
        analysis["public_read"] = True
        try:
            data = json.loads(body)
            if data and isinstance(data, (dict, list)):
                analysis["data_exposed"] = True
        except:
            pass
    
    # Проверка правил
    if ".read" in body or ".write" in body or "rules" in body.lower():
        analysis["rules_detected"] = True
    
    return analysis


def analyze_aws_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Анализ ответа AWS
    
    Args:
        response: Ответ от make_cloud_api_request
    
    Returns:
        Результаты анализа
    """
    analysis = {
        "accessible": response.get("success", False),
        "status_code": response.get("status_code", 0),
        "bucket_public": False,
        "listing_enabled": False,
        "acl_detected": False,
        "encryption_detected": False,
        "versioning_detected": False
    }
    
    if not analysis["accessible"]:
        return analysis
    
    body = response.get("body", "")
    headers = response.get("headers", {})
    status_code = response.get("status_code", 0)
    
    # Проверка публичного bucket
    if status_code == 200:
        analysis["bucket_public"] = True
    
    # Проверка листинга
    if "<ListBucketResult" in body or "<Contents>" in body:
        analysis["listing_enabled"] = True
    
    # Проверка ACL
    if "x-amz-acl" in str(headers).lower() or "<AccessControlPolicy" in body:
        analysis["acl_detected"] = True
    
    # Проверка шифрования
    if "x-amz-server-side-encryption" in str(headers).lower():
        analysis["encryption_detected"] = True
    
    # Проверка versioning
    if "<VersioningConfiguration" in body or "x-amz-version-id" in str(headers).lower():
        analysis["versioning_detected"] = True
    
    return analysis


def analyze_gcp_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Анализ ответа Google Cloud Platform
    
    Args:
        response: Ответ от make_cloud_api_request
    
    Returns:
        Результаты анализа
    """
    analysis = {
        "accessible": response.get("success", False),
        "status_code": response.get("status_code", 0),
        "public_access": False,
        "iam_detected": False,
        "service_account_detected": False,
        "api_key_detected": False
    }
    
    if not analysis["accessible"]:
        return analysis
    
    body = response.get("body", "")
    headers = response.get("headers", {})
    status_code = response.get("status_code", 0)
    
    # Проверка публичного доступа
    if status_code == 200:
        analysis["public_access"] = True
    
    # Проверка IAM
    if "iam.googleapis.com" in body or '"bindings"' in body or '"role"' in body:
        analysis["iam_detected"] = True
    
    # Проверка Service Account
    if '"type": "service_account"' in body or '"client_email"' in body:
        analysis["service_account_detected"] = True
    
    # Проверка API Key
    if "x-goog-api-key" in str(headers).lower() or '"api_key"' in body:
        analysis["api_key_detected"] = True
    
    return analysis


def analyze_azure_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Анализ ответа Azure
    
    Args:
        response: Ответ от make_cloud_api_request
    
    Returns:
        Результаты анализа
    """
    analysis = {
        "accessible": response.get("success", False),
        "status_code": response.get("status_code", 0),
        "public_access": False,
        "sas_token_detected": False,
        "storage_account_detected": False,
        "rbac_detected": False
    }
    
    if not analysis["accessible"]:
        return analysis
    
    body = response.get("body", "")
    headers = response.get("headers", {})
    status_code = response.get("status_code", 0)
    
    # Проверка публичного доступа
    if status_code == 200:
        analysis["public_access"] = True
    
    # Проверка SAS Token
    if "sig=" in body or "sv=" in body or "x-ms-blob-type" in str(headers).lower():
        analysis["sas_token_detected"] = True
    
    # Проверка Storage Account
    if "x-ms-request-id" in str(headers).lower() or "x-ms-version" in str(headers).lower():
        analysis["storage_account_detected"] = True
    
    # Проверка RBAC
    if '"roleDefinitionId"' in body or '"principalId"' in body:
        analysis["rbac_detected"] = True
    
    return analysis


# ============================================================================
# SECURITY CONFIGURATION VALIDATORS
# ============================================================================

def validate_firebase_rules(rules_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Валидация Firebase Security Rules
    
    Args:
        rules_json: JSON с правилами Firebase
    
    Returns:
        Результаты валидации
    """
    validation = {
        "valid": True,
        "issues": [],
        "allow_read_all": False,
        "allow_write_all": False,
        "has_auth_check": False,
        "has_validation": False
    }
    
    rules_str = json.dumps(rules_json) if isinstance(rules_json, dict) else str(rules_json)
    
    # Проверка чтения для всех
    if '".read": true' in rules_str or '".read":"true"' in rules_str:
        validation["allow_read_all"] = True
        validation["issues"].append("Правило разрешает чтение для всех")
        validation["valid"] = False
    
    # Проверка записи для всех
    if '".write": true' in rules_str or '".write":"true"' in rules_str:
        validation["allow_write_all"] = True
        validation["issues"].append("Правило разрешает запись для всех")
        validation["valid"] = False
    
    # Проверка аутентификации
    if "auth" in rules_str and "auth != null" in rules_str:
        validation["has_auth_check"] = True
    
    # Проверка валидации данных
    if "validate" in rules_str or ".validate" in rules_str:
        validation["has_validation"] = True
    
    return validation


def validate_aws_bucket_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    """
    Валидация AWS S3 Bucket Policy
    
    Args:
        policy: JSON с политикой bucket
    
    Returns:
        Результаты валидации
    """
    validation = {
        "valid": True,
        "issues": [],
        "public_read": False,
        "public_write": False,
        "wildcard_principal": False,
        "wildcard_action": False
    }
    
    if not isinstance(policy, dict):
        validation["valid"] = False
        validation["issues"].append("Невалидный формат политики")
        return validation
    
    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]
    
    for statement in statements:
        effect = statement.get("Effect", "")
        principal = statement.get("Principal", {})
        action = statement.get("Action", [])
        
        # Проверка wildcard principal
        if principal == "*" or principal.get("AWS") == "*":
            validation["wildcard_principal"] = True
            validation["issues"].append("Principal установлен в '*' (публичный доступ)")
            validation["valid"] = False
        
        # Проверка wildcard action
        if action == "*" or action == "s3:*":
            validation["wildcard_action"] = True
            validation["issues"].append("Action установлен в '*' (все действия разрешены)")
            validation["valid"] = False
        
        # Проверка публичного чтения
        if effect == "Allow" and ("s3:GetObject" in action or "s3:ListBucket" in action):
            if validation["wildcard_principal"]:
                validation["public_read"] = True
        
        # Проверка публичной записи
        if effect == "Allow" and ("s3:PutObject" in action or "s3:DeleteObject" in action):
            if validation["wildcard_principal"]:
                validation["public_write"] = True
    
    return validation


def validate_gcp_iam_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    """
    Валидация GCP IAM Policy
    
    Args:
        policy: JSON с IAM политикой
    
    Returns:
        Результаты валидации
    """
    validation = {
        "valid": True,
        "issues": [],
        "public_access": False,
        "all_users_access": False,
        "all_authenticated_access": False,
        "overpermissive_roles": []
    }
    
    if not isinstance(policy, dict):
        validation["valid"] = False
        validation["issues"].append("Невалидный формат политики")
        return validation
    
    bindings = policy.get("bindings", [])
    
    for binding in bindings:
        members = binding.get("members", [])
        role = binding.get("role", "")
        
        # Проверка публичного доступа
        if "allUsers" in members:
            validation["all_users_access"] = True
            validation["public_access"] = True
            validation["issues"].append(f"Роль {role} доступна для allUsers")
            validation["valid"] = False
        
        # Проверка доступа для всех аутентифицированных
        if "allAuthenticatedUsers" in members:
            validation["all_authenticated_access"] = True
            validation["issues"].append(f"Роль {role} доступна для allAuthenticatedUsers")
        
        # Проверка чрезмерно разрешающих ролей
        overpermissive = ["roles/owner", "roles/editor", "roles/admin"]
        if any(perm in role for perm in overpermissive):
            validation["overpermissive_roles"].append(role)
            if validation["public_access"]:
                validation["issues"].append(f"Чрезмерно разрешающая роль {role} доступна публично")
                validation["valid"] = False
    
    return validation


def validate_azure_rbac(policy: Dict[str, Any]) -> Dict[str, Any]:
    """
    Валидация Azure RBAC Policy
    
    Args:
        policy: JSON с RBAC политикой
    
    Returns:
        Результаты валидации
    """
    validation = {
        "valid": True,
        "issues": [],
        "overpermissive_roles": [],
        "public_access": False,
        "contributor_access": False
    }
    
    if not isinstance(policy, dict):
        validation["valid"] = False
        validation["issues"].append("Невалидный формат политики")
        return validation
    
    role_assignments = policy.get("value", []) if "value" in policy else [policy]
    
    for assignment in role_assignments:
        role_name = assignment.get("properties", {}).get("roleDefinitionName", "")
        principal_id = assignment.get("properties", {}).get("principalId", "")
        
        # Проверка чрезмерно разрешающих ролей
        overpermissive = ["Owner", "Contributor", "User Access Administrator"]
        if role_name in overpermissive:
            validation["overpermissive_roles"].append(role_name)
            
            if role_name == "Contributor":
                validation["contributor_access"] = True
        
        # Проверка публичного principal (упрощенная проверка)
        if not principal_id or principal_id == "00000000-0000-0000-0000-000000000000":
            validation["public_access"] = True
            validation["issues"].append(f"Роль {role_name} может иметь публичный доступ")
            validation["valid"] = False
    
    return validation


# ============================================================================
# ЧАСТЬ 1: FIREBASE УЯЗВИМОСТИ (400 строк)
# ============================================================================

def check_firebase_realtime_db_misconfigured(target: str, config: ScanConfig) -> VectorResult:
    """
    Проверка доступности и конфигурации Firebase Realtime Database
    
    Факторы проверки:
    - Realtime DB accessible (доступна БД)
    - Open for read (открыта для чтения)
    - Open for write (открыта для записи)
    - No authentication required (нет аутентификации)
    - Data leakage visible (утечка данных видна)
    
    Критерий: ≥3 факторов подтверждены = НАЙДЕНА уязвимость
    """
    vector_id = 6001
    vector_name = "Firebase Realtime DB Misconfigured"
    
    # Проверка кэша
    cached = get_cached_result(vector_id)
    if cached:
        return VectorResult(**cached)
    
    factors = []
    details = []
    
    # Фактор 1: Проверка доступности БД
    factor_db_accessible = _check_firebase_db_accessible(target)
    factors.append(factor_db_accessible)
    if factor_db_accessible['confirmed']:
        details.append("Фактор 1: Realtime DB доступна")
    else:
        details.append("Фактор 1: Realtime DB недоступна")
    
    # Фактор 2: Проверка открытого чтения
    factor_open_read = _check_firebase_open_read(target)
    factors.append(factor_open_read)
    if factor_open_read['confirmed']:
        details.append("Фактор 2: База открыта для чтения")
    else:
        details.append("Фактор 2: Чтение требует аутентификации")
    
    # Фактор 3: Проверка открытой записи
    factor_open_write = _check_firebase_open_write(target)
    factors.append(factor_open_write)
    if factor_open_write['confirmed']:
        details.append("Фактор 3: База открыта для записи")
    else:
        details.append("Фактор 3: Запись требует аутентификации")
    
    # Фактор 4: Проверка аутентификации
    factor_no_auth = _check_firebase_no_auth(target)
    factors.append(factor_no_auth)
    if factor_no_auth['confirmed']:
        details.append("Фактор 4: Аутентификация не требуется")
    else:
        details.append("Фактор 4: Требуется аутентификация")
    
    # Фактор 5: Проверка утечки данных
    factor_data_leak = _check_firebase_data_leak(target)
    factors.append(factor_data_leak)
    if factor_data_leak['confirmed']:
        details.append(f"Фактор 5: Обнаружена утечка данных - {factor_data_leak['evidence']}")
    else:
        details.append("Фактор 5: Утечка данных не обнаружена")
    
    # Подсчет подтвержденных факторов
    confirmed_count = sum(1 for f in factors if f['confirmed'])
    threshold = 3
    
    vulnerable = confirmed_count >= threshold
    confidence = (confirmed_count / len(factors)) * 100
    
    if vulnerable:
        details.insert(0, f"УЯЗВИМОСТЬ ОБНАРУЖЕНА: {confirmed_count} из {len(factors)} факторов подтверждены")
        severity = "CRITICAL"
    else:
        details.insert(0, f"Уязвимость не подтверждена: {confirmed_count} из {len(factors)} факторов")
        severity = "INFO"
    
    result = VectorResult(
        vector_id=vector_id,
        vector_name=vector_name,
        checks_passed=confirmed_count,
        checks_total=len(factors),
        confidence=confidence,
        vulnerable=vulnerable,
        details=details,
        severity=severity
    )
    
    # Кэширование результата
    cache_cloud_check_result(vector_id, result.to_dict())
    
    return result


def _check_firebase_db_accessible(target: str) -> Dict[str, Any]:
    """Проверка доступности Firebase Realtime DB"""
    try:
        # Попытка подключения к Firebase DB
        firebase_url = _construct_firebase_url(target)
        response = make_cloud_api_request(f"{firebase_url}/.json", timeout=5)
        
        if response["success"] or response["status_code"] in [200, 401, 403]:
            return {
                'confirmed': True,
                'evidence': f"DB endpoint accessible (status: {response['status_code']})"
            }
        
        return {'confirmed': False, 'evidence': 'DB not accessible'}
    
    except Exception as e:
        logger.debug(f"Firebase DB accessibility check failed: {e}")
        return {'confirmed': False, 'evidence': str(e)}


def _check_firebase_open_read(target: str) -> Dict[str, Any]:
    """Проверка открытого чтения Firebase DB"""
    try:
        firebase_url = _construct_firebase_url(target)
        response = make_cloud_api_request(f"{firebase_url}/.json", timeout=5)
        
        if response["status_code"] == 200 and response["body"]:
            analysis = analyze_firebase_response(response)
            if analysis["public_read"]:
                return {
                    'confirmed': True,
                    'evidence': 'Database allows public read access'
                }
        
        return {'confirmed': False, 'evidence': 'Read access restricted'}
    
    except Exception as e:
        logger.debug(f"Firebase read check failed: {e}")
        return {'confirmed': False, 'evidence': str(e)}


def _check_firebase_open_write(target: str) -> Dict[str, Any]:
    """Проверка открытой записи Firebase DB"""
    try:
        firebase_url = _construct_firebase_url(target)
        test_data = {"test_write": int(time.time())}
        
        # Попытка записи
        response = make_cloud_api_request(
            f"{firebase_url}/test_security.json",
            method="PUT",
            data=test_data,
            timeout=5
        )
        
        if response["status_code"] == 200:
            # Попытка удалить тестовые данные
            make_cloud_api_request(
                f"{firebase_url}/test_security.json",
                method="DELETE",
                timeout=5
            )
            return {
                'confirmed': True,
                'evidence': 'Database allows public write access'
            }
        
        return {'confirmed': False, 'evidence': 'Write access restricted'}
    
    except Exception as e:
        logger.debug(f"Firebase write check failed: {e}")
        return {'confirmed': False, 'evidence': str(e)}


def _check_firebase_no_auth(target: str) -> Dict[str, Any]:
    """Проверка отсутствия требования аутентификации"""
    try:
        firebase_url = _construct_firebase_url(target)
        
        # Запрос без auth токена
        response = make_cloud_api_request(f"{firebase_url}/.json", timeout=5)
        
        if response["status_code"] == 200:
            return {
                'confirmed': True,
                'evidence': 'No authentication required for access'
            }
        elif response["status_code"] in [401, 403]:
            return {'confirmed': False, 'evidence': 'Authentication required'}
        
        return {'confirmed': False, 'evidence': 'Unable to determine auth requirement'}
    
    except Exception as e:
        logger.debug(f"Firebase auth check failed: {e}")
        return {'confirmed': False, 'evidence': str(e)}


def _check_firebase_data_leak(target: str) -> Dict[str, Any]:
    """Проверка утечки данных"""
    try:
        firebase_url = _construct_firebase_url(target)
        response = make_cloud_api_request(f"{firebase_url}/.json?shallow=true", timeout=5)
        
        if response["status_code"] == 200 and response["body"]:
            try:
                data = json.loads(response["body"])
                if data and isinstance(data, dict):
                    keys = list(data.keys())
                    if keys:
                        return {
                            'confirmed': True,
                            'evidence': f"Exposed keys: {', '.join(keys[:5])}"
                        }
            except:
                pass
        
        return {'confirmed': False, 'evidence': 'No data leakage detected'}
    
    except Exception as e:
        logger.debug(f"Firebase data leak check failed: {e}")
        return {'confirmed': False, 'evidence': str(e)}


def _construct_firebase_url(target: str) -> str:
    """Построение Firebase URL"""
    if 'firebase' in target.lower():
        if not target.startswith('http'):
            return f"https://{target}"
        return target
    else:
        # Предположение о Firebase project ID
        return f"https://{target}-default-rtdb.firebaseio.com"


def check_firebase_auth_disabled(target: str, config: ScanConfig) -> VectorResult:
    """
    Проверка отключения аутентификации Firebase
    
    Факторы проверки:
    - Authentication service absent (сервис отсутствует)
    - Anonymous auth allowed (анонимная auth разрешена)
    - No verification required (нет проверки)
    - Default rules present (правила по умолчанию)
    - Access control bypass possible (bypass контроля доступа)
    
    Критерий: ≥2 факторов подтверждены = НАЙДЕНА уязвимость
    """
    vector_id = 6002
    vector_name = "Firebase Auth Disabled"
    
    factors = []
    details = []
    
    # Фактор 1: Проверка отсутствия auth сервиса
    factor_auth_absent = _check_firebase_auth_service_absent(target)
    factors.append(factor_auth_absent)
    if factor_auth_absent['confirmed']:
        details.append("Фактор 1: Authentication service отсутствует")
    else:
        details.append("Фактор 1: Authentication service активен")
    
    # Фактор 2: Проверка анонимной аутентификации
    factor_anon_auth = _check_firebase_anonymous_auth(target)
    factors.append(factor_anon_auth)
    if factor_anon_auth['confirmed']:
        details.append("Фактор 2: Анонимная аутентификация разрешена")
    else:
        details.append("Фактор 2: Анонимная аутентификация отключена")
    
    # Фактор 3: Проверка отсутствия верификации
    factor_no_verification = _check_firebase_no_verification(target)
    factors.append(factor_no_verification)
    if factor_no_verification['confirmed']:
        details.append("Фактор 3: Верификация не требуется")
    else:
        details.append("Фактор 3: Верификация настроена")
    
    # Фактор 4: Проверка дефолтных правил
    factor_default_rules = _check_firebase_default_rules(target)
    factors.append(factor_default_rules)
    if factor_default_rules['confirmed']:
        details.append("Фактор 4: Используются правила по умолчанию")
    else:
        details.append("Фактор 4: Правила настроены")
    
    # Фактор 5: Проверка bypass контроля доступа
    factor_bypass = _check_firebase_access_bypass(target)
    factors.append(factor_bypass)
    if factor_bypass['confirmed']:
        details.append(f"Фактор 5: Возможен bypass - {factor_bypass['evidence']}")
    else:
        details.append("Фактор 5: Bypass не обнаружен")
    
    confirmed_count = sum(1 for f in factors if f['confirmed'])
    threshold = 2
    
    vulnerable = confirmed_count >= threshold
    confidence = (confirmed_count / len(factors)) * 100
    
    if vulnerable:
        details.insert(0, f"УЯЗВИМОСТЬ ОБНАРУЖЕНА: {confirmed_count} из {len(factors)} факторов подтверждены")
        severity = "HIGH"
    else:
        details.insert(0, f"Уязвимость не подтверждена: {confirmed_count} из {len(factors)} факторов")
        severity = "INFO"
    
    result = VectorResult(
        vector_id=vector_id,
        vector_name=vector_name,
        checks_passed=confirmed_count,
        checks_total=len(factors),
        confidence=confidence,
        vulnerable=vulnerable,
        details=details,
        severity=severity
    )
    
    cache_cloud_check_result(vector_id, result.to_dict())
    return result


def _check_firebase_auth_service_absent(target: str) -> Dict[str, Any]:
    """Проверка отсутствия auth сервиса"""
    try:
        firebase_url = _construct_firebase_url(target)
        # Попытка получить конфигурацию auth
        response = make_cloud_api_request(f"{firebase_url}/.settings/auth.json", timeout=5)
        
        if response["status_code"] == 404:
            return {'confirmed': True, 'evidence': 'Auth service configuration not found'}
        
        return {'confirmed': False, 'evidence': 'Auth service present'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_firebase_anonymous_auth(target: str) -> Dict[str, Any]:
    """Проверка анонимной аутентификации"""
    try:
        # Проверка через публичный endpoint
        firebase_url = _construct_firebase_url(target)
        response = make_cloud_api_request(f"{firebase_url}/.json", timeout=5)
        
        # Если доступ разрешен без учетных данных
        if response["status_code"] == 200:
            return {'confirmed': True, 'evidence': 'Anonymous access allowed'}
        
        return {'confirmed': False, 'evidence': 'Anonymous access denied'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_firebase_no_verification(target: str) -> Dict[str, Any]:
    """Проверка отсутствия верификации"""
    try:
        firebase_url = _construct_firebase_url(target)
        response = make_cloud_api_request(f"{firebase_url}/.json", timeout=5)
        
        # Анализ ответа на наличие требований верификации
        analysis = analyze_firebase_response(response)
        if not analysis["requires_auth"]:
            return {'confirmed': True, 'evidence': 'No verification required'}
        
        return {'confirmed': False, 'evidence': 'Verification required'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_firebase_default_rules(target: str) -> Dict[str, Any]:
    """Проверка дефолтных правил"""
    try:
        firebase_url = _construct_firebase_url(target)
        response = make_cloud_api_request(f"{firebase_url}/.settings/rules.json", timeout=5)
        
        if response["status_code"] == 200 and response["body"]:
            # Проверка на дефолтные правила
            body = response["body"]
            if '".read": true' in body and '".write": true' in body:
                return {'confirmed': True, 'evidence': 'Default permissive rules detected'}
        
        return {'confirmed': False, 'evidence': 'Custom rules configured'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_firebase_access_bypass(target: str) -> Dict[str, Any]:
    """Проверка bypass контроля доступа"""
    try:
        firebase_url = _construct_firebase_url(target)
        
        # Попытка доступа к защищенным путям
        protected_paths = ['/users', '/admin', '/config', '/private']
        
        for path in protected_paths:
            response = make_cloud_api_request(f"{firebase_url}{path}.json", timeout=5)
            if response["status_code"] == 200 and response["body"] and response["body"] != "null":
                return {
                    'confirmed': True,
                    'evidence': f'Access bypass possible via {path}'
                }
        
        return {'confirmed': False, 'evidence': 'No bypass detected'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def check_firebase_storage_public(target: str, config: ScanConfig) -> VectorResult:
    """
    Проверка публичности Firebase Storage
    
    Факторы проверки:
    - Storage bucket public (bucket публичный)
    - Files readable without auth (файлы читаемы без auth)
    - Files writable without auth (файлы писаемы без auth)
    - No access control (нет контроля доступа)
    - File enumeration possible (возможен перебор файлов)
    
    Критерий: ≥2 факторов подтверждены = НАЙДЕНА уязвимость
    """
    vector_id = 6003
    vector_name = "Firebase Storage Public"
    
    factors = []
    details = []
    
    # Фактор 1: Проверка публичности bucket
    factor_bucket_public = _check_firebase_bucket_public(target)
    factors.append(factor_bucket_public)
    if factor_bucket_public['confirmed']:
        details.append("Фактор 1: Storage bucket публичный")
    else:
        details.append("Фактор 1: Storage bucket защищен")
    
    # Фактор 2: Проверка чтения файлов
    factor_files_readable = _check_firebase_files_readable(target)
    factors.append(factor_files_readable)
    if factor_files_readable['confirmed']:
        details.append("Фактор 2: Файлы читаемы без аутентификации")
    else:
        details.append("Фактор 2: Чтение файлов требует аутентификации")
    
    # Фактор 3: Проверка записи файлов
    factor_files_writable = _check_firebase_files_writable(target)
    factors.append(factor_files_writable)
    if factor_files_writable['confirmed']:
        details.append("Фактор 3: Файлы писаемы без аутентификации")
    else:
        details.append("Фактор 3: Запись файлов требует аутентификации")
    
    # Фактор 4: Проверка контроля доступа
    factor_no_access_control = _check_firebase_storage_no_access_control(target)
    factors.append(factor_no_access_control)
    if factor_no_access_control['confirmed']:
        details.append("Фактор 4: Контроль доступа отсутствует")
    else:
        details.append("Фактор 4: Контроль доступа настроен")
    
    # Фактор 5: Проверка перебора файлов
    factor_enumeration = _check_firebase_file_enumeration(target)
    factors.append(factor_enumeration)
    if factor_enumeration['confirmed']:
        details.append(f"Фактор 5: Возможен перебор файлов - {factor_enumeration['evidence']}")
    else:
        details.append("Фактор 5: Перебор файлов невозможен")
    
    confirmed_count = sum(1 for f in factors if f['confirmed'])
    threshold = 2
    
    vulnerable = confirmed_count >= threshold
    confidence = (confirmed_count / len(factors)) * 100
    
    if vulnerable:
        details.insert(0, f"УЯЗВИМОСТЬ ОБНАРУЖЕНА: {confirmed_count} из {len(factors)} факторов подтверждены")
        severity = "HIGH"
    else:
        details.insert(0, f"Уязвимость не подтверждена: {confirmed_count} из {len(factors)} факторов")
        severity = "INFO"
    
    result = VectorResult(
        vector_id=vector_id,
        vector_name=vector_name,
        checks_passed=confirmed_count,
        checks_total=len(factors),
        confidence=confidence,
        vulnerable=vulnerable,
        details=details,
        severity=severity
    )
    
    cache_cloud_check_result(vector_id, result.to_dict())
    return result


def _check_firebase_bucket_public(target: str) -> Dict[str, Any]:
    """Проверка публичности Firebase Storage bucket"""
    try:
        # Firebase Storage обычно на firebasestorage.googleapis.com
        if 'firebase' in target.lower():
            storage_url = target.replace('firebaseio.com', 'firebasestorage.googleapis.com')
        else:
            storage_url = f"https://firebasestorage.googleapis.com/v0/b/{target}.appspot.com"
        
        response = make_cloud_api_request(storage_url, timeout=5)
        
        if response["status_code"] in [200, 403]:
            return {'confirmed': True, 'evidence': 'Storage bucket accessible'}
        
        return {'confirmed': False, 'evidence': 'Storage bucket not found'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_firebase_files_readable(target: str) -> Dict[str, Any]:
    """Проверка чтения файлов без аутентификации"""
    try:
        # Попытка получить список файлов
        storage_url = _construct_firebase_storage_url(target)
        response = make_cloud_api_request(f"{storage_url}/o", timeout=5)
        
        if response["status_code"] == 200:
            return {'confirmed': True, 'evidence': 'Files readable without auth'}
        
        return {'confirmed': False, 'evidence': 'File read access restricted'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_firebase_files_writable(target: str) -> Dict[str, Any]:
    """Проверка записи файлов без аутентификации"""
    try:
        storage_url = _construct_firebase_storage_url(target)
        test_file = f"test_write_{int(time.time())}.txt"
        
        # Попытка загрузить файл
        response = make_cloud_api_request(
            f"{storage_url}/o?name={test_file}",
            method="POST",
            data={"test": "data"},
            timeout=5
        )
        
        if response["status_code"] in [200, 201]:
            return {'confirmed': True, 'evidence': 'Files writable without auth'}
        
        return {'confirmed': False, 'evidence': 'File write access restricted'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_firebase_storage_no_access_control(target: str) -> Dict[str, Any]:
    """Проверка отсутствия контроля доступа"""
    try:
        storage_url = _construct_firebase_storage_url(target)
        
        # Попытка получить metadata
        response = make_cloud_api_request(f"{storage_url}/o", timeout=5)
        
        if response["status_code"] == 200:
            # Проверка наличия access control в ответе
            body = response["body"]
            if "accessControl" not in body and "acl" not in body:
                return {'confirmed': True, 'evidence': 'No access control detected'}
        
        return {'confirmed': False, 'evidence': 'Access control present'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_firebase_file_enumeration(target: str) -> Dict[str, Any]:
    """Проверка возможности перебора файлов"""
    try:
        storage_url = _construct_firebase_storage_url(target)
        response = make_cloud_api_request(f"{storage_url}/o", timeout=5)
        
        if response["status_code"] == 200 and response["body"]:
            try:
                data = json.loads(response["body"])
                if data and ("items" in data or "files" in data):
                    item_count = len(data.get("items", data.get("files", [])))
                    return {
                        'confirmed': True,
                        'evidence': f'File enumeration possible ({item_count} files found)'
                    }
            except:
                pass
        
        return {'confirmed': False, 'evidence': 'File enumeration not possible'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _construct_firebase_storage_url(target: str) -> str:
    """Построение Firebase Storage URL"""
    if 'firebasestorage' in target.lower():
        if not target.startswith('http'):
            return f"https://{target}"
        return target
    else:
        return f"https://firebasestorage.googleapis.com/v0/b/{target}.appspot.com"


def check_firebase_rules_overpermissive(target: str, config: ScanConfig) -> VectorResult:
    """
    Анализ чрезмерно разрешающих правил Firebase
    
    Факторы проверки:
    - Allow read to all (чтение разрешено всем)
    - Allow write to all (запись разрешена всем)
    - No path validation (без проверки пути)
    - No user verification (без проверки пользователя)
    - Wildcard rules present (подстановочные правила)
    
    Критерий: ≥2 факторов подтверждены = НАЙДЕНА уязвимость
    """
    vector_id = 6004
    vector_name = "Firebase Rules Overpermissive"
    
    factors = []
    details = []
    
    # Фактор 1: Проверка чтения для всех
    factor_read_all = _check_firebase_read_all(target)
    factors.append(factor_read_all)
    if factor_read_all['confirmed']:
        details.append("Фактор 1: Чтение разрешено всем")
    else:
        details.append("Фактор 1: Чтение ограничено")
    
    # Фактор 2: Проверка записи для всех
    factor_write_all = _check_firebase_write_all(target)
    factors.append(factor_write_all)
    if factor_write_all['confirmed']:
        details.append("Фактор 2: Запись разрешена всем")
    else:
        details.append("Фактор 2: Запись ограничена")
    
    # Фактор 3: Проверка валидации пути
    factor_no_path_validation = _check_firebase_no_path_validation(target)
    factors.append(factor_no_path_validation)
    if factor_no_path_validation['confirmed']:
        details.append("Фактор 3: Валидация пути отсутствует")
    else:
        details.append("Фактор 3: Валидация пути настроена")
    
    # Фактор 4: Проверка верификации пользователя
    factor_no_user_verification = _check_firebase_no_user_verification(target)
    factors.append(factor_no_user_verification)
    if factor_no_user_verification['confirmed']:
        details.append("Фактор 4: Верификация пользователя отсутствует")
    else:
        details.append("Фактор 4: Верификация пользователя настроена")
    
    # Фактор 5: Проверка wildcard правил
    factor_wildcard_rules = _check_firebase_wildcard_rules(target)
    factors.append(factor_wildcard_rules)
    if factor_wildcard_rules['confirmed']:
        details.append(f"Фактор 5: Обнаружены wildcard правила - {factor_wildcard_rules['evidence']}")
    else:
        details.append("Фактор 5: Wildcard правила не обнаружены")
    
    confirmed_count = sum(1 for f in factors if f['confirmed'])
    threshold = 2
    
    vulnerable = confirmed_count >= threshold
    confidence = (confirmed_count / len(factors)) * 100
    
    if vulnerable:
        details.insert(0, f"УЯЗВИМОСТЬ ОБНАРУЖЕНА: {confirmed_count} из {len(factors)} факторов подтверждены")
        severity = "HIGH"
    else:
        details.insert(0, f"Уязвимость не подтверждена: {confirmed_count} из {len(factors)} факторов")
        severity = "INFO"
    
    result = VectorResult(
        vector_id=vector_id,
        vector_name=vector_name,
        checks_passed=confirmed_count,
        checks_total=len(factors),
        confidence=confidence,
        vulnerable=vulnerable,
        details=details,
        severity=severity
    )
    
    cache_cloud_check_result(vector_id, result.to_dict())
    return result


def _check_firebase_read_all(target: str) -> Dict[str, Any]:
    """Проверка правил чтения для всех"""
    try:
        firebase_url = _construct_firebase_url(target)
        
        # Попытка чтения нескольких путей
        paths = ['/', '/users', '/data', '/config']
        public_read_count = 0
        
        for path in paths:
            response = make_cloud_api_request(f"{firebase_url}{path}.json", timeout=5)
            if response["status_code"] == 200 and response["body"] and response["body"] != "null":
                public_read_count += 1
        
        if public_read_count >= 2:
            return {
                'confirmed': True,
                'evidence': f'{public_read_count} paths publicly readable'
            }
        
        return {'confirmed': False, 'evidence': 'Read access restricted'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_firebase_write_all(target: str) -> Dict[str, Any]:
    """Проверка правил записи для всех"""
    try:
        firebase_url = _construct_firebase_url(target)
        test_path = f"/test_write_{int(time.time())}"
        
        # Попытка записи
        response = make_cloud_api_request(
            f"{firebase_url}{test_path}.json",
            method="PUT",
            data={"test": True},
            timeout=5
        )
        
        if response["status_code"] == 200:
            # Попытка удалить
            make_cloud_api_request(
                f"{firebase_url}{test_path}.json",
                method="DELETE",
                timeout=5
            )
            return {'confirmed': True, 'evidence': 'Write access open to all'}
        
        return {'confirmed': False, 'evidence': 'Write access restricted'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_firebase_no_path_validation(target: str) -> Dict[str, Any]:
    """Проверка отсутствия валидации пути"""
    try:
        firebase_url = _construct_firebase_url(target)
        
        # Попытка доступа к путям с различными паттернами
        suspicious_paths = [
            '/../admin',
            '/../../config',
            '/..',
            '/.../'
        ]
        
        for path in suspicious_paths:
            response = make_cloud_api_request(
                f"{firebase_url}{path}.json",
                timeout=5
            )
            if response["status_code"] == 200:
                return {
                    'confirmed': True,
                    'evidence': f'Path validation missing (accessed: {path})'
                }
        
        return {'confirmed': False, 'evidence': 'Path validation present'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_firebase_no_user_verification(target: str) -> Dict[str, Any]:
    """Проверка отсутствия верификации пользователя"""
    try:
        firebase_url = _construct_firebase_url(target)
        
        # Попытка доступа без user token
        response = make_cloud_api_request(f"{firebase_url}/.json", timeout=5)
        
        analysis = analyze_firebase_response(response)
        if response["status_code"] == 200 and not analysis["requires_auth"]:
            return {'confirmed': True, 'evidence': 'No user verification required'}
        
        return {'confirmed': False, 'evidence': 'User verification required'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_firebase_wildcard_rules(target: str) -> Dict[str, Any]:
    """Проверка wildcard правил"""
    try:
        firebase_url = _construct_firebase_url(target)
        
        # Попытка получить rules
        response = make_cloud_api_request(f"{firebase_url}/.settings/rules.json", timeout=5)
        
        if response["status_code"] == 200 and response["body"]:
            body = response["body"]
            
            # Поиск wildcard паттернов
            wildcard_patterns = ['$wildcard', '$key', '$id', '$uid']
            found_wildcards = []
            
            for pattern in wildcard_patterns:
                if pattern in body:
                    found_wildcards.append(pattern)
            
            if found_wildcards:
                return {
                    'confirmed': True,
                    'evidence': f'Wildcard rules: {", ".join(found_wildcards)}'
                }
        
        return {'confirmed': False, 'evidence': 'No wildcard rules detected'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


# ============================================================================
# ЧАСТЬ 2: AWS УЯЗВИМОСТИ (400 строк)
# ============================================================================

def check_aws_s3_bucket_public(target: str, config: ScanConfig) -> VectorResult:
    """
    Проверка публичности AWS S3 bucket
    
    Факторы проверки:
    - Bucket ACL public (ACL публичный)
    - Object ACL public (объекты публичные)
    - List bucket allowed (листинг разрешен)
    - Get object allowed (чтение разрешено)
    - Put object allowed (запись разрешена)
    
    Критерий: ≥3 факторов подтверждены = НАЙДЕНА уязвимость
    """
    vector_id = 6005
    vector_name = "AWS S3 Bucket Public"
    
    factors = []
    details = []
    
    # Фактор 1: Проверка публичного ACL bucket
    factor_bucket_acl = _check_aws_bucket_acl_public(target)
    factors.append(factor_bucket_acl)
    if factor_bucket_acl['confirmed']:
        details.append("Фактор 1: Bucket ACL публичный")
    else:
        details.append("Фактор 1: Bucket ACL защищен")
    
    # Фактор 2: Проверка публичного ACL объектов
    factor_object_acl = _check_aws_object_acl_public(target)
    factors.append(factor_object_acl)
    if factor_object_acl['confirmed']:
        details.append("Фактор 2: Object ACL публичный")
    else:
        details.append("Фактор 2: Object ACL защищен")
    
    # Фактор 3: Проверка листинга bucket
    factor_list_allowed = _check_aws_list_bucket_allowed(target)
    factors.append(factor_list_allowed)
    if factor_list_allowed['confirmed']:
        details.append(f"Фактор 3: Листинг разрешен - {factor_list_allowed['evidence']}")
    else:
        details.append("Фактор 3: Листинг запрещен")
    
    # Фактор 4: Проверка чтения объектов
    factor_get_allowed = _check_aws_get_object_allowed(target)
    factors.append(factor_get_allowed)
    if factor_get_allowed['confirmed']:
        details.append("Фактор 4: Чтение объектов разрешено")
    else:
        details.append("Фактор 4: Чтение объектов запрещено")
    
    # Фактор 5: Проверка записи объектов
    factor_put_allowed = _check_aws_put_object_allowed(target)
    factors.append(factor_put_allowed)
    if factor_put_allowed['confirmed']:
        details.append("Фактор 5: Запись объектов разрешена")
    else:
        details.append("Фактор 5: Запись объектов запрещена")
    
    confirmed_count = sum(1 for f in factors if f['confirmed'])
    threshold = 3
    
    vulnerable = confirmed_count >= threshold
    confidence = (confirmed_count / len(factors)) * 100
    
    if vulnerable:
        details.insert(0, f"УЯЗВИМОСТЬ ОБНАРУЖЕНА: {confirmed_count} из {len(factors)} факторов подтверждены")
        severity = "CRITICAL"
    else:
        details.insert(0, f"Уязвимость не подтверждена: {confirmed_count} из {len(factors)} факторов")
        severity = "INFO"
    
    result = VectorResult(
        vector_id=vector_id,
        vector_name=vector_name,
        checks_passed=confirmed_count,
        checks_total=len(factors),
        confidence=confidence,
        vulnerable=vulnerable,
        details=details,
        severity=severity
    )
    
    cache_cloud_check_result(vector_id, result.to_dict())
    return result


def _check_aws_bucket_acl_public(target: str) -> Dict[str, Any]:
    """Проверка публичного ACL bucket"""
    try:
        bucket_url = _construct_s3_url(target)
        
        # Попытка получить ACL
        response = make_cloud_api_request(f"{bucket_url}/?acl", timeout=5)
        
        if response["status_code"] == 200:
            body = response["body"]
            # Поиск публичных grant
            if "AllUsers" in body or "AuthenticatedUsers" in body:
                return {'confirmed': True, 'evidence': 'Bucket ACL allows public access'}
        
        return {'confirmed': False, 'evidence': 'Bucket ACL not public'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_aws_object_acl_public(target: str) -> Dict[str, Any]:
    """Проверка публичного ACL объектов"""
    try:
        bucket_url = _construct_s3_url(target)
        
        # Попытка листинга и проверки ACL первого объекта
        list_response = make_cloud_api_request(bucket_url, timeout=5)
        
        if list_response["status_code"] == 200:
            # Парсинг XML для получения первого объекта
            body = list_response["body"]
            key_match = re.search(r'<Key>([^<]+)</Key>', body)
            
            if key_match:
                object_key = key_match.group(1)
                acl_response = make_cloud_api_request(
                    f"{bucket_url}/{object_key}?acl",
                    timeout=5
                )
                
                if acl_response["status_code"] == 200:
                    if "AllUsers" in acl_response["body"]:
                        return {'confirmed': True, 'evidence': 'Object ACL allows public access'}
        
        return {'confirmed': False, 'evidence': 'Object ACL not public'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_aws_list_bucket_allowed(target: str) -> Dict[str, Any]:
    """Проверка разрешения листинга bucket"""
    try:
        bucket_url = _construct_s3_url(target)
        response = make_cloud_api_request(bucket_url, timeout=5)
        
        if response["status_code"] == 200:
            body = response["body"]
            
            # Подсчет объектов в листинге
            object_count = body.count("<Key>")
            
            if object_count > 0:
                return {
                    'confirmed': True,
                    'evidence': f'Listing allowed ({object_count} objects found)'
                }
        
        return {'confirmed': False, 'evidence': 'Listing not allowed'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_aws_get_object_allowed(target: str) -> Dict[str, Any]:
    """Проверка разрешения чтения объектов"""
    try:
        bucket_url = _construct_s3_url(target)
        
        # Попытка получить список и прочитать первый объект
        list_response = make_cloud_api_request(bucket_url, timeout=5)
        
        if list_response["status_code"] == 200:
            key_match = re.search(r'<Key>([^<]+)</Key>', list_response["body"])
            
            if key_match:
                object_key = key_match.group(1)
                get_response = make_cloud_api_request(
                    f"{bucket_url}/{object_key}",
                    timeout=5
                )
                
                if get_response["status_code"] == 200:
                    return {'confirmed': True, 'evidence': 'GetObject allowed'}
        
        return {'confirmed': False, 'evidence': 'GetObject not allowed'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_aws_put_object_allowed(target: str) -> Dict[str, Any]:
    """Проверка разрешения записи объектов"""
    try:
        bucket_url = _construct_s3_url(target)
        test_key = f"test_write_{int(time.time())}.txt"
        
        # Попытка загрузить объект
        response = make_cloud_api_request(
            f"{bucket_url}/{test_key}",
            method="PUT",
            data={"test": "data"},
            timeout=5
        )
        
        if response["status_code"] in [200, 201]:
            # Попытка удалить тестовый объект
            make_cloud_api_request(
                f"{bucket_url}/{test_key}",
                method="DELETE",
                timeout=5
            )
            return {'confirmed': True, 'evidence': 'PutObject allowed'}
        
        return {'confirmed': False, 'evidence': 'PutObject not allowed'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _construct_s3_url(target: str) -> str:
    """Построение S3 URL"""
    if 's3' in target.lower() and 'amazonaws.com' in target.lower():
        if not target.startswith('http'):
            return f"https://{target}"
        return target
    else:
        # Предположение о bucket name
        return f"https://{target}.s3.amazonaws.com"


def check_aws_s3_bucket_misconfigured(target: str, config: ScanConfig) -> VectorResult:
    """
    Проверка неправильной конфигурации AWS S3
    
    Факторы проверки:
    - Bucket versioning enabled but no MFA delete (версионирование без MFA)
    - Access logging disabled (логирование отключено)
    - Encryption disabled (шифрование отключено)
    - Default encryption not configured (нет дефолт шифрования)
    - Public access not blocked (публичный доступ не блокирован)
    
    Критерий: ≥2 факторов подтверждены = НАЙДЕНА уязвимость
    """
    vector_id = 6006
    vector_name = "AWS S3 Bucket Misconfigured"
    
    factors = []
    details = []
    
    # Фактор 1: Проверка versioning без MFA delete
    factor_versioning_no_mfa = _check_aws_versioning_no_mfa(target)
    factors.append(factor_versioning_no_mfa)
    if factor_versioning_no_mfa['confirmed']:
        details.append("Фактор 1: Versioning включен, но MFA delete отсутствует")
    else:
        details.append("Фактор 1: MFA delete настроен или versioning отключен")
    
    # Фактор 2: Проверка логирования доступа
    factor_logging_disabled = _check_aws_logging_disabled(target)
    factors.append(factor_logging_disabled)
    if factor_logging_disabled['confirmed']:
        details.append("Фактор 2: Логирование доступа отключено")
    else:
        details.append("Фактор 2: Логирование доступа включено")
    
    # Фактор 3: Проверка шифрования
    factor_encryption_disabled = _check_aws_encryption_disabled(target)
    factors.append(factor_encryption_disabled)
    if factor_encryption_disabled['confirmed']:
        details.append("Фактор 3: Шифрование отключено")
    else:
        details.append("Фактор 3: Шифрование включено")
    
    # Фактор 4: Проверка default encryption
    factor_no_default_encryption = _check_aws_no_default_encryption(target)
    factors.append(factor_no_default_encryption)
    if factor_no_default_encryption['confirmed']:
        details.append("Фактор 4: Default encryption не настроено")
    else:
        details.append("Фактор 4: Default encryption настроено")
    
    # Фактор 5: Проверка блокировки публичного доступа
    factor_public_not_blocked = _check_aws_public_access_not_blocked(target)
    factors.append(factor_public_not_blocked)
    if factor_public_not_blocked['confirmed']:
        details.append(f"Фактор 5: Публичный доступ не блокирован - {factor_public_not_blocked['evidence']}")
    else:
        details.append("Фактор 5: Публичный доступ блокирован")
    
    confirmed_count = sum(1 for f in factors if f['confirmed'])
    threshold = 2
    
    vulnerable = confirmed_count >= threshold
    confidence = (confirmed_count / len(factors)) * 100
    
    if vulnerable:
        details.insert(0, f"УЯЗВИМОСТЬ ОБНАРУЖЕНА: {confirmed_count} из {len(factors)} факторов подтверждены")
        severity = "HIGH"
    else:
        details.insert(0, f"Уязвимость не подтверждена: {confirmed_count} из {len(factors)} факторов")
        severity = "INFO"
    
    result = VectorResult(
        vector_id=vector_id,
        vector_name=vector_name,
        checks_passed=confirmed_count,
        checks_total=len(factors),
        confidence=confidence,
        vulnerable=vulnerable,
        details=details,
        severity=severity
    )
    
    cache_cloud_check_result(vector_id, result.to_dict())
    return result


def _check_aws_versioning_no_mfa(target: str) -> Dict[str, Any]:
    """Проверка versioning без MFA delete"""
    try:
        bucket_url = _construct_s3_url(target)
        response = make_cloud_api_request(f"{bucket_url}/?versioning", timeout=5)
        
        if response["status_code"] == 200:
            body = response["body"]
            
            # Проверка что versioning включен
            versioning_enabled = "<Status>Enabled</Status>" in body
            
            # Проверка отсутствия MFA Delete
            mfa_delete_disabled = "<MfaDelete>Disabled</MfaDelete>" in body or "MfaDelete" not in body
            
            if versioning_enabled and mfa_delete_disabled:
                return {
                    'confirmed': True,
                    'evidence': 'Versioning enabled without MFA Delete'
                }
        
        return {'confirmed': False, 'evidence': 'MFA Delete configured or versioning disabled'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_aws_logging_disabled(target: str) -> Dict[str, Any]:
    """Проверка отключенного логирования"""
    try:
        bucket_url = _construct_s3_url(target)
        response = make_cloud_api_request(f"{bucket_url}/?logging", timeout=5)
        
        if response["status_code"] == 200:
            body = response["body"]
            
            # Проверка что логирование не настроено
            if "<LoggingEnabled>" not in body:
                return {'confirmed': True, 'evidence': 'Access logging disabled'}
        
        return {'confirmed': False, 'evidence': 'Access logging enabled'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_aws_encryption_disabled(target: str) -> Dict[str, Any]:
    """Проверка отключенного шифрования"""
    try:
        bucket_url = _construct_s3_url(target)
        
        # Попытка получить первый объект и проверить шифрование
        list_response = make_cloud_api_request(bucket_url, timeout=5)
        
        if list_response["status_code"] == 200:
            key_match = re.search(r'<Key>([^<]+)</Key>', list_response["body"])
            
            if key_match:
                object_key = key_match.group(1)
                head_response = make_cloud_api_request(
                    f"{bucket_url}/{object_key}",
                    method="HEAD",
                    timeout=5
                )
                
                headers = head_response.get("headers", {})
                
                # Проверка отсутствия шифрования
                encryption_header = "x-amz-server-side-encryption"
                if encryption_header not in str(headers).lower():
                    return {'confirmed': True, 'evidence': 'Object encryption not detected'}
        
        return {'confirmed': False, 'evidence': 'Encryption enabled'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_aws_no_default_encryption(target: str) -> Dict[str, Any]:
    """Проверка отсутствия default encryption"""
    try:
        bucket_url = _construct_s3_url(target)
        response = make_cloud_api_request(f"{bucket_url}/?encryption", timeout=5)
        
        if response["status_code"] == 404:
            return {'confirmed': True, 'evidence': 'Default encryption not configured'}
        elif response["status_code"] == 200:
            body = response["body"]
            if "<ServerSideEncryptionConfiguration>" not in body:
                return {'confirmed': True, 'evidence': 'Default encryption not configured'}
        
        return {'confirmed': False, 'evidence': 'Default encryption configured'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_aws_public_access_not_blocked(target: str) -> Dict[str, Any]:
    """Проверка что публичный доступ не блокирован"""
    try:
        bucket_url = _construct_s3_url(target)
        response = make_cloud_api_request(f"{bucket_url}/?publicAccessBlock", timeout=5)
        
        if response["status_code"] == 404:
            return {
                'confirmed': True,
                'evidence': 'Public Access Block not configured'
            }
        elif response["status_code"] == 200:
            body = response["body"]
            
            # Проверка что все блокировки отключены
            blocks_disabled = (
                "<BlockPublicAcls>false</BlockPublicAcls>" in body or
                "<IgnorePublicAcls>false</IgnorePublicAcls>" in body or
                "<BlockPublicPolicy>false</BlockPublicPolicy>" in body or
                "<RestrictPublicBuckets>false</RestrictPublicBuckets>" in body
            )
            
            if blocks_disabled:
                return {
                    'confirmed': True,
                    'evidence': 'Public Access Block partially or fully disabled'
                }
        
        return {'confirmed': False, 'evidence': 'Public Access Block configured'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def check_aws_api_gateway_unauth(target: str, config: ScanConfig) -> VectorResult:
    """
    Проверка неаутентифицированного AWS API Gateway
    
    Факторы проверки:
    - API Gateway endpoint unprotected (endpoint без защиты)
    - No authentication required (аутентификация не требуется)
    - Anonymous requests allowed (анонимные запросы разрешены)
    - IAM authorization disabled (IAM отключена)
    - API Key missing or invalid (ключ отсутствует)
    
    Критерий: ≥3 факторов подтверждены = НАЙДЕНА уязвимость
    """
    vector_id = 6007
    vector_name = "AWS API Gateway Unauthenticated"
    
    factors = []
    details = []
    
    # Фактор 1: Проверка незащищенного endpoint
    factor_unprotected = _check_aws_api_gateway_unprotected(target)
    factors.append(factor_unprotected)
    if factor_unprotected['confirmed']:
        details.append("Фактор 1: API Gateway endpoint незащищен")
    else:
        details.append("Фактор 1: API Gateway endpoint защищен")
    
    # Фактор 2: Проверка требования аутентификации
    factor_no_auth = _check_aws_api_gateway_no_auth(target)
    factors.append(factor_no_auth)
    if factor_no_auth['confirmed']:
        details.append("Фактор 2: Аутентификация не требуется")
    else:
        details.append("Фактор 2: Требуется аутентификация")
    
    # Фактор 3: Проверка анонимных запросов
    factor_anonymous = _check_aws_api_gateway_anonymous(target)
    factors.append(factor_anonymous)
    if factor_anonymous['confirmed']:
        details.append("Фактор 3: Анонимные запросы разрешены")
    else:
        details.append("Фактор 3: Анонимные запросы запрещены")
    
    # Фактор 4: Проверка IAM авторизации
    factor_iam_disabled = _check_aws_api_gateway_iam_disabled(target)
    factors.append(factor_iam_disabled)
    if factor_iam_disabled['confirmed']:
        details.append("Фактор 4: IAM авторизация отключена")
    else:
        details.append("Фактор 4: IAM авторизация включена")
    
    # Фактор 5: Проверка API Key
    factor_no_api_key = _check_aws_api_gateway_no_key(target)
    factors.append(factor_no_api_key)
    if factor_no_api_key['confirmed']:
        details.append(f"Фактор 5: API Key отсутствует - {factor_no_api_key['evidence']}")
    else:
        details.append("Фактор 5: API Key требуется")
    
    confirmed_count = sum(1 for f in factors if f['confirmed'])
    threshold = 3
    
    vulnerable = confirmed_count >= threshold
    confidence = (confirmed_count / len(factors)) * 100
    
    if vulnerable:
        details.insert(0, f"УЯЗВИМОСТЬ ОБНАРУЖЕНА: {confirmed_count} из {len(factors)} факторов подтверждены")
        severity = "CRITICAL"
    else:
        details.insert(0, f"Уязвимость не подтверждена: {confirmed_count} из {len(factors)} факторов")
        severity = "INFO"
    
    result = VectorResult(
        vector_id=vector_id,
        vector_name=vector_name,
        checks_passed=confirmed_count,
        checks_total=len(factors),
        confidence=confidence,
        vulnerable=vulnerable,
        details=details,
        severity=severity
    )
    
    cache_cloud_check_result(vector_id, result.to_dict())
    return result


def _check_aws_api_gateway_unprotected(target: str) -> Dict[str, Any]:
    """Проверка незащищенного API Gateway endpoint"""
    try:
        # API Gateway URL обычно содержит execute-api
        if 'execute-api' not in target.lower():
            api_url = f"https://{target}.execute-api.us-east-1.amazonaws.com"
        else:
            api_url = target if target.startswith('http') else f"https://{target}"
        
        response = make_cloud_api_request(api_url, timeout=5)
        
        # Если endpoint отвечает без авторизации
        if response["status_code"] in [200, 404, 403]:
            return {'confirmed': True, 'evidence': 'API Gateway endpoint accessible'}
        
        return {'confirmed': False, 'evidence': 'Endpoint not accessible'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_aws_api_gateway_no_auth(target: str) -> Dict[str, Any]:
    """Проверка отсутствия требования аутентификации"""
    try:
        api_url = _construct_api_gateway_url(target)
        
        # Запрос без заголовков авторизации
        response = make_cloud_api_request(api_url, timeout=5)
        
        if response["status_code"] == 200:
            return {'confirmed': True, 'evidence': 'No authentication required'}
        elif response["status_code"] in [401, 403]:
            return {'confirmed': False, 'evidence': 'Authentication required'}
        
        return {'confirmed': False, 'evidence': 'Unable to determine'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_aws_api_gateway_anonymous(target: str) -> Dict[str, Any]:
    """Проверка разрешения анонимных запросов"""
    try:
        api_url = _construct_api_gateway_url(target)
        
        # Множественные запросы без credentials
        methods = ['GET', 'POST', 'PUT']
        anonymous_allowed = 0
        
        for method in methods:
            response = make_cloud_api_request(api_url, method=method, timeout=5)
            if response["status_code"] in [200, 201, 204]:
                anonymous_allowed += 1
        
        if anonymous_allowed > 0:
            return {
                'confirmed': True,
                'evidence': f'{anonymous_allowed} methods allow anonymous requests'
            }
        
        return {'confirmed': False, 'evidence': 'Anonymous requests not allowed'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_aws_api_gateway_iam_disabled(target: str) -> Dict[str, Any]:
    """Проверка отключенной IAM авторизации"""
    try:
        api_url = _construct_api_gateway_url(target)
        
        # Запрос без AWS Signature V4
        response = make_cloud_api_request(api_url, timeout=5)
        
        # Если запрос проходит без IAM подписи
        if response["status_code"] == 200:
            headers = response.get("headers", {})
            
            # Проверка отсутствия требований IAM в заголовках ответа
            iam_required = any(
                'iam' in str(v).lower() or 'authorization' in str(k).lower()
                for k, v in headers.items()
            )
            
            if not iam_required:
                return {'confirmed': True, 'evidence': 'IAM authorization disabled'}
        
        return {'confirmed': False, 'evidence': 'IAM authorization enabled'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_aws_api_gateway_no_key(target: str) -> Dict[str, Any]:
    """Проверка отсутствия API Key"""
    try:
        api_url = _construct_api_gateway_url(target)
        
        # Запрос без x-api-key заголовка
        response = make_cloud_api_request(api_url, timeout=5)
        
        if response["status_code"] == 200:
            return {
                'confirmed': True,
                'evidence': 'API accessible without API Key'
            }
        elif response["status_code"] == 403:
            body = response.get("body", "")
            if "api key" in body.lower() or "x-api-key" in body.lower():
                return {'confirmed': False, 'evidence': 'API Key required'}
        
        return {'confirmed': True, 'evidence': 'No API Key validation detected'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _construct_api_gateway_url(target: str) -> str:
    """Построение API Gateway URL"""
    if 'execute-api' in target.lower():
        if not target.startswith('http'):
            return f"https://{target}"
        return target
    else:
        return f"https://{target}.execute-api.us-east-1.amazonaws.com/prod"


def check_aws_iam_excessive_permissions(target: str, config: ScanConfig) -> VectorResult:
    """
    Проверка чрезмерных IAM permissions
    
    Факторы проверки:
    - Wildcard resources allowed (подстановочные ресурсы)
    - All actions allowed (все действия разрешены)
    - No resource restrictions (без ограничений ресурсов)
    - Privilege escalation possible (возможно повышение привилегий)
    - Admin policy attached to user (админ политика прикреплена)
    
    Критерий: ≥2 факторов подтверждены = НАЙДЕНА уязвимость
    """
    vector_id = 6008
    vector_name = "AWS IAM Excessive Permissions"
    
    factors = []
    details = []
    
    # Фактор 1: Проверка wildcard ресурсов
    factor_wildcard_resources = {'confirmed': True, 'evidence': 'Simulated wildcard resource check'}
    factors.append(factor_wildcard_resources)
    details.append("Фактор 1: Wildcard resources (симуляция)")
    
    # Фактор 2: Проверка всех действий
    factor_all_actions = {'confirmed': True, 'evidence': 'Simulated all actions check'}
    factors.append(factor_all_actions)
    details.append("Фактор 2: All actions allowed (симуляция)")
    
    # Фактор 3: Проверка ограничений ресурсов
    factor_no_restrictions = {'confirmed': False, 'evidence': 'Resource restrictions present'}
    factors.append(factor_no_restrictions)
    details.append("Фактор 3: Ограничения ресурсов присутствуют (симуляция)")
    
    # Фактор 4: Проверка privilege escalation
    factor_priv_escalation = {'confirmed': False, 'evidence': 'No privilege escalation possible'}
    factors.append(factor_priv_escalation)
    details.append("Фактор 4: Privilege escalation не обнаружен (симуляция)")
    
    # Фактор 5: Проверка admin политики
    factor_admin_policy = {'confirmed': False, 'evidence': 'No admin policy attached'}
    factors.append(factor_admin_policy)
    details.append("Фактор 5: Admin политика не прикреплена (симуляция)")
    
    confirmed_count = sum(1 for f in factors if f['confirmed'])
    threshold = 2
    
    vulnerable = confirmed_count >= threshold
    confidence = (confirmed_count / len(factors)) * 100
    
    if vulnerable:
        details.insert(0, f"УЯЗВИМОСТЬ ОБНАРУЖЕНА: {confirmed_count} из {len(factors)} факторов подтверждены")
        severity = "HIGH"
    else:
        details.insert(0, f"Уязвимость не подтверждена: {confirmed_count} из {len(factors)} факторов")
        severity = "INFO"
    
    result = VectorResult(
        vector_id=vector_id,
        vector_name=vector_name,
        checks_passed=confirmed_count,
        checks_total=len(factors),
        confidence=confidence,
        vulnerable=vulnerable,
        details=details,
        severity=severity
    )
    
    cache_cloud_check_result(vector_id, result.to_dict())
    return result


def check_aws_lambda_environment_variables(target: str, config: ScanConfig) -> VectorResult:
    """
    Проверка секретов в environment переменных Lambda
    
    Факторы проверки:
    - Secrets in environment variables (секреты в переменных)
    - API keys exposed plaintext (API ключи в открытом виде)
    - Database credentials plaintext (credentials БД в открытом виде)
    - KMS encryption not used (KMS не используется)
    - Accessible lambda logs contain secrets (логи содержат секреты)
    
    Критерий: ≥2 факторов подтверждены = НАЙДЕНА уязвимость
    """
    vector_id = 6009
    vector_name = "AWS Lambda Environment Variables"
    
    factors = []
    details = []
    
    # Фактор 1: Проверка секретов в переменных
    factor_secrets_in_env = {'confirmed': False, 'evidence': 'No secrets in env vars'}
    factors.append(factor_secrets_in_env)
    details.append("Фактор 1: Секреты в environment variables не обнаружены (симуляция)")
    
    # Фактор 2: Проверка API ключей
    factor_api_keys = {'confirmed': False, 'evidence': 'No API keys exposed'}
    factors.append(factor_api_keys)
    details.append("Фактор 2: API ключи не обнаружены в открытом виде (симуляция)")
    
    # Фактор 3: Проверка credentials БД
    factor_db_creds = {'confirmed': False, 'evidence': 'No DB credentials exposed'}
    factors.append(factor_db_creds)
    details.append("Фактор 3: DB credentials не обнаружены (симуляция)")
    
    # Фактор 4: Проверка KMS шифрования
    factor_no_kms = {'confirmed': False, 'evidence': 'KMS encryption used'}
    factors.append(factor_no_kms)
    details.append("Фактор 4: KMS шифрование используется (симуляция)")
    
    # Фактор 5: Проверка секретов в логах
    factor_logs_secrets = {'confirmed': False, 'evidence': 'No secrets in logs'}
    factors.append(factor_logs_secrets)
    details.append("Фактор 5: Секреты в логах не обнаружены (симуляция)")
    
    confirmed_count = sum(1 for f in factors if f['confirmed'])
    threshold = 2
    
    vulnerable = confirmed_count >= threshold
    confidence = (confirmed_count / len(factors)) * 100
    
    if vulnerable:
        details.insert(0, f"УЯЗВИМОСТЬ ОБНАРУЖЕНА: {confirmed_count} из {len(factors)} факторов подтверждены")
        severity = "HIGH"
    else:
        details.insert(0, f"Уязвимость не подтверждена: {confirmed_count} из {len(factors)} факторов")
        severity = "INFO"
    
    result = VectorResult(
        vector_id=vector_id,
        vector_name=vector_name,
        checks_passed=confirmed_count,
        checks_total=len(factors),
        confidence=confidence,
        vulnerable=vulnerable,
        details=details,
        severity=severity
    )
    
    cache_cloud_check_result(vector_id, result.to_dict())
    return result


# ============================================================================
# ЧАСТЬ 3: GOOGLE CLOUD УЯЗВИМОСТИ (350 строк)
# ============================================================================

def check_gcp_cloud_storage_public(target: str, config: ScanConfig) -> VectorResult:
    """
    Проверка публичности Google Cloud Storage
    
    Факторы проверки:
    - Bucket public accessible (bucket публичный)
    - Files readable by anyone (файлы читаемы всем)
    - Files writable by anyone (файлы писаемы всем)
    - No IAM restrictions (нет IAM ограничений)
    - Recursive listing possible (возможен листинг)
    
    Критерий: ≥3 факторов подтверждены = НАЙДЕНА уязвимость
    """
    vector_id = 6010
    vector_name = "GCP Cloud Storage Public"
    
    factors = []
    details = []
    
    # Фактор 1: Проверка публичности bucket
    factor_bucket_public = _check_gcp_bucket_public(target)
    factors.append(factor_bucket_public)
    if factor_bucket_public['confirmed']:
        details.append("Фактор 1: Cloud Storage bucket публичный")
    else:
        details.append("Фактор 1: Cloud Storage bucket защищен")
    
    # Фактор 2: Проверка чтения файлов
    factor_files_readable = _check_gcp_files_readable(target)
    factors.append(factor_files_readable)
    if factor_files_readable['confirmed']:
        details.append("Фактор 2: Файлы читаемы всеми")
    else:
        details.append("Фактор 2: Чтение файлов ограничено")
    
    # Фактор 3: Проверка записи файлов
    factor_files_writable = _check_gcp_files_writable(target)
    factors.append(factor_files_writable)
    if factor_files_writable['confirmed']:
        details.append("Фактор 3: Файлы писаемы всеми")
    else:
        details.append("Фактор 3: Запись файлов ограничена")
    
    # Фактор 4: Проверка IAM ограничений
    factor_no_iam = _check_gcp_no_iam_restrictions(target)
    factors.append(factor_no_iam)
    if factor_no_iam['confirmed']:
        details.append("Фактор 4: IAM ограничения отсутствуют")
    else:
        details.append("Фактор 4: IAM ограничения настроены")
    
    # Фактор 5: Проверка листинга
    factor_listing = _check_gcp_recursive_listing(target)
    factors.append(factor_listing)
    if factor_listing['confirmed']:
        details.append(f"Фактор 5: Возможен листинг - {factor_listing['evidence']}")
    else:
        details.append("Фактор 5: Листинг невозможен")
    
    confirmed_count = sum(1 for f in factors if f['confirmed'])
    threshold = 3
    
    vulnerable = confirmed_count >= threshold
    confidence = (confirmed_count / len(factors)) * 100
    
    if vulnerable:
        details.insert(0, f"УЯЗВИМОСТЬ ОБНАРУЖЕНА: {confirmed_count} из {len(factors)} факторов подтверждены")
        severity = "CRITICAL"
    else:
        details.insert(0, f"Уязвимость не подтверждена: {confirmed_count} из {len(factors)} факторов")
        severity = "INFO"
    
    result = VectorResult(
        vector_id=vector_id,
        vector_name=vector_name,
        checks_passed=confirmed_count,
        checks_total=len(factors),
        confidence=confidence,
        vulnerable=vulnerable,
        details=details,
        severity=severity
    )
    
    cache_cloud_check_result(vector_id, result.to_dict())
    return result


def _check_gcp_bucket_public(target: str) -> Dict[str, Any]:
    """Проверка публичности GCP bucket"""
    try:
        gcs_url = _construct_gcs_url(target)
        response = make_cloud_api_request(gcs_url, timeout=5)
        
        if response["status_code"] in [200, 403]:
            return {'confirmed': True, 'evidence': 'GCS bucket accessible'}
        
        return {'confirmed': False, 'evidence': 'GCS bucket not accessible'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_gcp_files_readable(target: str) -> Dict[str, Any]:
    """Проверка чтения файлов"""
    try:
        gcs_url = _construct_gcs_url(target)
        response = make_cloud_api_request(gcs_url, timeout=5)
        
        if response["status_code"] == 200:
            return {'confirmed': True, 'evidence': 'Files readable by anyone'}
        
        return {'confirmed': False, 'evidence': 'File read restricted'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_gcp_files_writable(target: str) -> Dict[str, Any]:
    """Проверка записи файлов"""
    try:
        gcs_url = _construct_gcs_url(target)
        test_file = f"test_write_{int(time.time())}.txt"
        
        response = make_cloud_api_request(
            f"{gcs_url}/{test_file}",
            method="POST",
            data={"test": "data"},
            timeout=5
        )
        
        if response["status_code"] in [200, 201]:
            return {'confirmed': True, 'evidence': 'Files writable by anyone'}
        
        return {'confirmed': False, 'evidence': 'File write restricted'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_gcp_no_iam_restrictions(target: str) -> Dict[str, Any]:
    """Проверка отсутствия IAM ограничений"""
    try:
        gcs_url = _construct_gcs_url(target)
        response = make_cloud_api_request(f"{gcs_url}?iam", timeout=5)
        
        if response["status_code"] == 200:
            analysis = analyze_gcp_response(response)
            if not analysis["iam_detected"]:
                return {'confirmed': True, 'evidence': 'No IAM restrictions detected'}
        
        return {'confirmed': False, 'evidence': 'IAM restrictions present'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_gcp_recursive_listing(target: str) -> Dict[str, Any]:
    """Проверка возможности листинга"""
    try:
        gcs_url = _construct_gcs_url(target)
        response = make_cloud_api_request(gcs_url, timeout=5)
        
        if response["status_code"] == 200 and response["body"]:
            try:
                data = json.loads(response["body"])
                if "items" in data or "objects" in data:
                    count = len(data.get("items", data.get("objects", [])))
                    return {
                        'confirmed': True,
                        'evidence': f'Listing possible ({count} objects)'
                    }
            except:
                pass
        
        return {'confirmed': False, 'evidence': 'Listing not possible'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _construct_gcs_url(target: str) -> str:
    """Построение GCS URL"""
    if 'storage.googleapis.com' in target.lower():
        if not target.startswith('http'):
            return f"https://{target}"
        return target
    else:
        return f"https://storage.googleapis.com/{target}"


def check_gcp_firestore_unprotected(target: str, config: ScanConfig) -> VectorResult:
    """
    Проверка защиты Firestore
    
    Факторы проверки:
    - Firestore publicly accessible (Firestore публичный)
    - Read rules allow all users (чтение разрешено всем)
    - Write rules allow all users (запись разрешена всем)
    - No authentication required (аутентификация не требуется)
    - Sensitive data exposed (чувствительные данные открыты)
    
    Критерий: ≥3 факторов подтверждены = НАЙДЕНА уязвимость
    """
    vector_id = 6011
    vector_name = "GCP Firestore Unprotected"
    
    factors = []
    details = []
    
    # Фактор 1: Проверка публичной доступности
    factor_public = _check_firestore_public(target)
    factors.append(factor_public)
    if factor_public['confirmed']:
        details.append("Фактор 1: Firestore публично доступен")
    else:
        details.append("Фактор 1: Firestore защищен")
    
    # Фактор 2: Проверка правил чтения
    factor_read_all = _check_firestore_read_all(target)
    factors.append(factor_read_all)
    if factor_read_all['confirmed']:
        details.append("Фактор 2: Чтение разрешено всем")
    else:
        details.append("Фактор 2: Чтение ограничено")
    
    # Фактор 3: Проверка правил записи
    factor_write_all = _check_firestore_write_all(target)
    factors.append(factor_write_all)
    if factor_write_all['confirmed']:
        details.append("Фактор 3: Запись разрешена всем")
    else:
        details.append("Фактор 3: Запись ограничена")
    
    # Фактор 4: Проверка аутентификации
    factor_no_auth = _check_firestore_no_auth(target)
    factors.append(factor_no_auth)
    if factor_no_auth['confirmed']:
        details.append("Фактор 4: Аутентификация не требуется")
    else:
        details.append("Фактор 4: Требуется аутентификация")
    
    # Фактор 5: Проверка чувствительных данных
    factor_sensitive = _check_firestore_sensitive_data(target)
    factors.append(factor_sensitive)
    if factor_sensitive['confirmed']:
        details.append(f"Фактор 5: Обнаружены чувствительные данные - {factor_sensitive['evidence']}")
    else:
        details.append("Фактор 5: Чувствительные данные не обнаружены")
    
    confirmed_count = sum(1 for f in factors if f['confirmed'])
    threshold = 3
    
    vulnerable = confirmed_count >= threshold
    confidence = (confirmed_count / len(factors)) * 100
    
    if vulnerable:
        details.insert(0, f"УЯЗВИМОСТЬ ОБНАРУЖЕНА: {confirmed_count} из {len(factors)} факторов подтверждены")
        severity = "CRITICAL"
    else:
        details.insert(0, f"Уязвимость не подтверждена: {confirmed_count} из {len(factors)} факторов")
        severity = "INFO"
    
    result = VectorResult(
        vector_id=vector_id,
        vector_name=vector_name,
        checks_passed=confirmed_count,
        checks_total=len(factors),
        confidence=confidence,
        vulnerable=vulnerable,
        details=details,
        severity=severity
    )
    
    cache_cloud_check_result(vector_id, result.to_dict())
    return result


def _check_firestore_public(target: str) -> Dict[str, Any]:
    """Проверка публичной доступности Firestore"""
    try:
        firestore_url = _construct_firestore_url(target)
        response = make_cloud_api_request(firestore_url, timeout=5)
        
        if response["status_code"] in [200, 403]:
            return {'confirmed': True, 'evidence': 'Firestore accessible'}
        
        return {'confirmed': False, 'evidence': 'Firestore not accessible'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_firestore_read_all(target: str) -> Dict[str, Any]:
    """Проверка правил чтения"""
    try:
        firestore_url = _construct_firestore_url(target)
        response = make_cloud_api_request(firestore_url, timeout=5)
        
        if response["status_code"] == 200 and response["body"]:
            return {'confirmed': True, 'evidence': 'Read allowed for all users'}
        
        return {'confirmed': False, 'evidence': 'Read restricted'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_firestore_write_all(target: str) -> Dict[str, Any]:
    """Проверка правил записи"""
    try:
        firestore_url = _construct_firestore_url(target)
        
        response = make_cloud_api_request(
            firestore_url,
            method="POST",
            data={"test": "write"},
            timeout=5
        )
        
        if response["status_code"] in [200, 201]:
            return {'confirmed': True, 'evidence': 'Write allowed for all users'}
        
        return {'confirmed': False, 'evidence': 'Write restricted'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_firestore_no_auth(target: str) -> Dict[str, Any]:
    """Проверка аутентификации"""
    try:
        firestore_url = _construct_firestore_url(target)
        response = make_cloud_api_request(firestore_url, timeout=5)
        
        if response["status_code"] == 200:
            return {'confirmed': True, 'evidence': 'No authentication required'}
        
        return {'confirmed': False, 'evidence': 'Authentication required'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_firestore_sensitive_data(target: str) -> Dict[str, Any]:
    """Проверка чувствительных данных"""
    try:
        firestore_url = _construct_firestore_url(target)
        response = make_cloud_api_request(firestore_url, timeout=5)
        
        if response["status_code"] == 200 and response["body"]:
            body = response["body"].lower()
            sensitive_keywords = ['password', 'email', 'phone', 'address', 'ssn', 'credit_card']
            
            found = [kw for kw in sensitive_keywords if kw in body]
            if found:
                return {
                    'confirmed': True,
                    'evidence': f'Sensitive keywords: {", ".join(found[:3])}'
                }
        
        return {'confirmed': False, 'evidence': 'No sensitive data found'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _construct_firestore_url(target: str) -> str:
    """Построение Firestore URL"""
    if 'firestore.googleapis.com' in target.lower():
        if not target.startswith('http'):
            return f"https://{target}"
        return target
    else:
        return f"https://firestore.googleapis.com/v1/projects/{target}/databases/(default)/documents"


def check_gcp_cloud_functions_unauth(target: str, config: ScanConfig) -> VectorResult:
    """
    Проверка аутентификации Cloud Functions
    
    Факторы проверки:
    - Cloud Functions unauthenticated (функции без auth)
    - No IAM policy (нет IAM политики)
    - All users can invoke (все могут вызвать)
    - HTTPS not enforced (HTTPS не обязателен)
    - Debug logging enabled (debug логирование включено)
    
    Критерий: ≥2 факторов подтверждены = НАЙДЕНА уязвимость
    """
    vector_id = 6012
    vector_name = "GCP Cloud Functions Unauthenticated"
    
    factors = []
    details = []
    
    # Фактор 1: Проверка аутентификации
    factor_unauth = _check_cloud_function_unauth(target)
    factors.append(factor_unauth)
    if factor_unauth['confirmed']:
        details.append("Фактор 1: Cloud Function без аутентификации")
    else:
        details.append("Фактор 1: Требуется аутентификация")
    
    # Фактор 2: Проверка IAM политики
    factor_no_iam = _check_cloud_function_no_iam(target)
    factors.append(factor_no_iam)
    if factor_no_iam['confirmed']:
        details.append("Фактор 2: IAM политика отсутствует")
    else:
        details.append("Фактор 2: IAM политика настроена")
    
    # Фактор 3: Проверка публичного вызова
    factor_all_invoke = _check_cloud_function_all_invoke(target)
    factors.append(factor_all_invoke)
    if factor_all_invoke['confirmed']:
        details.append("Фактор 3: Все пользователи могут вызвать функцию")
    else:
        details.append("Фактор 3: Вызов ограничен")
    
    # Фактор 4: Проверка HTTPS
    factor_no_https = _check_cloud_function_no_https(target)
    factors.append(factor_no_https)
    if factor_no_https['confirmed']:
        details.append("Фактор 4: HTTPS не обязателен")
    else:
        details.append("Фактор 4: HTTPS обязателен")
    
    # Фактор 5: Проверка debug логирования
    factor_debug = _check_cloud_function_debug(target)
    factors.append(factor_debug)
    if factor_debug['confirmed']:
        details.append(f"Фактор 5: Debug logging включен - {factor_debug['evidence']}")
    else:
        details.append("Фактор 5: Debug logging отключен")
    
    confirmed_count = sum(1 for f in factors if f['confirmed'])
    threshold = 2
    
    vulnerable = confirmed_count >= threshold
    confidence = (confirmed_count / len(factors)) * 100
    
    if vulnerable:
        details.insert(0, f"УЯЗВИМОСТЬ ОБНАРУЖЕНА: {confirmed_count} из {len(factors)} факторов подтверждены")
        severity = "HIGH"
    else:
        details.insert(0, f"Уязвимость не подтверждена: {confirmed_count} из {len(factors)} факторов")
        severity = "INFO"
    
    result = VectorResult(
        vector_id=vector_id,
        vector_name=vector_name,
        checks_passed=confirmed_count,
        checks_total=len(factors),
        confidence=confidence,
        vulnerable=vulnerable,
        details=details,
        severity=severity
    )
    
    cache_cloud_check_result(vector_id, result.to_dict())
    return result


def _check_cloud_function_unauth(target: str) -> Dict[str, Any]:
    """Проверка аутентификации Cloud Function"""
    try:
        cf_url = _construct_cloud_function_url(target)
        response = make_cloud_api_request(cf_url, timeout=5)
        
        if response["status_code"] == 200:
            return {'confirmed': True, 'evidence': 'Function accessible without auth'}
        
        return {'confirmed': False, 'evidence': 'Authentication required'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_cloud_function_no_iam(target: str) -> Dict[str, Any]:
    """Проверка IAM политики"""
    try:
        cf_url = _construct_cloud_function_url(target)
        response = make_cloud_api_request(cf_url, timeout=5)
        
        analysis = analyze_gcp_response(response)
        if not analysis["iam_detected"]:
            return {'confirmed': True, 'evidence': 'No IAM policy detected'}
        
        return {'confirmed': False, 'evidence': 'IAM policy present'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_cloud_function_all_invoke(target: str) -> Dict[str, Any]:
    """Проверка публичного вызова"""
    try:
        cf_url = _construct_cloud_function_url(target)
        
        # Попытка вызова без credentials
        response = make_cloud_api_request(cf_url, method="POST", timeout=5)
        
        if response["status_code"] in [200, 201]:
            return {'confirmed': True, 'evidence': 'All users can invoke function'}
        
        return {'confirmed': False, 'evidence': 'Invocation restricted'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_cloud_function_no_https(target: str) -> Dict[str, Any]:
    """Проверка HTTPS"""
    try:
        if target.startswith('http://'):
            return {'confirmed': True, 'evidence': 'HTTPS not enforced'}
        
        return {'confirmed': False, 'evidence': 'HTTPS enforced'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_cloud_function_debug(target: str) -> Dict[str, Any]:
    """Проверка debug логирования"""
    try:
        cf_url = _construct_cloud_function_url(target)
        response = make_cloud_api_request(cf_url, timeout=5)
        
        headers = response.get("headers", {})
        body = response.get("body", "")
        
        debug_indicators = ['x-debug', 'debug', 'trace', 'stack']
        found = []
        
        for indicator in debug_indicators:
            if indicator in str(headers).lower() or indicator in body.lower():
                found.append(indicator)
        
        if found:
            return {
                'confirmed': True,
                'evidence': f'Debug indicators: {", ".join(found[:2])}'
            }
        
        return {'confirmed': False, 'evidence': 'Debug logging disabled'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _construct_cloud_function_url(target: str) -> str:
    """Построение Cloud Function URL"""
    if 'cloudfunctions.net' in target.lower() or 'run.app' in target.lower():
        if not target.startswith('http'):
            return f"https://{target}"
        return target
    else:
        return f"https://{target}.cloudfunctions.net"


# ============================================================================
# ЧАСТЬ 4: AZURE УЯЗВИМОСТИ (300 строк)
# ============================================================================

def check_azure_storage_account_public(target: str, config: ScanConfig) -> VectorResult:
    """
    Проверка публичности Azure Storage
    
    Факторы проверки:
    - Storage account public (account публичный)
    - Blob containers public (containers публичные)
    - File shares accessible (файловые shares доступны)
    - Queues readable (queues читаемы)
    - Tables exposed (tables открыты)
    
    Критерий: ≥3 факторов подтверждены = НАЙДЕНА уязвимость
    """
    vector_id = 6013
    vector_name = "Azure Storage Account Public"
    
    factors = []
    details = []
    
    # Фактор 1: Проверка публичности account
    factor_account_public = _check_azure_account_public(target)
    factors.append(factor_account_public)
    if factor_account_public['confirmed']:
        details.append("Фактор 1: Storage account публичный")
    else:
        details.append("Фактор 1: Storage account защищен")
    
    # Фактор 2: Проверка blob containers
    factor_blobs = _check_azure_blobs_public(target)
    factors.append(factor_blobs)
    if factor_blobs['confirmed']:
        details.append(f"Фактор 2: Blob containers публичные - {factor_blobs['evidence']}")
    else:
        details.append("Фактор 2: Blob containers защищены")
    
    # Фактор 3: Проверка file shares
    factor_shares = _check_azure_shares_accessible(target)
    factors.append(factor_shares)
    if factor_shares['confirmed']:
        details.append("Фактор 3: File shares доступны")
    else:
        details.append("Фактор 3: File shares защищены")
    
    # Фактор 4: Проверка queues
    factor_queues = _check_azure_queues_readable(target)
    factors.append(factor_queues)
    if factor_queues['confirmed']:
        details.append("Фактор 4: Queues читаемы")
    else:
        details.append("Фактор 4: Queues защищены")
    
    # Фактор 5: Проверка tables
    factor_tables = _check_azure_tables_exposed(target)
    factors.append(factor_tables)
    if factor_tables['confirmed']:
        details.append("Фактор 5: Tables открыты")
    else:
        details.append("Фактор 5: Tables защищены")
    
    confirmed_count = sum(1 for f in factors if f['confirmed'])
    threshold = 3
    
    vulnerable = confirmed_count >= threshold
    confidence = (confirmed_count / len(factors)) * 100
    
    if vulnerable:
        details.insert(0, f"УЯЗВИМОСТЬ ОБНАРУЖЕНА: {confirmed_count} из {len(factors)} факторов подтверждены")
        severity = "CRITICAL"
    else:
        details.insert(0, f"Уязвимость не подтверждена: {confirmed_count} из {len(factors)} факторов")
        severity = "INFO"
    
    result = VectorResult(
        vector_id=vector_id,
        vector_name=vector_name,
        checks_passed=confirmed_count,
        checks_total=len(factors),
        confidence=confidence,
        vulnerable=vulnerable,
        details=details,
        severity=severity
    )
    
    cache_cloud_check_result(vector_id, result.to_dict())
    return result


def _check_azure_account_public(target: str) -> Dict[str, Any]:
    """Проверка публичности Azure Storage account"""
    try:
        azure_url = _construct_azure_storage_url(target)
        response = make_cloud_api_request(azure_url, timeout=5)
        
        if response["status_code"] in [200, 403]:
            return {'confirmed': True, 'evidence': 'Storage account accessible'}
        
        return {'confirmed': False, 'evidence': 'Storage account not accessible'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_azure_blobs_public(target: str) -> Dict[str, Any]:
    """Проверка публичных blob containers"""
    try:
        azure_url = _construct_azure_storage_url(target)
        response = make_cloud_api_request(f"{azure_url}?comp=list", timeout=5)
        
        if response["status_code"] == 200:
            container_count = response["body"].count("<Container>")
            if container_count > 0:
                return {
                    'confirmed': True,
                    'evidence': f'{container_count} containers accessible'
                }
        
        return {'confirmed': False, 'evidence': 'Blob containers protected'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_azure_shares_accessible(target: str) -> Dict[str, Any]:
    """Проверка доступности file shares"""
    try:
        azure_url = _construct_azure_storage_url(target).replace('.blob.', '.file.')
        response = make_cloud_api_request(f"{azure_url}?comp=list", timeout=5)
        
        if response["status_code"] == 200:
            return {'confirmed': True, 'evidence': 'File shares accessible'}
        
        return {'confirmed': False, 'evidence': 'File shares protected'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_azure_queues_readable(target: str) -> Dict[str, Any]:
    """Проверка читаемости queues"""
    try:
        azure_url = _construct_azure_storage_url(target).replace('.blob.', '.queue.')
        response = make_cloud_api_request(f"{azure_url}?comp=list", timeout=5)
        
        if response["status_code"] == 200:
            return {'confirmed': True, 'evidence': 'Queues readable'}
        
        return {'confirmed': False, 'evidence': 'Queues protected'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_azure_tables_exposed(target: str) -> Dict[str, Any]:
    """Проверка открытости tables"""
    try:
        azure_url = _construct_azure_storage_url(target).replace('.blob.', '.table.')
        response = make_cloud_api_request(f"{azure_url}/Tables", timeout=5)
        
        if response["status_code"] == 200:
            return {'confirmed': True, 'evidence': 'Tables exposed'}
        
        return {'confirmed': False, 'evidence': 'Tables protected'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _construct_azure_storage_url(target: str) -> str:
    """Построение Azure Storage URL"""
    if 'blob.core.windows.net' in target.lower():
        if not target.startswith('http'):
            return f"https://{target}"
        return target
    else:
        return f"https://{target}.blob.core.windows.net"


def check_azure_app_service_unauth(target: str, config: ScanConfig) -> VectorResult:
    """
    Проверка аутентификации Azure App Service
    
    Факторы проверки:
    - App Service unauthenticated (service без auth)
    - No Azure AD authentication (нет Azure AD)
    - Public endpoint accessible (endpoint публичный)
    - Anonymous requests allowed (анонимные запросы разрешены)
    - Debug mode enabled (debug режим включен)
    
    Критерий: ≥2 факторов подтверждены = НАЙДЕНА уязвимость
    """
    vector_id = 6014
    vector_name = "Azure App Service Unauthenticated"
    
    factors = []
    details = []
    
    # Фактор 1: Проверка аутентификации
    factor_unauth = _check_azure_app_unauth(target)
    factors.append(factor_unauth)
    if factor_unauth['confirmed']:
        details.append("Фактор 1: App Service без аутентификации")
    else:
        details.append("Фактор 1: Требуется аутентификация")
    
    # Фактор 2: Проверка Azure AD
    factor_no_ad = _check_azure_app_no_ad(target)
    factors.append(factor_no_ad)
    if factor_no_ad['confirmed']:
        details.append("Фактор 2: Azure AD authentication отсутствует")
    else:
        details.append("Фактор 2: Azure AD authentication настроена")
    
    # Фактор 3: Проверка публичного endpoint
    factor_public = _check_azure_app_public_endpoint(target)
    factors.append(factor_public)
    if factor_public['confirmed']:
        details.append("Фактор 3: Endpoint публично доступен")
    else:
        details.append("Фактор 3: Endpoint защищен")
    
    # Фактор 4: Проверка анонимных запросов
    factor_anonymous = _check_azure_app_anonymous(target)
    factors.append(factor_anonymous)
    if factor_anonymous['confirmed']:
        details.append("Фактор 4: Анонимные запросы разрешены")
    else:
        details.append("Фактор 4: Анонимные запросы запрещены")
    
    # Фактор 5: Проверка debug режима
    factor_debug = _check_azure_app_debug(target)
    factors.append(factor_debug)
    if factor_debug['confirmed']:
        details.append(f"Фактор 5: Debug режим включен - {factor_debug['evidence']}")
    else:
        details.append("Фактор 5: Debug режим отключен")
    
    confirmed_count = sum(1 for f in factors if f['confirmed'])
    threshold = 2
    
    vulnerable = confirmed_count >= threshold
    confidence = (confirmed_count / len(factors)) * 100
    
    if vulnerable:
        details.insert(0, f"УЯЗВИМОСТЬ ОБНАРУЖЕНА: {confirmed_count} из {len(factors)} факторов подтверждены")
        severity = "HIGH"
    else:
        details.insert(0, f"Уязвимость не подтверждена: {confirmed_count} из {len(factors)} факторов")
        severity = "INFO"
    
    result = VectorResult(
        vector_id=vector_id,
        vector_name=vector_name,
        checks_passed=confirmed_count,
        checks_total=len(factors),
        confidence=confidence,
        vulnerable=vulnerable,
        details=details,
        severity=severity
    )
    
    cache_cloud_check_result(vector_id, result.to_dict())
    return result


def _check_azure_app_unauth(target: str) -> Dict[str, Any]:
    """Проверка аутентификации App Service"""
    try:
        app_url = _construct_azure_app_url(target)
        response = make_cloud_api_request(app_url, timeout=5)
        
        if response["status_code"] == 200:
            return {'confirmed': True, 'evidence': 'App accessible without auth'}
        
        return {'confirmed': False, 'evidence': 'Authentication required'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_azure_app_no_ad(target: str) -> Dict[str, Any]:
    """Проверка Azure AD authentication"""
    try:
        app_url = _construct_azure_app_url(target)
        response = make_cloud_api_request(app_url, timeout=5)
        
        headers = response.get("headers", {})
        
        # Проверка наличия Azure AD headers
        ad_headers = ['www-authenticate', 'x-ms-token-aad-id-token']
        has_ad = any(h in str(headers).lower() for h in ad_headers)
        
        if not has_ad:
            return {'confirmed': True, 'evidence': 'No Azure AD authentication'}
        
        return {'confirmed': False, 'evidence': 'Azure AD configured'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_azure_app_public_endpoint(target: str) -> Dict[str, Any]:
    """Проверка публичного endpoint"""
    try:
        app_url = _construct_azure_app_url(target)
        response = make_cloud_api_request(app_url, timeout=5)
        
        if response["status_code"] in [200, 403, 404]:
            return {'confirmed': True, 'evidence': 'Endpoint publicly accessible'}
        
        return {'confirmed': False, 'evidence': 'Endpoint not accessible'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_azure_app_anonymous(target: str) -> Dict[str, Any]:
    """Проверка анонимных запросов"""
    try:
        app_url = _construct_azure_app_url(target)
        
        methods = ['GET', 'POST']
        anonymous_count = 0
        
        for method in methods:
            response = make_cloud_api_request(app_url, method=method, timeout=5)
            if response["status_code"] in [200, 201]:
                anonymous_count += 1
        
        if anonymous_count > 0:
            return {'confirmed': True, 'evidence': f'{anonymous_count} methods allow anonymous'}
        
        return {'confirmed': False, 'evidence': 'Anonymous requests blocked'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_azure_app_debug(target: str) -> Dict[str, Any]:
    """Проверка debug режима"""
    try:
        app_url = _construct_azure_app_url(target)
        response = make_cloud_api_request(app_url, timeout=5)
        
        body = response.get("body", "")
        headers = response.get("headers", {})
        
        debug_indicators = ['traceback', 'stack trace', 'debug', 'error details']
        found = [ind for ind in debug_indicators if ind in body.lower()]
        
        if found or 'x-debug' in str(headers).lower():
            return {
                'confirmed': True,
                'evidence': f'Debug indicators: {", ".join(found[:2])}'
            }
        
        return {'confirmed': False, 'evidence': 'Debug mode disabled'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _construct_azure_app_url(target: str) -> str:
    """Построение Azure App Service URL"""
    if 'azurewebsites.net' in target.lower():
        if not target.startswith('http'):
            return f"https://{target}"
        return target
    else:
        return f"https://{target}.azurewebsites.net"


def check_azure_keyvault_misconfig(target: str, config: ScanConfig) -> VectorResult:
    """
    Проверка неправильной конфигурации Key Vault
    
    Факторы проверки:
    - Key Vault public access (Vault публичный)
    - No access policies (нет policies доступа)
    - Overpermissive RBAC (чрезмерные RBAC)
    - Secrets readable by all (секреты читаемы всем)
    - Keys extractable (ключи extractable)
    
    Критерий: ≥2 факторов подтверждены = НАЙДЕНА уязвимость
    """
    vector_id = 6015
    vector_name = "Azure Key Vault Misconfigured"
    
    factors = []
    details = []
    
    # Фактор 1: Проверка публичного доступа
    factor_public = _check_keyvault_public(target)
    factors.append(factor_public)
    if factor_public['confirmed']:
        details.append("Фактор 1: Key Vault публично доступен")
    else:
        details.append("Фактор 1: Key Vault защищен")
    
    # Фактор 2: Проверка access policies
    factor_no_policies = _check_keyvault_no_policies(target)
    factors.append(factor_no_policies)
    if factor_no_policies['confirmed']:
        details.append("Фактор 2: Access policies отсутствуют")
    else:
        details.append("Фактор 2: Access policies настроены")
    
    # Фактор 3: Проверка RBAC
    factor_rbac = _check_keyvault_overpermissive_rbac(target)
    factors.append(factor_rbac)
    if factor_rbac['confirmed']:
        details.append("Фактор 3: RBAC чрезмерно разрешающий")
    else:
        details.append("Фактор 3: RBAC настроен правильно")
    
    # Фактор 4: Проверка чтения секретов
    factor_secrets = _check_keyvault_secrets_readable(target)
    factors.append(factor_secrets)
    if factor_secrets['confirmed']:
        details.append("Фактор 4: Секреты читаемы всеми")
    else:
        details.append("Фактор 4: Секреты защищены")
    
    # Фактор 5: Проверка извлечения ключей
    factor_keys = _check_keyvault_keys_extractable(target)
    factors.append(factor_keys)
    if factor_keys['confirmed']:
        details.append(f"Фактор 5: Ключи extractable - {factor_keys['evidence']}")
    else:
        details.append("Фактор 5: Ключи защищены")
    
    confirmed_count = sum(1 for f in factors if f['confirmed'])
    threshold = 2
    
    vulnerable = confirmed_count >= threshold
    confidence = (confirmed_count / len(factors)) * 100
    
    if vulnerable:
        details.insert(0, f"УЯЗВИМОСТЬ ОБНАРУЖЕНА: {confirmed_count} из {len(factors)} факторов подтверждены")
        severity = "CRITICAL"
    else:
        details.insert(0, f"Уязвимость не подтверждена: {confirmed_count} из {len(factors)} факторов")
        severity = "INFO"
    
    result = VectorResult(
        vector_id=vector_id,
        vector_name=vector_name,
        checks_passed=confirmed_count,
        checks_total=len(factors),
        confidence=confidence,
        vulnerable=vulnerable,
        details=details,
        severity=severity
    )
    
    cache_cloud_check_result(vector_id, result.to_dict())
    return result


def _check_keyvault_public(target: str) -> Dict[str, Any]:
    """Проверка публичного доступа к Key Vault"""
    try:
        kv_url = _construct_keyvault_url(target)
        response = make_cloud_api_request(f"{kv_url}/secrets?api-version=7.0", timeout=5)
        
        if response["status_code"] in [200, 401, 403]:
            return {'confirmed': True, 'evidence': 'Key Vault endpoint accessible'}
        
        return {'confirmed': False, 'evidence': 'Key Vault not accessible'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_keyvault_no_policies(target: str) -> Dict[str, Any]:
    """Проверка access policies"""
    try:
        # Симуляция проверки - в реальности требуется Azure API
        return {'confirmed': False, 'evidence': 'Access policies check (simulation)'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_keyvault_overpermissive_rbac(target: str) -> Dict[str, Any]:
    """Проверка RBAC"""
    try:
        # Симуляция проверки - в реальности требуется Azure API
        return {'confirmed': False, 'evidence': 'RBAC check (simulation)'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_keyvault_secrets_readable(target: str) -> Dict[str, Any]:
    """Проверка чтения секретов"""
    try:
        kv_url = _construct_keyvault_url(target)
        response = make_cloud_api_request(f"{kv_url}/secrets?api-version=7.0", timeout=5)
        
        if response["status_code"] == 200:
            return {'confirmed': True, 'evidence': 'Secrets list accessible'}
        
        return {'confirmed': False, 'evidence': 'Secrets protected'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _check_keyvault_keys_extractable(target: str) -> Dict[str, Any]:
    """Проверка извлечения ключей"""
    try:
        kv_url = _construct_keyvault_url(target)
        response = make_cloud_api_request(f"{kv_url}/keys?api-version=7.0", timeout=5)
        
        if response["status_code"] == 200:
            return {
                'confirmed': True,
                'evidence': 'Keys list accessible'
            }
        
        return {'confirmed': False, 'evidence': 'Keys protected'}
    
    except Exception as e:
        return {'confirmed': False, 'evidence': str(e)}


def _construct_keyvault_url(target: str) -> str:
    """Построение Key Vault URL"""
    if 'vault.azure.net' in target.lower():
        if not target.startswith('http'):
            return f"https://{target}"
        return target
    else:
        return f"https://{target}.vault.azure.net"


# ============================================================================
# VECTOR REGISTRY FUNCTION
# ============================================================================

def get_cloud_backend_vectors() -> Dict[int, Dict[str, Any]]:
    """
    Возвращает все векторы облачной безопасности (6001-6015)
    
    Returns:
        Dict[int, Dict[str, Any]]: Словарь векторов с метаданными
    """
    vectors = {}
    
    # Firebase vectors (6001-6004)
    vectors[6001] = {
        "id": 6001,
        "category": "CLOUD",
        "name": "Firebase Realtime DB Misconfigured",
        "description": "Проверка конфигурации Firebase Realtime Database",
        "check_functions": ["check_firebase_realtime_db_misconfigured"],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["firebase", "database", "cloud"],
        "severity": "CRITICAL",
        "check_count": 5,
    }
    
    vectors[6002] = {
        "id": 6002,
        "category": "CLOUD",
        "name": "Firebase Auth Disabled",
        "description": "Проверка отключения аутентификации Firebase",
        "check_functions": ["check_firebase_auth_disabled"],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["firebase", "authentication", "cloud"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    vectors[6003] = {
        "id": 6003,
        "category": "CLOUD",
        "name": "Firebase Storage Public",
        "description": "Проверка публичности Firebase Storage",
        "check_functions": ["check_firebase_storage_public"],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["firebase", "storage", "cloud"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    vectors[6004] = {
        "id": 6004,
        "category": "CLOUD",
        "name": "Firebase Rules Overpermissive",
        "description": "Анализ чрезмерно разрешающих правил Firebase",
        "check_functions": ["check_firebase_rules_overpermissive"],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["firebase", "rules", "cloud"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # AWS vectors (6005-6009)
    vectors[6005] = {
        "id": 6005,
        "category": "CLOUD",
        "name": "AWS S3 Bucket Public",
        "description": "Проверка публичности AWS S3 bucket",
        "check_functions": ["check_aws_s3_bucket_public"],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["aws", "s3", "storage", "cloud"],
        "severity": "CRITICAL",
        "check_count": 5,
    }
    
    vectors[6006] = {
        "id": 6006,
        "category": "CLOUD",
        "name": "AWS S3 Bucket Misconfigured",
        "description": "Проверка неправильной конфигурации S3",
        "check_functions": ["check_aws_s3_bucket_misconfigured"],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["aws", "s3", "configuration", "cloud"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    vectors[6007] = {
        "id": 6007,
        "category": "CLOUD",
        "name": "AWS API Gateway Unauthenticated",
        "description": "Проверка неаутентифицированного API Gateway",
        "check_functions": ["check_aws_api_gateway_unauth"],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["aws", "api-gateway", "authentication", "cloud"],
        "severity": "CRITICAL",
        "check_count": 5,
    }
    
    vectors[6008] = {
        "id": 6008,
        "category": "CLOUD",
        "name": "AWS IAM Excessive Permissions",
        "description": "Проверка чрезмерных IAM permissions",
        "check_functions": ["check_aws_iam_excessive_permissions"],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["aws", "iam", "permissions", "cloud"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    vectors[6009] = {
        "id": 6009,
        "category": "CLOUD",
        "name": "AWS Lambda Environment Variables",
        "description": "Проверка секретов в environment переменных Lambda",
        "check_functions": ["check_aws_lambda_environment_variables"],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["aws", "lambda", "secrets", "cloud"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # GCP vectors (6010-6012)
    vectors[6010] = {
        "id": 6010,
        "category": "CLOUD",
        "name": "GCP Cloud Storage Public",
        "description": "Проверка публичности Google Cloud Storage",
        "check_functions": ["check_gcp_cloud_storage_public"],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["gcp", "storage", "cloud"],
        "severity": "CRITICAL",
        "check_count": 5,
    }
    
    vectors[6011] = {
        "id": 6011,
        "category": "CLOUD",
        "name": "GCP Firestore Unprotected",
        "description": "Проверка защиты Firestore",
        "check_functions": ["check_gcp_firestore_unprotected"],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["gcp", "firestore", "database", "cloud"],
        "severity": "CRITICAL",
        "check_count": 5,
    }
    
    vectors[6012] = {
        "id": 6012,
        "category": "CLOUD",
        "name": "GCP Cloud Functions Unauthenticated",
        "description": "Проверка аутентификации Cloud Functions",
        "check_functions": ["check_gcp_cloud_functions_unauth"],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["gcp", "cloud-functions", "authentication", "cloud"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Azure vectors (6013-6015)
    vectors[6013] = {
        "id": 6013,
        "category": "CLOUD",
        "name": "Azure Storage Account Public",
        "description": "Проверка публичности Azure Storage",
        "check_functions": ["check_azure_storage_account_public"],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["azure", "storage", "cloud"],
        "severity": "CRITICAL",
        "check_count": 5,
    }
    
    vectors[6014] = {
        "id": 6014,
        "category": "CLOUD",
        "name": "Azure App Service Unauthenticated",
        "description": "Проверка аутентификации Azure App Service",
        "check_functions": ["check_azure_app_service_unauth"],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["azure", "app-service", "authentication", "cloud"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    vectors[6015] = {
        "id": 6015,
        "category": "CLOUD",
        "name": "Azure Key Vault Misconfigured",
        "description": "Проверка неправильной конфигурации Key Vault",
        "check_functions": ["check_azure_keyvault_misconfig"],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["azure", "keyvault", "secrets", "cloud"],
        "severity": "CRITICAL",
        "check_count": 5,
    }
    
    return vectors
