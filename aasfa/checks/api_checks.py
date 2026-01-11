"""aasfa.checks.api_checks

Проверки безопасности API и web-сервисов.

Цель модуля — найти типичные ошибки конфигурации и уязвимости API:
- отсутствие аутентификации/авторизации
- отсутствие HTTPS / слабая транспортная защита
- отсутствие rate limiting
- небезопасная конфигурация CORS
- информационные утечки (Swagger/OpenAPI, Actuator, GraphQL introspection)
- слабые JWT секреты и небезопасные claims
- типичные инъекции (SQLi/command/path traversal) по простым безопасным эвристикам

Общий подход:
- По возможности выполняем несколько независимых сигналов (многофакторность):
  например, для "API без аутентификации" проверяем несколько endpoint'ов,
  и дополнительно анализируем ответ (JSON/типичные поля).
- Все запросы ограничены таймаутом.
- Мы не пытаемся выполнять разрушительные действия: POST/PUT/DELETE используются
  только для безопасных тестов (например, login с дефолтными кредами).

Каждая функция возвращает dict: {"vulnerable": bool, "details": str, ...}
"""

from __future__ import annotations

import json
import re
import socket
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

try:
    import requests
except Exception:  # pragma: no cover
    requests = None  # type: ignore

try:
    import jwt
except Exception:  # pragma: no cover
    jwt = None  # type: ignore


CheckResult = Dict[str, Any]


# =============================
# Общие helper-функции
# =============================

def _clamp_timeout(timeout: int | float, *, lower: float = 1.0, upper: float = 10.0) -> float:
    """Нормализует таймаут для сетевых операций."""

    try:
        t = float(timeout)
    except Exception:
        t = upper
    if t != t:
        t = upper
    return max(lower, min(t, upper))


def _result(vulnerable: bool, details: str, *, severity: Optional[str] = None, **extra: Any) -> CheckResult:
    data: CheckResult = {"vulnerable": bool(vulnerable), "details": str(details)}
    if severity:
        data['severity'] = severity
    data.update(extra)
    return data


def _is_port_open(host: str, port: int, timeout: float) -> bool:
    """Быстрая проверка TCP порта."""

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(_clamp_timeout(timeout, upper=3.0))
        ok = s.connect_ex((host, int(port))) == 0
        s.close()
        return ok
    except Exception:
        return False


def _discover_http_ports(target: str, port: int, timeout: float) -> List[int]:
    """Пытается найти подходящие HTTP(S) порты."""

    candidates: List[int] = []
    try:
        p = int(port)
        if 1 <= p <= 65535:
            candidates.append(p)
    except Exception:
        pass

    for p in [80, 8080, 8000, 3000, 5000, 8888, 443, 8443, 9443]:
        if p not in candidates:
            candidates.append(p)

    open_ports = [p for p in candidates if _is_port_open(target, p, timeout)]
    return open_ports[:5] or candidates[:3]


def _build_url(host: str, port: int, path: str, *, https: bool) -> str:
    if not path.startswith('/'):
        path = '/' + path
    scheme = 'https' if https else 'http'
    return f"{scheme}://{host}:{int(port)}{path}"


def _request(
    method: str,
    url: str,
    *,
    timeout: float,
    headers: Optional[Dict[str, str]] = None,
    json_body: Any = None,
    data: Any = None,
    allow_redirects: bool = False,
) -> Optional["requests.Response"]:
    """Безопасный HTTP запрос через requests."""

    if requests is None:
        return None

    try:
        return requests.request(
            method=method,
            url=url,
            headers=headers,
            json=json_body,
            data=data,
            timeout=_clamp_timeout(timeout),
            verify=False,
            allow_redirects=allow_redirects,
        )
    except Exception:
        return None


def _try_json(resp: "requests.Response") -> Optional[Any]:
    try:
        return resp.json()
    except Exception:
        return None


def _looks_like_auth_challenge(resp: "requests.Response") -> bool:
    """Эвристика: ответ требует авторизацию."""

    if resp.status_code in {401, 403}:
        return True
    auth_hdr = resp.headers.get('WWW-Authenticate', '')
    if auth_hdr:
        return True
    body = (resp.text or '').lower()
    return any(x in body for x in ['unauthorized', 'forbidden', 'auth required', 'login required'])


def _sensitive_json_keys_found(obj: Any) -> List[str]:
    """Ищет чувствительные ключи в JSON."""

    found: List[str] = []
    sensitive = {'password', 'passwd', 'pwd', 'token', 'secret', 'api_key', 'apikey', 'access_token', 'refresh_token'}

    def walk(x: Any):
        if isinstance(x, dict):
            for k, v in x.items():
                try:
                    k_l = str(k).lower()
                    if k_l in sensitive:
                        found.append(k_l)
                except Exception:
                    pass
                walk(v)
        elif isinstance(x, list):
            for i in x:
                walk(i)

    walk(obj)
    return sorted(set(found))


def _extract_jwt_from_response(resp: "requests.Response") -> Optional[str]:
    """Пытается извлечь JWT из ответа."""

    j = _try_json(resp)
    if isinstance(j, dict):
        for k in ['token', 'access_token', 'jwt', 'id_token']:
            v = j.get(k)
            if isinstance(v, str) and v.count('.') == 2:
                return v

    text = resp.text or ''
    m = re.search(r'([A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)', text)
    if m:
        return m.group(1)

    return None


def _jwt_header(token: str) -> Optional[Dict[str, Any]]:
    """Декодирует JWT header без проверки подписи."""

    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        header_b64 = parts[0] + '=' * (-len(parts[0]) % 4)
        raw = json.loads(__import__('base64').urlsafe_b64decode(header_b64.encode()).decode('utf-8', errors='ignore'))
        if isinstance(raw, dict):
            return raw
    except Exception:
        return None
    return None


def _jwt_payload(token: str) -> Optional[Dict[str, Any]]:
    """Декодирует JWT payload без проверки подписи."""

    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        payload_b64 = parts[1] + '=' * (-len(parts[1]) % 4)
        raw = json.loads(__import__('base64').urlsafe_b64decode(payload_b64.encode()).decode('utf-8', errors='ignore'))
        if isinstance(raw, dict):
            return raw
    except Exception:
        return None
    return None


def _jwt_weak_secret(token: str, secrets: Sequence[str]) -> Optional[str]:
    """Пытается подобрать слабый секрет для HS256."""

    if jwt is None:
        return None

    header = _jwt_header(token) or {}
    alg = str(header.get('alg', '')).upper()
    if alg not in {'HS256', 'HS384', 'HS512'}:
        return None

    for secret in secrets:
        try:
            jwt.decode(token, secret, algorithms=[alg])
            return secret
        except Exception:
            continue

    return None



# =============================
# Основные проверки из тикета
# =============================

def check_api_authentication(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка наличия аутентификации в API."""

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    endpoints = ['/api/users', '/api/data', '/api/config', '/api/admin', '/api/v1/users', '/api/v1/admin']

    evidence: List[str] = []
    for p in ports:
        for https in (False, True):
            for ep in endpoints:
                url = _build_url(target, p, ep, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if _looks_like_auth_challenge(resp):
                    continue
                if resp.status_code == 200:
                    j = _try_json(resp)
                    if j is not None:
                        keys = _sensitive_json_keys_found(j)
                        evidence.append(f"{url} -> 200 JSON (keys={keys or 'no-sensitive-keys'})")
                    else:
                        evidence.append(f"{url} -> 200")
                if len(evidence) >= 2:
                    return _result(True, "API: доступ без аутентификации подтверждён: " + '; '.join(evidence[:3]), severity='CRITICAL')

    if evidence:
        return _result(True, "API: возможен доступ без аутентификации: " + '; '.join(evidence[:3]), severity='HIGH')

    return _result(False, "API: явного доступа без аутентификации не обнаружено")


def check_api_no_https(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка API без HTTPS."""

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    for p in ports:
        http_url = _build_url(target, p, '/api/', https=False)
        https_url = _build_url(target, p, '/api/', https=True)

        http_resp = _request('GET', http_url, timeout=t)
        https_resp = _request('GET', https_url, timeout=t)

        http_ok = http_resp is not None and http_resp.status_code < 500
        https_ok = https_resp is not None and https_resp.status_code < 500

        if http_ok and not https_ok:
            return _result(True, f"API: доступно по HTTP без HTTPS (port={p})", severity='CRITICAL')

    return _result(False, "API: признак 'только HTTP' не обнаружен")


def check_api_rate_limiting(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка отсутствия Rate Limiting."""

    t = _clamp_timeout(timeout, upper=6.0)
    ports = _discover_http_ports(target, port, t)

    test_paths = ['/api/test', '/api/health', '/api/ping', '/api/status', '/api/']

    for p in ports:
        for https in (False, True):
            for path in test_paths:
                url = _build_url(target, p, path, https=https)
                ok_responses = 0
                saw_429 = False
                saw_rate_headers = False

                for _i in range(15):
                    resp = _request('GET', url, timeout=t)
                    if not resp:
                        break
                    if resp.status_code == 429:
                        saw_429 = True
                        break
                    ok_responses += 1
                    if any(h in resp.headers for h in ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'RateLimit-Limit']):
                        saw_rate_headers = True

                if saw_429 or saw_rate_headers:
                    return _result(False, f"API: rate limiting обнаружен ({'429' if saw_429 else 'rate headers'})")

                if ok_responses >= 10:
                    return _result(True, f"API: rate limiting не обнаружен на {url} (>=10 запросов без 429)", severity='MEDIUM')

    return _result(False, "API: недостаточно данных для проверки rate limiting")


def check_cors_wildcard(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка CORS wildcard (*)."""

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    for p in ports:
        url = _build_url(target, p, '/api/', https=False)
        resp = _request('GET', url, timeout=t, headers={'Origin': 'http://attacker.example'})
        if not resp:
            continue
        aco = resp.headers.get('Access-Control-Allow-Origin', '')
        acc = resp.headers.get('Access-Control-Allow-Credentials', '')
        if aco.strip() == '*':
            sev = 'HIGH' if acc.lower() == 'true' else 'MEDIUM'
            return _result(True, f"API: CORS wildcard обнаружен (ACA-Origin='*', credentials={acc!r})", severity=sev)

    return _result(False, "API: CORS wildcard не обнаружен")


def check_api_info_disclosure(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка раскрытия информации об API (Swagger/OpenAPI/Actuator/GraphQL)."""

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    endpoints = [
        '/swagger.json', '/swagger/v1/swagger.json', '/swagger-ui/', '/api/docs', '/api-docs',
        '/.well-known/openapi.json', '/openapi.json', '/actuator', '/actuator/health', '/graphql',
    ]

    for p in ports:
        for https in (False, True):
            for ep in endpoints:
                url = _build_url(target, p, ep, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code == 200 and len(resp.text or '') > 10:
                    body_l = (resp.text or '').lower()
                    if any(x in body_l for x in ['openapi', 'swagger', 'graphql', 'actuator', '__schema']):
                        return _result(True, f"API: обнаружен info disclosure endpoint: {url}", severity='HIGH')

    return _result(False, "API: endpoints документации/интроспекции не обнаружены")


def check_api_default_credentials(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка default учётных данных в API."""

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    login_paths = ['/api/login', '/login', '/auth/login', '/api/auth/login']
    credentials = [
        ('admin', 'admin'), ('admin', '123456'), ('root', 'root'), ('test', 'test'), ('user', 'password'),
    ]

    for p in ports:
        for https in (False, True):
            for lp in login_paths:
                url = _build_url(target, p, lp, https=https)
                for u, pw in credentials:
                    resp = _request('POST', url, timeout=t, json_body={'username': u, 'password': pw}, allow_redirects=False)
                    if not resp:
                        continue
                    if resp.status_code in {200, 201}:
                        token = _extract_jwt_from_response(resp)
                        if token:
                            return _result(True, f"API: дефолтные креды работают ({u}:{pw}) и выдан token", severity='CRITICAL')
                        j = _try_json(resp)
                        if isinstance(j, dict) and any(k in j for k in ['success', 'ok', 'authenticated']):
                            return _result(True, f"API: дефолтные креды работают ({u}:{pw})", severity='CRITICAL')

    return _result(False, "API: дефолтные креды не подтверждены")


def check_jwt_weak_secret(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка слабого JWT секрета."""

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    common_secrets = ['secret', 'password', '123456', 'admin', 'key', 'jwt', 'token', 'changeme']
    token_paths = ['/api/token', '/token', '/auth/token', '/api/auth/token']

    for p in ports:
        for https in (False, True):
            for tp in token_paths:
                url = _build_url(target, p, tp, https=https)
                resp = _request('GET', url, timeout=t)
                if resp:
                    token = _extract_jwt_from_response(resp)
                    if token:
                        hdr = _jwt_header(token) or {}
                        if str(hdr.get('alg', '')).lower() == 'none':
                            return _result(True, f"API: JWT использует alg=none ({url})", severity='CRITICAL')
                        weak = _jwt_weak_secret(token, common_secrets)
                        if weak:
                            return _result(True, f"API: подобран слабый JWT secret={weak!r} ({url})", severity='CRITICAL')

            for lp in ['/api/login', '/login', '/auth/login', '/api/auth/login']:
                url = _build_url(target, p, lp, https=https)
                resp = _request('POST', url, timeout=t, json_body={'username': 'admin', 'password': 'admin'})
                if not resp:
                    continue
                token = _extract_jwt_from_response(resp)
                if token:
                    weak = _jwt_weak_secret(token, common_secrets)
                    if weak:
                        return _result(True, f"API: слабый JWT secret={weak!r} (login endpoint)", severity='CRITICAL')

    return _result(False, "API: слабый JWT secret не подтверждён (или токен не получен)")


def check_api_sql_injection(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка SQL Injection в API (safe эвристика)."""

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    payloads = ["' OR '1'='1", "1' UNION SELECT NULL--", "admin'--", "1' OR 1=1--"]
    error_markers = ['sql', 'syntax error', 'sqlite', 'postgres', 'mysql', 'ora-', 'psql', 'odbc', 'traceback']

    for p in ports:
        for https in (False, True):
            base = _build_url(target, p, '/api/search', https=https)
            for payload in payloads:
                url = base + '?' + urllib.parse.urlencode({'q': payload})
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                body_l = (resp.text or '').lower()
                if any(m in body_l for m in error_markers):
                    return _result(True, f"API: возможная SQLi (ошибка в ответе) на {url}", severity='HIGH')

    return _result(False, "API: явных признаков SQLi не обнаружено")


def check_api_idor(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка IDOR (Insecure Direct Object Reference)."""

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    for p in ports:
        for https in (False, True):
            url1 = _build_url(target, p, '/api/user/1', https=https)
            url2 = _build_url(target, p, '/api/user/2', https=https)
            r1 = _request('GET', url1, timeout=t)
            r2 = _request('GET', url2, timeout=t)
            if not r1 or not r2:
                continue
            if _looks_like_auth_challenge(r1) or _looks_like_auth_challenge(r2):
                continue
            if r1.status_code == 200 and r2.status_code == 200 and (r1.text or '') != (r2.text or ''):
                return _result(True, f"API: возможный IDOR (доступ к /api/user/1 и /api/user/2 без auth) на порту {p}", severity='HIGH')

    return _result(False, "API: IDOR не подтверждён")


def check_api_missing_csrf(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка отсутствия CSRF защиты."""

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    for p in ports:
        url = _build_url(target, p, '/api/action', https=False)
        resp = _request('POST', url, timeout=t, headers={'Origin': 'http://attacker.example'})
        if not resp:
            continue
        if resp.status_code not in {401, 403}:
            return _result(True, f"API: возможное отсутствие CSRF защиты (POST не заблокирован) {url} -> {resp.status_code}", severity='MEDIUM')

    return _result(False, "API: CSRF issue не подтверждён")


def check_api_exposed_keys(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск API ключей в коде (локальный статический анализ)."""

    try:
        if not Path(target).exists():
            return _result(False, "API keys: проверка применима только к локальным файлам")
    except Exception:
        return _result(False, "API keys: target не является локальным путём")

    patterns = [
        r"[Aa]pi[_-]?[Kk]ey\s*[:=]\s*[\"']\w{16,}[\"']",
        r"[Ss]ecret\s*[:=]\s*[\"']\w{16,}[\"']",
        r"AKIA[0-9A-Z]{16}",
        r"AIza[0-9A-Za-z\-_]{35}",
        r"xox[baprs]-[0-9A-Za-z-]{10,}",
    ]

    files: List[Path] = []
    root = Path(target)
    if root.is_file():
        files = [root]
    else:
        for p in root.rglob('*'):
            if p.is_file() and p.suffix.lower() in {'.py', '.js', '.ts', '.java', '.kt', '.go', '.rb', '.php', '.env', '.yaml', '.yml', '.json'}:
                files.append(p)
            if len(files) >= 200:
                break

    hits = 0
    examples: List[str] = []
    for f in files:
        try:
            text = f.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
        for pat in patterns:
            try:
                if re.search(pat, text):
                    hits += 1
                    examples.append(str(f))
                    break
            except re.error:
                continue
        if hits >= 2:
            break

    if hits:
        return _result(True, f"API keys: обнаружены потенциальные секреты (hits={hits}) files={examples[:8]}", severity='CRITICAL')

    return _result(False, "API keys: явных секретов не найдено")


def check_graphql_introspection(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка доступности GraphQL introspection."""

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    query = {'query': 'query{__schema{types{name}}}'}

    for p in ports:
        url = _build_url(target, p, '/graphql', https=False)
        resp = _request('POST', url, timeout=t, json_body=query)
        if not resp:
            continue
        if resp.status_code == 200 and '__schema' in (resp.text or ''):
            return _result(True, f"API: GraphQL introspection доступен ({url})", severity='HIGH')

    return _result(False, "API: GraphQL introspection не обнаружен")


def check_api_error_messages(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка раскрытия информации через ошибки."""

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['traceback', 'stack trace', 'exception', 'sql', 'database error', 'nullpointer', 'at org.']

    for p in ports:
        url = _build_url(target, p, '/api/notfound', https=False)
        resp = _request('GET', url, timeout=t)
        if not resp:
            continue
        body_l = (resp.text or '').lower()
        if any(m in body_l for m in markers):
            return _result(True, f"API: раскрытие через ошибки ({url})", severity='MEDIUM')

    return _result(False, "API: раскрытие через ошибки не подтверждено")


def check_api_swagger_exposed(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Swagger/OpenAPI документация доступна публично.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/swagger.json', '/openapi.json', '/swagger/v1/swagger.json', '/.well-known/openapi.json']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='HIGH')

    return _result(False, "API: endpoint не обнаружен")


def check_api_swagger_ui_exposed(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Swagger UI доступен публично.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/swagger-ui/', '/swagger-ui/index.html', '/api/swagger-ui/', '/swagger/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='MEDIUM')

    return _result(False, "API: endpoint не обнаружен")


def check_api_actuator_exposed(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Spring Boot Actuator доступен публично.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/actuator', '/actuator/env', '/actuator/beans', '/actuator/mappings', '/actuator/health']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='HIGH')

    return _result(False, "API: endpoint не обнаружен")


def check_api_prometheus_metrics_exposed(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Prometheus metrics endpoint доступен.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/metrics', '/actuator/prometheus', '/prometheus']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='MEDIUM')

    return _result(False, "API: endpoint не обнаружен")


def check_api_debug_endpoints(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Debug endpoints доступны (часто содержат чувствительные данные).

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/debug', '/debug/vars', '/__debug__', '/_debugbar']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='MEDIUM')

    return _result(False, "API: endpoint не обнаружен")


def check_api_admin_panels_exposed(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Админ панели API доступны без защиты.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/admin', '/api/admin', '/admin/login', '/api/v1/admin']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='HIGH')

    return _result(False, "API: endpoint не обнаружен")


def check_api_health_endpoints_exposed(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Health/status endpoints доступны и могут раскрывать детали.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/health', '/api/health', '/status', '/api/status', '/ping', '/api/ping']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_kibana_elasticsearch_exposed(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Kibana/Elasticsearch endpoints доступны (встречаются на устройствах/бэкендах).

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/app/kibana', '/_cat/indices', '/_cluster/health', '/_search']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='HIGH')

    return _result(False, "API: endpoint не обнаружен")


def check_api_consul_etcd_exposed(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Consul/etcd management endpoints доступны.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/v1/kv/', '/v1/catalog/services', '/v2/keys/', '/v3/kv/range']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='HIGH')

    return _result(False, "API: endpoint не обнаружен")


def check_api_docker_k8s_exposed(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Docker/Kubernetes APIs доступны.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/version', '/containers/json', '/api/v1/nodes', '/api/v1/pods']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='CRITICAL')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_01(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #01.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/1', '/internal/1', '/.1/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_02(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #02.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/2', '/internal/2', '/.2/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_03(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #03.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/3', '/internal/3', '/.3/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_04(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #04.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/4', '/internal/4', '/.4/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_05(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #05.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/5', '/internal/5', '/.5/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_06(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #06.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/6', '/internal/6', '/.6/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_07(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #07.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/7', '/internal/7', '/.7/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_08(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #08.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/8', '/internal/8', '/.8/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_09(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #09.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/9', '/internal/9', '/.9/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_10(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #10.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/10', '/internal/10', '/.10/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_11(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #11.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/11', '/internal/11', '/.11/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_12(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #12.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/12', '/internal/12', '/.12/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_13(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #13.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/13', '/internal/13', '/.13/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_14(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #14.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/14', '/internal/14', '/.14/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_15(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #15.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/15', '/internal/15', '/.15/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_16(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #16.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/16', '/internal/16', '/.16/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_17(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #17.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/17', '/internal/17', '/.17/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_18(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #18.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/18', '/internal/18', '/.18/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_19(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #19.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/19', '/internal/19', '/.19/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_20(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #20.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/20', '/internal/20', '/.20/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_21(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #21.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/21', '/internal/21', '/.21/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_22(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #22.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/22', '/internal/22', '/.22/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_23(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #23.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/23', '/internal/23', '/.23/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_24(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #24.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/24', '/internal/24', '/.24/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_25(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #25.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/25', '/internal/25', '/.25/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_26(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #26.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/26', '/internal/26', '/.26/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_27(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #27.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/27', '/internal/27', '/.27/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_28(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #28.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/28', '/internal/28', '/.28/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_29(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #29.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/29', '/internal/29', '/.29/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_30(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #30.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/30', '/internal/30', '/.30/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_31(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #31.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/31', '/internal/31', '/.31/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_32(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #32.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/32', '/internal/32', '/.32/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_33(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #33.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/33', '/internal/33', '/.33/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_34(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #34.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/34', '/internal/34', '/.34/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_35(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #35.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/35', '/internal/35', '/.35/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_36(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #36.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/36', '/internal/36', '/.36/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_37(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #37.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/37', '/internal/37', '/.37/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_38(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #38.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/38', '/internal/38', '/.38/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_39(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #39.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/39', '/internal/39', '/.39/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_40(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #40.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/40', '/internal/40', '/.40/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_41(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #41.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/41', '/internal/41', '/.41/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_42(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #42.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/42', '/internal/42', '/.42/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_43(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #43.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/43', '/internal/43', '/.43/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_44(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #44.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/44', '/internal/44', '/.44/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_45(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #45.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/45', '/internal/45', '/.45/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_46(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #46.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/46', '/internal/46', '/.46/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_47(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #47.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/47', '/internal/47', '/.47/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_48(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #48.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/48', '/internal/48', '/.48/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_49(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #49.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/49', '/internal/49', '/.49/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_50(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #50.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/50', '/internal/50', '/.50/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_51(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #51.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/51', '/internal/51', '/.51/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_52(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #52.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/52', '/internal/52', '/.52/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_53(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #53.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/53', '/internal/53', '/.53/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_54(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #54.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/54', '/internal/54', '/.54/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_55(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #55.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/55', '/internal/55', '/.55/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_56(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #56.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/56', '/internal/56', '/.56/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_57(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #57.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/57', '/internal/57', '/.57/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_58(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #58.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/58', '/internal/58', '/.58/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_59(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #59.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/59', '/internal/59', '/.59/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


def check_api_sensitive_path_60(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка типового чувствительного пути #60.

    Многофакторность:
    - проверяем несколько вариантов пути
    - дополнительно анализируем ответ на наличие маркеров технологии

    Vulnerable, если найден хотя бы один endpoint с HTTP 200/401/403 и содержимым.
    """

    t = _clamp_timeout(timeout)
    ports = _discover_http_ports(target, port, t)

    markers = ['swagger', 'openapi', 'actuator', 'graphql', 'kibana', 'elastic', 'etcd', 'consul', 'docker', 'kubernetes']

    for p in ports:
        for https in (False, True):
            for path in ['/api/internal/60', '/internal/60', '/.60/']:
                url = _build_url(target, p, path, https=https)
                resp = _request('GET', url, timeout=t)
                if not resp:
                    continue
                if resp.status_code in {200, 401, 403} and len(resp.text or '') > 20:
                    body_l = (resp.text or '').lower()
                    if any(m in body_l for m in markers) or resp.status_code == 200:
                        return _result(True, f"API: endpoint доступен: {url} (status={resp.status_code})", severity='LOW')

    return _result(False, "API: endpoint не обнаружен")


# =============================
# Автосгенерированные проверки доступности endpoint'ов
# =============================
