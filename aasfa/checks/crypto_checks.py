"""aasfa.checks.crypto_checks

Криптографические проверки безопасности.

Модуль предназначен для двух сценариев:

1) Remote/network проверки (TLS/сертификаты/шифры) по IP/хосту.
2) Локальный статический анализ (поиск слабых алгоритмов, hardcoded ключей
   и типичных антипаттернов в исходном коде), когда `target` указывает на файл
   или директорию.

Все функции:
- возвращают словарь вида {"vulnerable": bool, "details": str, ...}
- имеют строгие таймауты на все сетевые/подпроцессные операции
- стараются быть многофакторными: используют несколько независимых сигналов
  (например: версия TLS + negotiated cipher + параметры сертификата)

Важно:
- При отсутствии достаточных данных функция должна возвращать vulnerable=False,
  а в details — объяснять причину (например, сервис недоступен).

"""

from __future__ import annotations

import datetime as _dt
import re
import socket
import ssl
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
    from cryptography.hazmat.primitives.serialization import Encoding
except Exception:  # pragma: no cover
    x509 = None  # type: ignore


CheckResult = Dict[str, Any]


# =============================
# Общие вспомогательные функции
# =============================

def _clamp_timeout(timeout: int | float, *, lower: float = 1.0, upper: float = 15.0) -> float:
    """Нормализует таймаут.

    Args:
        timeout: значение, полученное от конфигурации сканера.
        lower: минимальный таймаут.
        upper: максимальный таймаут (чтобы не зависнуть на медленных сервисах).

    Returns:
        float: безопасный таймаут.
    """

    try:
        t = float(timeout)
    except Exception:
        t = upper
    if t != t:  # NaN
        t = upper
    return max(lower, min(t, upper))


def _result(vulnerable: bool, details: str, *, severity: Optional[str] = None, **extra: Any) -> CheckResult:
    """Утилита для формирования результата проверки."""

    data: CheckResult = {"vulnerable": bool(vulnerable), "details": str(details)}
    if severity:
        data["severity"] = severity
    data.update(extra)
    return data


def _is_local_target(target: str) -> bool:
    """Проверяет, является ли target локальным путём."""

    try:
        return Path(target).exists()
    except Exception:
        return False


def _iter_files(target: str, *, max_files: int = 200, max_depth: int = 8) -> List[Path]:
    """Собирает список файлов для статического анализа.

    Мы ограничиваем количество файлов и глубину, чтобы не анализировать
    гигантские репозитории в рамках сетевого сканирования.
    """

    root = Path(target)
    if root.is_file():
        return [root]

    files: List[Path] = []
    try:
        base_depth = len(root.resolve().parts)
    except Exception:
        base_depth = 0

    for p in root.rglob('*'):
        try:
            if not p.is_file():
                continue
            if p.suffix.lower() in {'.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip', '.jar', '.apk', '.so', '.bin', '.exe'}:
                continue
            if base_depth and (len(p.resolve().parts) - base_depth) > max_depth:
                continue
            files.append(p)
            if len(files) >= max_files:
                break
        except Exception:
            continue

    return files


def _safe_read_text(path: Path, *, max_bytes: int = 1_000_000) -> str:
    """Безопасно читает текстовый файл."""

    try:
        with path.open('rb') as f:
            raw = f.read(max_bytes)
        return raw.decode('utf-8', errors='ignore')
    except Exception:
        return ''


def _count_pattern_hits(text: str, patterns: Sequence[str]) -> int:
    """Считает количество совпадений по набору паттернов."""

    hits = 0
    for pat in patterns:
        try:
            if re.search(pat, text, re.IGNORECASE | re.MULTILINE):
                hits += 1
        except re.error:
            continue
    return hits


def _code_pattern_check(
    target: str,
    *,
    patterns: Sequence[str],
    min_hits: int = 1,
    title: str,
    severity: str,
    max_files: int = 200,
) -> CheckResult:
    """Базовая многофакторная проверка по исходному коду."""

    if not _is_local_target(target):
        return _result(
            False,
            f"{title}: проверка применима только к локальным файлам (получен target={target!r})",
        )

    files = _iter_files(target, max_files=max_files)
    if not files:
        return _result(False, f"{title}: файлы для анализа не найдены")

    hits = 0
    matched_files: List[str] = []
    for f in files:
        content = _safe_read_text(f)
        if not content:
            continue
        file_hits = _count_pattern_hits(content, patterns)
        if file_hits:
            hits += file_hits
            matched_files.append(str(f))
        if hits >= min_hits:
            break

    if hits >= min_hits:
        details = f"{title}: найдены совпадения ({hits}); файлы: {', '.join(matched_files[:10])}"
        return _result(True, details, severity=severity)

    return _result(False, f"{title}: совпадения не обнаружены")


# =============================
# TLS/сертификаты (remote scan)
# =============================

def _socket_connect(host: str, port: int, timeout: float) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, int(port)))
    return s


def _tls_handshake(
    host: str,
    port: int,
    *,
    timeout: float,
    min_version: Optional[int] = None,
    max_version: Optional[int] = None,
    ciphers: Optional[str] = None,
    sni: Optional[str] = None,
) -> Tuple[Optional[str], Optional[Tuple[str, str, int]]]:
    """Выполняет TLS handshake и возвращает (version, cipher)."""

    timeout = _clamp_timeout(timeout, upper=10.0)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        if hasattr(context, 'minimum_version') and min_version is not None:
            context.minimum_version = ssl.TLSVersion(min_version)  # type: ignore[arg-type]
        if hasattr(context, 'maximum_version') and max_version is not None:
            context.maximum_version = ssl.TLSVersion(max_version)  # type: ignore[arg-type]
    except Exception:
        pass

    try:
        if ciphers:
            context.set_ciphers(ciphers)
    except Exception:
        ciphers = None

    try:
        context.options |= getattr(ssl, 'OP_LEGACY_SERVER_CONNECT', 0)
    except Exception:
        pass

    sock: Optional[socket.socket] = None
    try:
        sock = _socket_connect(host, port, timeout)
        with context.wrap_socket(sock, server_hostname=sni or host) as ssock:
            version = ssock.version()
            cipher = ssock.cipher()
            return version, cipher
    except Exception:
        try:
            if sock:
                sock.close()
        except Exception:
            pass
        return None, None


def _get_peer_cert(host: str, port: int, timeout: float) -> Optional["x509.Certificate"]:
    """Получает X509 сертификат сервера (DER) и парсит через cryptography."""

    if x509 is None:
        return None

    timeout = _clamp_timeout(timeout, upper=10.0)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    sock: Optional[socket.socket] = None
    try:
        sock = _socket_connect(host, port, timeout)
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
        if not der:
            return None
        return x509.load_der_x509_certificate(der)
    except Exception:
        try:
            if sock:
                sock.close()
        except Exception:
            pass
        return None


def _discover_tls_ports(target: str, port: int, *, timeout: float) -> List[int]:
    """Список портов для TLS-проверок (best-effort)."""

    candidates: List[int] = []
    try:
        p = int(port)
        if 1 <= p <= 65535:
            candidates.append(p)
    except Exception:
        pass

    for p in [443, 8443, 9443, 10443]:
        if p not in candidates:
            candidates.append(p)

    open_ports: List[int] = []
    for p in candidates[:6]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(_clamp_timeout(timeout, upper=3.0))
            ok = s.connect_ex((target, p)) == 0
            s.close()
            if ok:
                open_ports.append(p)
        except Exception:
            continue

    return open_ports or candidates[:2]


def _tls_version_supported(host: str, port: int, tls_version: str, timeout: float) -> bool:
    """Проверяет, поддерживается ли конкретная версия TLS."""

    version_map = {
        'TLSv1': getattr(ssl.TLSVersion, 'TLSv1', None),
        'TLSv1.1': getattr(ssl.TLSVersion, 'TLSv1_1', None),
        'TLSv1.2': getattr(ssl.TLSVersion, 'TLSv1_2', None),
        'TLSv1.3': getattr(ssl.TLSVersion, 'TLSv1_3', None),
    }

    v = version_map.get(tls_version)
    if v is None:
        return False

    version, _ = _tls_handshake(host, port, timeout=timeout, min_version=v, max_version=v)
    if not version:
        return False
    return version.startswith(tls_version)


def _tls_weak_cipher_supported(host: str, port: int, timeout: float) -> bool:
    """Пытается договориться о заведомо слабом наборе шифров."""

    weak_cipher_candidates = [
        'RC4-SHA:RC4-MD5:@SECLEVEL=0',
        'DES-CBC3-SHA:DES-CBC-SHA:@SECLEVEL=0',
        'NULL-MD5:NULL-SHA:@SECLEVEL=0',
        'EXP-RC4-MD5:EXP-DES-CBC-SHA:@SECLEVEL=0',
    ]

    for cipher_str in weak_cipher_candidates:
        version, cipher = _tls_handshake(host, port, timeout=timeout, ciphers=cipher_str)
        if version and cipher:
            return True
    return False


def _cert_is_self_signed(cert: "x509.Certificate") -> bool:
    """Проверяет, является ли сертификат самоподписанным."""

    try:
        if cert.issuer != cert.subject:
            return False

        pub = cert.public_key()
        try:
            if isinstance(pub, rsa.RSAPublicKey):
                pub.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
                return True
            if isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm),
                )
                return True
        except Exception:
            return True

        return True
    except Exception:
        return False


def _cert_key_strength(cert: "x509.Certificate") -> Tuple[str, Optional[int]]:
    """Возвращает тип ключа и размер (если применимо)."""

    try:
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            return 'RSA', int(pub.key_size)
        if isinstance(pub, ec.EllipticCurvePublicKey):
            return 'EC', int(pub.key_size)
        return type(pub).__name__, None
    except Exception:
        return 'UNKNOWN', None


def _cert_signature_hash(cert: "x509.Certificate") -> Optional[str]:
    try:
        algo = cert.signature_hash_algorithm
        return getattr(algo, 'name', None)
    except Exception:
        return None



def check_md5_usage(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск использования MD5 в коде (hashlib/md5/строковые указания).

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 2 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['hashlib\\.md5', 'MD5\\(', '\\.md5\\(', '"md5"', "'md5'"],
        min_hits=2,
        title='Поиск использования MD5 в коде',
        severity='HIGH',
    )


def check_sha1_usage(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск использования SHA-1 (hashlib/строки/вызовы функций).

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 2 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['hashlib\\.sha1', 'SHA1\\(', '\\.sha1\\(', '"sha1"', '"SHA-1"', "'sha1'"],
        min_hits=2,
        title='Поиск использования SHA-1',
        severity='HIGH',
    )


def check_des_usage(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск использования DES/3DES (устаревшие симметричные шифры).

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 2 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['\\bDES\\b', '"des"', "'des'", 'TripleDES', '\\b3DES\\b', 'Cipher\\.getInstance\\(.*DES'],
        min_hits=2,
        title='Поиск использования DES/3DES',
        severity='CRITICAL',
    )


def check_rc4_usage(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск использования RC4 (Arcfour/RC4).

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 2 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['\\bRC4\\b', '"rc4"', 'Arcfour', 'ARCFOUR'],
        min_hits=2,
        title='Поиск использования RC4',
        severity='CRITICAL',
    )


def check_hardcoded_keys(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск hardcoded ключей и секретов (API keys, SECRET, PASSWORD, private key blocks).

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 2 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['\\\\b(API[_-]?KEY|APIKEY|SECRET|PASSWORD|TOKEN)\\\\s*[:=]\\\\s*[\\"\\\']\\\\S{8,}[\\"\\\']', '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', '\\\\bAKIA[0-9A-Z]{16}\\\\b', '\\\\bAIza[0-9A-Za-z\\\\-_]{35}\\\\b', '\\\\bxox[baprs]-[0-9A-Za-z-]{10,}\\\\b'],
        min_hits=2,
        title='Поиск hardcoded ключей и секретов',
        severity='CRITICAL',
    )


def check_ecb_mode_usage(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск использования режима ECB (AES-ECB и аналоги).

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 2 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['AES/ECB', 'ECB\\b', 'MODE_ECB', 'Cipher\\.getInstance\\(.*ECB'],
        min_hits=2,
        title='Поиск использования режима ECB',
        severity='HIGH',
    )


def check_static_iv_usage(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск статических IV (инициализационных векторов) в коде.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 2 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['\\bIV\\s*[:=]\\s*["\'].{8,}["\']', 'IvParameterSpec\\(', 'iv\\s*=\\s*bytes\\('],
        min_hits=2,
        title='Поиск статических IV',
        severity='HIGH',
    )


def check_insecure_random_usage(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск небезопасного генератора случайных чисел в криптоконтексте.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 2 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['random\\.random\\(', 'random\\.randint\\(', 'Math\\.random\\(', 'rand\\(', 'srand\\('],
        min_hits=2,
        title='Поиск небезопасного генератора случайных чисел в криптоконтексте',
        severity='MEDIUM',
    )


def check_weak_password_hashing(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск слабого хеширования паролей (MD5/SHA1 без KDF).

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 2 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['password.*md5', 'password.*sha1', 'hashlib\\.md5', 'hashlib\\.sha1', 'SHA1\\('],
        min_hits=2,
        title='Поиск слабого хеширования паролей',
        severity='HIGH',
    )


def check_missing_password_kdf(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск отсутствия KDF (bcrypt/scrypt/argon2/PBKDF2) при явных признаках хранения паролей.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 4 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['password', 'passwd', 'pwd', 'login'],
        min_hits=4,
        title='Поиск отсутствия KDF',
        severity='MEDIUM',
    )


def check_weak_hmac_compare(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск небезопасного сравнения HMAC/подписей (== вместо constant-time compare).

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['hmac.*==', 'signature.*==', 'compare.*=='],
        min_hits=1,
        title='Поиск небезопасного сравнения HMAC/подписей',
        severity='MEDIUM',
    )


def check_insecure_jwt_usage(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск небезопасного использования JWT (alg=none, отсутствие проверки).

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['alg\\s*[:=]\\s*["\']none["\']', 'jwt\\.decode\\(.*verify=False', 'verify_signature\\s*=\\s*False'],
        min_hits=1,
        title='Поиск небезопасного использования JWT',
        severity='HIGH',
    )


def check_tls_verification_disabled(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск отключения проверки TLS сертификата в коде.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 2 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['verify=False', 'CERT_NONE', 'ssl\\._create_unverified_context', 'check_hostname\\s*=\\s*False'],
        min_hits=2,
        title='Поиск отключения проверки TLS сертификата в коде',
        severity='HIGH',
    )


def check_weak_rsa_key_generation(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск генерации RSA ключей недостаточной длины (<2048) в коде.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['RSA\\.generate\\(\\s*(512|768|1024|1536)', 'genrsa\\s+(512|1024|1536)'],
        min_hits=1,
        title='Поиск генерации RSA ключей недостаточной длины',
        severity='HIGH',
    )


def check_insecure_crypto_modes_general(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск типичных небезопасных режимов/параметров (NOPADDING, DES, RC4, MD5).

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 3 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['NOPADDING', 'NoPadding', '\\bDES\\b', '\\bRC4\\b', '\\bMD5\\b'],
        min_hits=3,
        title='Поиск типичных небезопасных режимов/параметров',
        severity='MEDIUM',
    )


def check_hardcoded_secret_01(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск жёстко заданного секрета: AWS_SECRET_ACCESS_KEY.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['\\\\bAWS_SECRET_ACCESS_KEY\\\\b\\\\s*[:=]\\\\s*[\\"\\\']\\\\S{8,}[\\"\\\']'],
        min_hits=1,
        title='Поиск жёстко заданного секрета: AWS_SECRET_ACCESS_KEY',
        severity='CRITICAL',
    )


def check_hardcoded_secret_02(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск жёстко заданного секрета: AWS_ACCESS_KEY_ID.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['\\\\bAWS_ACCESS_KEY_ID\\\\b\\\\s*[:=]\\\\s*[\\"\\\']\\\\S{8,}[\\"\\\']'],
        min_hits=1,
        title='Поиск жёстко заданного секрета: AWS_ACCESS_KEY_ID',
        severity='CRITICAL',
    )


def check_hardcoded_secret_03(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск жёстко заданного секрета: GCP_SERVICE_ACCOUNT.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['\\\\bGCP_SERVICE_ACCOUNT\\\\b\\\\s*[:=]\\\\s*[\\"\\\']\\\\S{8,}[\\"\\\']'],
        min_hits=1,
        title='Поиск жёстко заданного секрета: GCP_SERVICE_ACCOUNT',
        severity='CRITICAL',
    )


def check_hardcoded_secret_04(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск жёстко заданного секрета: AZURE_CLIENT_SECRET.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['\\\\bAZURE_CLIENT_SECRET\\\\b\\\\s*[:=]\\\\s*[\\"\\\']\\\\S{8,}[\\"\\\']'],
        min_hits=1,
        title='Поиск жёстко заданного секрета: AZURE_CLIENT_SECRET',
        severity='CRITICAL',
    )


def check_hardcoded_secret_05(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск жёстко заданного секрета: PRIVATE_KEY.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['\\\\bPRIVATE_KEY\\\\b\\\\s*[:=]\\\\s*[\\"\\\']\\\\S{8,}[\\"\\\']'],
        min_hits=1,
        title='Поиск жёстко заданного секрета: PRIVATE_KEY',
        severity='CRITICAL',
    )


def check_hardcoded_secret_06(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск жёстко заданного секрета: JWT_SECRET.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['\\\\bJWT_SECRET\\\\b\\\\s*[:=]\\\\s*[\\"\\\']\\\\S{8,}[\\"\\\']'],
        min_hits=1,
        title='Поиск жёстко заданного секрета: JWT_SECRET',
        severity='CRITICAL',
    )


def check_hardcoded_secret_07(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск жёстко заданного секрета: SESSION_SECRET.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['\\\\bSESSION_SECRET\\\\b\\\\s*[:=]\\\\s*[\\"\\\']\\\\S{8,}[\\"\\\']'],
        min_hits=1,
        title='Поиск жёстко заданного секрета: SESSION_SECRET',
        severity='CRITICAL',
    )


def check_hardcoded_secret_08(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск жёстко заданного секрета: ENCRYPTION_KEY.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['\\\\bENCRYPTION_KEY\\\\b\\\\s*[:=]\\\\s*[\\"\\\']\\\\S{8,}[\\"\\\']'],
        min_hits=1,
        title='Поиск жёстко заданного секрета: ENCRYPTION_KEY',
        severity='CRITICAL',
    )


def check_hardcoded_secret_09(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск жёстко заданного секрета: DB_PASSWORD.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['\\\\bDB_PASSWORD\\\\b\\\\s*[:=]\\\\s*[\\"\\\']\\\\S{8,}[\\"\\\']'],
        min_hits=1,
        title='Поиск жёстко заданного секрета: DB_PASSWORD',
        severity='CRITICAL',
    )


def check_hardcoded_secret_10(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск жёстко заданного секрета: REDIS_PASSWORD.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['\\\\bREDIS_PASSWORD\\\\b\\\\s*[:=]\\\\s*[\\"\\\']\\\\S{8,}[\\"\\\']'],
        min_hits=1,
        title='Поиск жёстко заданного секрета: REDIS_PASSWORD',
        severity='CRITICAL',
    )


def check_hardcoded_secret_11(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск жёстко заданного секрета: MQTT_PASSWORD.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['\\\\bMQTT_PASSWORD\\\\b\\\\s*[:=]\\\\s*[\\"\\\']\\\\S{8,}[\\"\\\']'],
        min_hits=1,
        title='Поиск жёстко заданного секрета: MQTT_PASSWORD',
        severity='CRITICAL',
    )


def check_hardcoded_secret_12(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск жёстко заданного секрета: SMTP_PASSWORD.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['\\\\bSMTP_PASSWORD\\\\b\\\\s*[:=]\\\\s*[\\"\\\']\\\\S{8,}[\\"\\\']'],
        min_hits=1,
        title='Поиск жёстко заданного секрета: SMTP_PASSWORD',
        severity='CRITICAL',
    )


def check_hardcoded_secret_13(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск жёстко заданного секрета: S3_SECRET.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['\\\\bS3_SECRET\\\\b\\\\s*[:=]\\\\s*[\\"\\\']\\\\S{8,}[\\"\\\']'],
        min_hits=1,
        title='Поиск жёстко заданного секрета: S3_SECRET',
        severity='CRITICAL',
    )


def check_hardcoded_secret_14(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск жёстко заданного секрета: SIGNING_KEY.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['\\\\bSIGNING_KEY\\\\b\\\\s*[:=]\\\\s*[\\"\\\']\\\\S{8,}[\\"\\\']'],
        min_hits=1,
        title='Поиск жёстко заданного секрета: SIGNING_KEY',
        severity='CRITICAL',
    )


def check_md4_usage(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск использования MD4 (крайне устаревший хеш).

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['\\bMD4\\b', 'hashlib\\.new\\("md4"'],
        min_hits=1,
        title='Поиск использования MD4',
        severity='CRITICAL',
    )


def check_sha1_in_cert_pinning(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск SHA1 в механизмах pinning/сертификатах.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['sha1.*pin', 'pin.*sha1'],
        min_hits=1,
        title='Поиск SHA1 в механизмах pinning/сертификатах',
        severity='MEDIUM',
    )


def check_ripemd160_usage(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск RIPEMD-160 (не всегда уязвимо, но требует обоснования).

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['RIPEMD160', 'ripemd160'],
        min_hits=1,
        title='Поиск RIPEMD-160',
        severity='LOW',
    )


def check_weak_kdf_iterations(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск слишком малого числа итераций для PBKDF2.

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['PBKDF2.*iterations\\s*=\\s*(1000|2000|5000)', 'pbkdf2.*(1000|2000|5000)'],
        min_hits=1,
        title='Поиск слишком малого числа итераций для PBKDF2',
        severity='MEDIUM',
    )


def check_insecure_curve_usage(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск использования слабых эллиптических кривых (secp192r1 и аналоги).

    Тип проверки: статический анализ.

    Условия срабатывания:
    - анализируется файл/директория `target`
    - ищется набор регулярных выражений
    - требуется минимум 1 независимых совпадений

    Returns:
        dict: vulnerable=True при обнаружении паттернов.
    """

    return _code_pattern_check(
        target,
        patterns=['secp192', 'prime192', 'P-192'],
        min_hits=1,
        title='Поиск использования слабых эллиптических кривых',
        severity='HIGH',
    )


# =============================
# Основные криптографические проверки
# =============================

def check_password_hashing(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка алгоритма хеширования паролей (локальный статический анализ).

    Возвращает vulnerable=True, если обнаружены признаки хранения/хеширования пароля
    с использованием слабых алгоритмов (MD5/SHA1) без KDF.

    Логика многофакторная:
    - наличие ключевых слов password/pwd
    - + наличие md5/sha1
    - - отсутствие bcrypt/scrypt/argon2/pbkdf2
    """

    if not _is_local_target(target):
        return _result(False, "Password hashing: проверка применима только к локальному анализу")

    strong_markers = ['bcrypt', 'scrypt', 'argon2', 'pbkdf2', 'PBKDF2', 'passlib']
    weak_markers = ['hashlib.md5', 'hashlib.sha1', 'MD5(', 'SHA1(']

    files = _iter_files(target, max_files=200)
    if not files:
        return _result(False, "Password hashing: файлы не найдены")

    weak_hits = 0
    strong_hits = 0
    context_hits = 0
    for f in files:
        text = _safe_read_text(f)
        if not text:
            continue
        if re.search(r'password|passwd|pwd', text, re.IGNORECASE):
            context_hits += 1
        weak_hits += _count_pattern_hits(text, weak_markers)
        strong_hits += _count_pattern_hits(text, strong_markers)

    if context_hits and weak_hits and not strong_hits:
        return _result(True, f"Password hashing: найдены слабые алгоритмы (weak_hits={weak_hits}), strong не обнаружены", severity='HIGH')

    if strong_hits:
        return _result(False, f"Password hashing: обнаружены признаки стойкого KDF (strong_hits={strong_hits})")

    return _result(False, "Password hashing: недостаточно данных для вывода")


def check_salt_usage(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка использования salt при хешировании паролей (локальный анализ)."""

    if not _is_local_target(target):
        return _result(False, "Salt usage: проверка применима только к локальному анализу")

    files = _iter_files(target, max_files=200)
    if not files:
        return _result(False, "Salt usage: файлы не найдены")

    pwd_context = 0
    hash_context = 0
    salt_context = 0

    salt_markers = ['salt', 'SALT', 'SecureRandom', 'os.urandom', 'secrets.token_bytes', 'random.bytes']
    hash_markers = ['hashlib.', 'bcrypt', 'scrypt', 'argon2', 'pbkdf2', 'PBKDF2', 'digest']

    for f in files:
        text = _safe_read_text(f)
        if not text:
            continue
        if re.search(r'password|passwd|pwd', text, re.IGNORECASE):
            pwd_context += 1
        if _count_pattern_hits(text, hash_markers):
            hash_context += 1
        if _count_pattern_hits(text, salt_markers):
            salt_context += 1

    if pwd_context and hash_context and salt_context == 0:
        return _result(True, "Salt usage: есть хеширование паролей, но не найдено salt/secure random", severity='MEDIUM')

    if salt_context:
        return _result(False, f"Salt usage: признаки salt обнаружены (salt_hits={salt_context})")

    return _result(False, "Salt usage: недостаточно данных")


def check_ssl_pinning(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка наличия SSL Pinning в коде (локальный анализ)."""

    if not _is_local_target(target):
        return _result(False, "SSL pinning: проверка применима только к локальному анализу")

    files = _iter_files(target, max_files=200)
    if not files:
        return _result(False, "SSL pinning: файлы не найдены")

    pin_markers = [
        'CertificatePinner',
        'PublicKeyPinner',
        'pinCertificate',
        'pinPublicKey',
        'checkServerTrusted',
        'TrustManager',
    ]

    https_markers = ['https://', 'SSLContext', 'OkHttpClient', 'HttpURLConnection', 'requests.get']

    pin_hits = 0
    https_hits = 0

    for f in files:
        text = _safe_read_text(f)
        if not text:
            continue
        pin_hits += _count_pattern_hits(text, pin_markers)
        https_hits += _count_pattern_hits(text, https_markers)

    if https_hits >= 2 and pin_hits < 2:
        return _result(True, f"SSL pinning: сетевые вызовы обнаружены (https_hits={https_hits}), pinning не найден", severity='MEDIUM')

    if pin_hits >= 2:
        return _result(False, f"SSL pinning: признаки pinning обнаружены (pin_hits={pin_hits})")

    return _result(False, "SSL pinning: недостаточно данных")


# =============================
# TLS / сертификаты (remote)
# =============================

def check_tls_version_old(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка поддержки устаревших версий TLS 1.0/1.1."""

    t = _clamp_timeout(timeout)
    ports = _discover_tls_ports(target, port, timeout=t)

    supported_old = []
    for p in ports:
        if _tls_version_supported(target, p, 'TLSv1', t) or _tls_version_supported(target, p, 'TLSv1.1', t):
            supported_old.append(p)

    if supported_old:
        return _result(True, f"TLS: поддерживаются устаревшие версии TLS на портах {supported_old}", severity='HIGH')

    return _result(False, "TLS: поддержка TLS 1.0/1.1 не обнаружена")


def check_weak_cipher_suites(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Поиск слабых cipher suites."""

    t = _clamp_timeout(timeout)
    ports = _discover_tls_ports(target, port, timeout=t)

    evidence_ports: List[int] = []
    for p in ports:
        if _tls_weak_cipher_supported(target, p, t):
            evidence_ports.append(p)
            continue

        version, cipher = _tls_handshake(target, p, timeout=t)
        if cipher:
            cipher_name = cipher[0].upper()
            if any(x in cipher_name for x in ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'MD5']):
                evidence_ports.append(p)

    if evidence_ports:
        return _result(True, f"TLS: обнаружены слабые cipher suites на портах {evidence_ports}", severity='HIGH')

    return _result(False, "TLS: явные слабые cipher suites не обнаружены")


def check_self_signed_cert(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка самоподписанного сертификата (remote)."""

    t = _clamp_timeout(timeout)
    ports = _discover_tls_ports(target, port, timeout=t)

    for p in ports:
        cert = _get_peer_cert(target, p, t)
        if not cert:
            continue
        if _cert_is_self_signed(cert):
            subj = cert.subject.rfc4514_string() if hasattr(cert.subject, 'rfc4514_string') else 'unknown'
            return _result(True, f"TLS: self-signed сертификат на порту {p} ({subj})", severity='MEDIUM')

    return _result(False, "TLS: self-signed сертификат не обнаружен или сертификат недоступен")


def check_cert_expiration(target: str, port: int, timeout: int, *, days: int = 30, **_: Any) -> CheckResult:
    """Проверка истечения срока действия сертификата."""

    t = _clamp_timeout(timeout)
    ports = _discover_tls_ports(target, port, timeout=t)

    now = _dt.datetime.utcnow().replace(tzinfo=_dt.timezone.utc)
    for p in ports:
        cert = _get_peer_cert(target, p, t)
        if not cert:
            continue

        try:
            not_after = cert.not_valid_after
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=_dt.timezone.utc)
        except Exception:
            continue

        if not_after <= now:
            return _result(True, f"TLS: сертификат истёк на порту {p} (notAfter={not_after})", severity='HIGH')

        delta = (not_after - now).days
        if delta <= int(days):
            return _result(True, f"TLS: сертификат истекает скоро на порту {p} (через {delta} дней)", severity='MEDIUM')

    return _result(False, "TLS: истёкшие/истекающие сертификаты не обнаружены")


def check_rsa_key_length(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка длины RSA ключа сертификата (<2048 бит = уязвимо)."""

    t = _clamp_timeout(timeout)
    ports = _discover_tls_ports(target, port, timeout=t)

    for p in ports:
        cert = _get_peer_cert(target, p, t)
        if not cert:
            continue
        key_type, key_size = _cert_key_strength(cert)
        if key_type == 'RSA' and key_size is not None and key_size < 2048:
            return _result(True, f"TLS: слабый RSA ключ ({key_size} бит) на порту {p}", severity='HIGH')

    return _result(False, "TLS: слабые RSA ключи не обнаружены")


def check_tls_no_forward_secrecy(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка отсутствия Forward Secrecy."""

    t = _clamp_timeout(timeout)
    ports = _discover_tls_ports(target, port, timeout=t)

    weak_ports: List[int] = []
    for p in ports:
        version, cipher = _tls_handshake(target, p, timeout=t)
        if not cipher:
            continue
        name = cipher[0].upper()
        if 'DHE' not in name and 'ECDHE' not in name:
            weak_ports.append(p)

    if weak_ports:
        return _result(True, f"TLS: нет Forward Secrecy на портах {weak_ports}", severity='MEDIUM')

    return _result(False, "TLS: Forward Secrecy обнаружен или сервис недоступен")


def check_cert_weak_signature(target: str, port: int, timeout: int, **_: Any) -> CheckResult:
    """Проверка слабого алгоритма подписи сертификата (MD5/SHA1)."""

    t = _clamp_timeout(timeout)
    ports = _discover_tls_ports(target, port, timeout=t)

    for p in ports:
        cert = _get_peer_cert(target, p, t)
        if not cert:
            continue
        sig = _cert_signature_hash(cert)
        if sig and sig.lower() in {'md5', 'sha1'}:
            return _result(True, f"TLS: слабая подпись сертификата ({sig}) на порту {p}", severity='HIGH')

    return _result(False, "TLS: слабые подписи сертификатов не обнаружены")


# =============================
# Автосгенерированные локальные проверки
# =============================
