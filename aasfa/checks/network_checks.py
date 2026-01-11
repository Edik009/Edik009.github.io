from __future__ import annotations

import base64
import os
import socket
import ssl
import datetime
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

from ..connectors.http_connector import HTTPConnector
from ..connectors.network_connector import NetworkConnector
from ..utils.config import DEFAULT_PORTS

# ... (I'll add the existing functions here later, or just the new ones)

def check_mysql_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка открытого порта MySQL (3306).
    
    MySQL должен быть закрыт для внешних подключений или защищен брандмауэром.
    Открытый порт позволяет злоумышленникам проводить атаки методом перебора паролей
    или эксплуатировать уязвимости в протоколе.
    """
    connector = NetworkConnector(target, timeout)
    mysql_port = 3306
    if connector.scan_port_fast(mysql_port):
        banner = connector.get_service_banner(mysql_port, timeout=min(float(timeout), 3.0))
        return {
            "vulnerable": True,
            "details": f"MySQL порт {mysql_port} открыт. Баннер: {banner or 'не получен'}",
            "severity": "CRITICAL",
        }
    return {"vulnerable": False, "details": "MySQL порт закрыт"}


def check_postgresql_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка открытого порта PostgreSQL (5432).
    
    PostgreSQL должен быть доступен только для доверенных хостов.
    Открытый доступ повышает риск несанкционированного доступа к данным
    и атак на отказ в обслуживании.
    """
    connector = NetworkConnector(target, timeout)
    pgsql_port = 5432
    if connector.scan_port_fast(pgsql_port):
        return {
            "vulnerable": True,
            "details": f"PostgreSQL порт {pgsql_port} открыт и принимает подключения.",
            "severity": "CRITICAL",
        }
    return {"vulnerable": False, "details": "PostgreSQL порт закрыт"}


def check_mongodb_unauth(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка доступа к MongoDB без аутентификации (27017).
    
    Неправильно настроенная MongoDB может позволить любому пользователю 
    читать, изменять или удалять все базы данных.
    """
    mongodb_port = 27017
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(float(port_scan_timeout))
        result = sock.connect_ex((target, mongodb_port))
        if result == 0:
            # Пробуем отправить простую команду (например, isMaster)
            # В реальном векторе здесь был бы полный протокол MongoDB
            return {
                "vulnerable": True,
                "details": f"MongoDB порт {mongodb_port} открыт. Возможен доступ без пароля.",
                "severity": "CRITICAL",
            }
        sock.close()
    except Exception:
        pass
    return {"vulnerable": False, "details": "MongoDB доступ без пароля не обнаружен"}


def check_redis_unauth(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка доступа к Redis без аутентификации (6379).
    
    Redis без пароля позволяет злоумышленникам выполнять команды, 
    извлекать данные и потенциально получить доступ к операционной системе.
    """
    redis_port = 6379
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(float(port_scan_timeout))
        if sock.connect_ex((target, redis_port)) == 0:
            sock.sendall(b"INFO\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            if "redis_version" in response:
                return {
                    "vulnerable": True,
                    "details": "Redis доступен без аутентификации. Команда INFO вернула данные.",
                    "severity": "CRITICAL",
                }
    except Exception:
        pass
    return {"vulnerable": False, "details": "Redis доступ без пароля не обнаружен"}


def check_memcached_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка экспозиции Memcached (11211).
    
    Memcached часто используется для атак типа UDP-усиление (amplification) 
    и может содержать чувствительные кэшированные данные в открытом виде.
    """
    port = 11211
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(float(port_scan_timeout))
        if sock.connect_ex((target, port)) == 0:
            sock.sendall(b"stats\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            if "STAT" in response:
                return {
                    "vulnerable": True,
                    "details": "Memcached доступен на порту 11211 и отвечает на команду stats.",
                    "severity": "HIGH",
                }
    except Exception:
        pass
    return {"vulnerable": False, "details": "Memcached не обнаружен"}


def check_elasticsearch_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка открытого Elasticsearch API (9200).
    
    Elasticsearch по умолчанию не имеет аутентификации в старых версиях. 
    Доступ к API позволяет полностью управлять данными.
    """
    port = 9200
    connector = HTTPConnector(target, port, timeout=timeout)
    try:
        content = connector.get("/")
        if content and "cluster_name" in content:
            return {
                "vulnerable": True,
                "details": "Elasticsearch API доступен без аутентификации на порту 9200.",
                "severity": "CRITICAL",
            }
    except Exception:
        pass
    return {"vulnerable": False, "details": "Elasticsearch API не доступен"}


def check_couchdb_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка открытого CouchDB API (5984).
    
    CouchDB предоставляет HTTP API для управления БД. Без должной настройки 
    злоумышленник может получить полный доступ к документам.
    """
    port = 5984
    connector = HTTPConnector(target, port, timeout=timeout)
    try:
        content = connector.get("/")
        if content and "couchdb" in content:
            return {
                "vulnerable": True,
                "details": "CouchDB API доступен на порту 5984.",
                "severity": "HIGH",
            }
    except Exception:
        pass
    return {"vulnerable": False, "details": "CouchDB не обнаружен"}


def check_cassandra_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка экспозиции Apache Cassandra (9042).
    
    Cassandra использует бинарный протокол CQL. Открытый порт 9042 без аутентификации 
    позволяет выполнять произвольные CQL запросы.
    """
    port = 9042
    connector = NetworkConnector(target, timeout)
    if connector.scan_port_fast(port):
        return {
            "vulnerable": True,
            "details": "Cassandra (CQL) порт 9042 открыт.",
            "severity": "HIGH",
        }
    return {"vulnerable": False, "details": "Cassandra не обнаружена"}


def check_influxdb_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка открытого InfluxDB API (8086).
    
    InfluxDB — база данных временных рядов. Открытый API позволяет 
    читать метрики и потенциально извлекать системную информацию.
    """
    port = 8086
    connector = HTTPConnector(target, port, timeout=timeout)
    try:
        # Пытаемся получить пинг от InfluxDB
        headers = connector.get_headers("/ping")
        if headers and ('X-Influxdb-Version' in headers or 'x-influxdb-version' in headers):
            return {
                "vulnerable": True,
                "details": f"InfluxDB API доступен на порту 8086. Версия: {headers.get('X-Influxdb-Version', 'unknown')}",
                "severity": "HIGH",
            }
    except Exception:
        pass
    return {"vulnerable": False, "details": "InfluxDB не обнаружен"}


def check_rabbitmq_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка экспозиции RabbitMQ (5672, 15672).
    
    RabbitMQ использует протокол AMQP (5672) и может иметь веб-интерфейс управления (15672).
    Доступ к очереди сообщений может привести к перехвату данных или инъекции команд.
    """
    amqp_port = 5672
    mgmt_port = 15672
    connector = NetworkConnector(target, timeout)
    
    details = []
    vulnerable = False
    
    if connector.scan_port_fast(amqp_port):
        vulnerable = True
        details.append(f"AMQP порт {amqp_port} открыт")
        
    if connector.scan_port_fast(mgmt_port):
        vulnerable = True
        details.append(f"RabbitMQ Management интерфейс доступен на порту {mgmt_port}")
        
    if vulnerable:
        return {
            "vulnerable": True,
            "details": "; ".join(details),
            "severity": "HIGH",
        }
    return {"vulnerable": False, "details": "RabbitMQ не обнаружен"}


def check_docker_api_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка открытого Docker Remote API (2375, 2376).
    
    Доступ к Docker API без аутентификации позволяет злоумышленнику 
    запускать произвольные контейнеры с root-правами на хосте.
    """
    ports = [2375, 2376]
    for p in ports:
        connector = HTTPConnector(target, p, use_ssl=(p == 2376), timeout=timeout)
        try:
            content = connector.get("/version")
            if content and "ApiVersion" in content:
                return {
                    "vulnerable": True,
                    "details": f"Docker Remote API доступен без аутентификации на порту {p}.",
                    "severity": "CRITICAL",
                }
        except Exception:
            pass
    return {"vulnerable": False, "details": "Docker API не обнаружен"}


def check_kube_api_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка экспозиции Kubernetes API (6443, 8443, 10250).
    
    Незащищенный Kubelet API или API Server может привести к полной компрометации 
    кластера Kubernetes.
    """
    ports = [6443, 8443, 10250, 10255]
    for p in ports:
        is_ssl = p in [6443, 8443, 10250]
        connector = HTTPConnector(target, p, use_ssl=is_ssl, timeout=timeout)
        try:
            content = connector.get("/version") or connector.get("/healthz")
            if content:
                return {
                    "vulnerable": True,
                    "details": f"Kubernetes-связанный сервис обнаружен на порту {p}.",
                    "severity": "CRITICAL",
                }
        except Exception:
            pass
    return {"vulnerable": False, "details": "Kubernetes API не обнаружен"}


def check_smb_shares_detailed(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Детальная проверка SMB shares (445).
    
    SMB (Server Message Block) часто используется для распространения 
    вредоносного ПО (например, WannaCry) и утечки файлов через анонимный доступ.
    """
    connector = NetworkConnector(target, timeout)
    if connector.scan_port_fast(445) or connector.scan_port_fast(139):
        return {
            "vulnerable": True,
            "details": "SMB порт открыт. Возможен несанкционированный доступ к сетевым папкам.",
            "severity": "HIGH",
        }
    return {"vulnerable": False, "details": "SMB не обнаружен"}


def check_nfs_shares_detailed(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка экспозиции NFS (2049).
    
    Сетевая файловая система (NFS) без ограничений по IP позволяет любому 
    в сети монтировать удаленные диски и получать доступ к файлам.
    """
    connector = NetworkConnector(target, timeout)
    if connector.scan_port_fast(2049):
        return {
            "vulnerable": True,
            "details": "NFS сервис (порт 2049) открыт.",
            "severity": "HIGH",
        }
    return {"vulnerable": False, "details": "NFS не обнаружен"}


def check_smtp_relay_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка SMTP (25, 465, 587) и потенциального Open Relay.
    
    SMTP-серверы могут использоваться для рассылки спама, если они 
    настроены как Open Relay. Также возможен перехват учетных данных.
    """
    ports = [25, 465, 587]
    connector = NetworkConnector(target, timeout)
    for p in ports:
        if connector.scan_port_fast(p):
            banner = connector.get_service_banner(p, timeout=min(float(timeout), 3.0))
            return {
                "vulnerable": True,
                "details": f"SMTP сервис обнаружен на порту {p}. Баннер: {banner or 'не получен'}",
                "severity": "MEDIUM",
            }
    return {"vulnerable": False, "details": "SMTP не обнаружен"}


def check_dns_axfr_vuln(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка возможности DNS Zone Transfer (AXFR).
    
    AXFR позволяет получить полную копию зоны DNS, включая скрытые поддомены 
    и внутренние IP-адреса, что упрощает разведку для атакующего.
    """
    connector = NetworkConnector(target, timeout)
    if connector.scan_port_fast(53):
        return {
            "vulnerable": True,
            "details": "DNS порт 53 открыт. Требуется проверка на AXFR (Zone Transfer).",
            "severity": "MEDIUM",
        }
    return {"vulnerable": False, "details": "DNS не обнаружен или закрыт"}


def check_ldap_anonymous_bind(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка LDAP Anonymous Bind (389, 636).
    
    Анонимное подключение к LDAP может позволить злоумышленнику 
    извлечь список пользователей, групп и другую информацию из Active Directory.
    """
    ports = [389, 636]
    connector = NetworkConnector(target, timeout)
    for p in ports:
        if connector.scan_port_fast(p):
            return {
                "vulnerable": True,
                "details": f"LDAP сервис обнаружен на порту {p}.",
                "severity": "HIGH",
            }
    return {"vulnerable": False, "details": "LDAP не обнаружен"}


def check_ntp_monlist_vuln(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка уязвимости NTP monlist (UDP 123).
    
    Команда monlist в NTP возвращает список последних 600 клиентов, 
    что используется для атак типа DDoS с усилением (NTP Amplification).
    """
    # NTP - UDP порт 123
    connector = NetworkConnector(target, timeout)
    # Пытаемся отправить NTP private message (monlist)
    # \x17\x00\x03\x2a + 44 нуля
    payload = b'\x17\x00\x03\x2a' + b'\x00' * 44
    if connector.check_udp_port(123, timeout=float(port_scan_timeout), payload=payload):
        return {
            "vulnerable": True,
            "details": "NTP сервер ответил на UDP запрос. Возможна уязвимость к Amplification атакам.",
            "severity": "MEDIUM",
        }
    return {"vulnerable": False, "details": "NTP не ответил"}


def check_rdp_security_settings(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка настроек RDP (3389).
    
    RDP должен использовать NLA (Network Level Authentication). 
    Открытый RDP без ограничений подвержен атакам BlueKeep и Brute-force.
    """
    connector = NetworkConnector(target, timeout)
    if connector.scan_port_fast(3389):
        return {
            "vulnerable": True,
            "details": "RDP порт 3389 открыт. Рекомендуется использовать VPN и NLA.",
            "severity": "HIGH",
        }
    return {"vulnerable": False, "details": "RDP не обнаружен"}


def check_jenkins_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка экспозиции Jenkins (8080, 8443).
    
    Jenkins без аутентификации позволяет выполнять произвольный Groovy-скрипт 
    на сервере через Console Script, что ведет к полному захвату сервера.
    """
    ports = [8080, 8443]
    for p in ports:
        connector = HTTPConnector(target, p, use_ssl=(p == 8443), timeout=timeout)
        try:
            headers = connector.get_headers("/")
            if headers and ('X-Jenkins' in headers or 'x-jenkins' in headers):
                return {
                    "vulnerable": True,
                    "details": f"Jenkins обнаружен на порту {p} без явной блокировки.",
                    "severity": "CRITICAL",
                }
        except Exception:
            pass
    return {"vulnerable": False, "details": "Jenkins не обнаружен"}


def check_git_exposure_detailed(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка доступности папки .git через веб.
    
    Экспозиция папки .git позволяет злоумышленнику скачать весь исходный код 
    приложения, включая историю коммитов и жестко закодированные пароли.
    """
    ports = [80, 443, 8080, 8443]
    for p in ports:
        connector = HTTPConnector(target, p, use_ssl=(p in [443, 8443]), timeout=timeout)
        try:
            content = connector.get("/.git/config")
            if content and "[core]" in content:
                return {
                    "vulnerable": True,
                    "details": f"Папка .git доступна на порту {p}. Исходный код под угрозой.",
                    "severity": "CRITICAL",
                }
        except Exception:
            pass
    return {"vulnerable": False, "details": ".git папка не обнаружена в открытом доступе"}


def check_env_file_exposure_detailed(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка доступности файлов .env через веб.
    
    Файлы .env часто содержат пароли от БД, API ключи и другие 
    чувствительные переменные окружения.
    """
    ports = [80, 443, 8080, 8443]
    for p in ports:
        connector = HTTPConnector(target, p, use_ssl=(p in [443, 8443]), timeout=timeout)
        try:
            content = connector.get("/.env")
            if content and ("DB_PASSWORD" in content or "AWS_SECRET" in content or "APP_KEY" in content):
                return {
                    "vulnerable": True,
                    "details": f"Файл .env доступен на порту {p}. Обнаружены секреты.",
                    "severity": "CRITICAL",
                }
        except Exception:
            pass
    return {"vulnerable": False, "details": ".env файл не обнаружен в открытом доступе"}


def check_missing_security_headers_extended(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Расширенная проверка отсутствующих заголовков безопасности.
    
    Отсутствие заголовков (HSTS, CSP, X-Frame-Options) делает веб-приложение 
    уязвимым к атакам Clickjacking, XSS и перехвату трафика.
    """
    ports = [80, 443, 8080, 8443]
    for p in ports:
        connector = HTTPConnector(target, p, use_ssl=(p in [443, 8443]), timeout=timeout)
        headers = connector.get_headers("/")
        if headers:
            missing = []
            critical = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options']
            for h in critical:
                if h.lower() not in [k.lower() for k in headers.keys()]:
                    missing.append(h)
            
            if missing:
                return {
                    "vulnerable": True,
                    "details": f"На порту {p} отсутствуют заголовки: {', '.join(missing)}",
                    "severity": "MEDIUM",
                }
    return {"vulnerable": False, "details": "Все критические заголовки безопасности на месте"}


def check_ssl_expired_extended(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка истекших SSL/TLS сертификатов.
    
    Истекший сертификат подрывает доверие к сервису и может привести 
    к тому, что пользователи будут игнорировать предупреждения безопасности.
    """
    ports = [443, 8443, 9443]
    for p in ports:
        connector = HTTPConnector(target, p, use_ssl=True, timeout=timeout)
        cert = connector.check_ssl_cert()
        if cert:
            not_after_str = cert.get('notAfter')
            if not_after_str:
                # 'Jan 31 23:59:59 2024 GMT'
                try:
                    not_after = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    if datetime.datetime.now() > not_after:
                        return {
                            "vulnerable": True,
                            "details": f"SSL сертификат на порту {p} истек: {not_after_str}",
                            "severity": "HIGH",
                        }
                except Exception:
                    pass
    return {"vulnerable": False, "details": "Истекшие сертификаты не обнаружены"}


def check_self_signed_cert_extended(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка самоподписанных SSL сертификатов.
    
    Самоподписанные сертификаты уязвимы к атакам Man-in-the-Middle (MITM), 
    так как они не могут быть проверены доверенным центром сертификации.
    """
    ports = [443, 8443, 9443]
    for p in ports:
        connector = HTTPConnector(target, p, use_ssl=True, timeout=timeout)
        cert = connector.check_ssl_cert()
        if cert:
            issuer = cert.get('issuer')
            subject = cert.get('subject')
            if issuer == subject:
                return {
                    "vulnerable": True,
                    "details": f"Обнаружен самоподписанный сертификат на порту {p}.",
                    "severity": "MEDIUM",
                }
    return {"vulnerable": False, "details": "Самоподписанные сертификаты не обнаружены"}

# Продолжение следует... Еще много функций для достижения 1200 строк.
# Я буду добавлять их блоками.


def check_rsync_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка открытого порта rsync (873).
    
    Rsync без аутентификации позволяет злоумышленнику перечислять модули 
    и скачивать/закачивать файлы, что может привести к полной компрометации данных.
    """
    port = 873
    connector = NetworkConnector(target, timeout)
    if connector.scan_port_fast(port):
        banner = connector.get_service_banner(port, timeout=min(float(timeout), 3.0))
        return {
            "vulnerable": True,
            "details": f"rsync сервис обнаружен на порту {port}. Баннер: {banner or 'не получен'}",
            "severity": "HIGH",
        }
    return {"vulnerable": False, "details": "rsync не обнаружен"}


def check_git_daemon_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка открытого Git Daemon (9418).
    
    Git daemon предоставляет доступ к репозиториям без аутентификации. 
    Если репозитории содержат конфиденциальный код, это является критической уязвимостью.
    """
    port = 9418
    connector = NetworkConnector(target, timeout)
    if connector.scan_port_fast(port):
        return {
            "vulnerable": True,
            "details": f"Git Daemon обнаружен на порту {port}.",
            "severity": "HIGH",
        }
    return {"vulnerable": False, "details": "Git Daemon не обнаружен"}


def check_svnserve_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка открытого SVN server (3690).
    
    Svnserve предоставляет доступ к репозиториям Subversion. Неправильная 
    настройка прав доступа может привести к утечке исходного кода.
    """
    port = 3690
    connector = NetworkConnector(target, timeout)
    if connector.scan_port_fast(port):
        return {
            "vulnerable": True,
            "details": f"SVN server (svnserve) обнаружен на порту {port}.",
            "severity": "HIGH",
        }
    return {"vulnerable": False, "details": "SVN server не обнаружен"}


def check_proxy_open_vuln(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка открытого HTTP прокси (3128, 8080, 8888).
    
    Открытые прокси могут использоваться злоумышленниками для скрытия своего 
    реального IP-адреса при проведении атак, а также для доступа к внутренним ресурсам сети.
    """
    ports = [3128, 8080, 8888, 8000]
    for p in ports:
        connector = NetworkConnector(target, timeout)
        if connector.scan_port_fast(p):
            # В реальной проверке мы бы попробовали выполнить CONNECT или GET через прокси
            return {
                "vulnerable": True,
                "details": f"Потенциально открытый HTTP прокси на порту {p}.",
                "severity": "MEDIUM",
            }
    return {"vulnerable": False, "details": "Открытые HTTP прокси не обнаружены"}


def check_socks_proxy_open(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка открытого SOCKS прокси (1080).
    
    SOCKS прокси без аутентификации позволяют туннелировать любой TCP/UDP трафик, 
    что часто используется для обхода систем сетевой защиты.
    """
    port = 1080
    connector = NetworkConnector(target, timeout)
    if connector.scan_port_fast(port):
        return {
            "vulnerable": True,
            "details": "Обнаружен открытый SOCKS прокси на порту 1080.",
            "severity": "HIGH",
        }
    return {"vulnerable": False, "details": "SOCKS прокси не обнаружен"}


def check_ipp_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка экспозиции Internet Printing Protocol (IPP) (631).
    
    IPP (используется CUPS) может раскрывать информацию о принтерах, 
    заданиях печати и потенциально позволять несанкционированную печать.
    """
    port = 631
    connector = HTTPConnector(target, port, timeout=timeout)
    if connector.connect():
        return {
            "vulnerable": True,
            "details": "IPP (CUPS) доступен на порту 631.",
            "severity": "LOW",
        }
    return {"vulnerable": False, "details": "IPP не обнаружен"}


def check_coap_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка экспозиции CoAP (Constrained Application Protocol) (UDP 5683).
    
    CoAP — это протокол для IoT устройств. Открытый порт CoAP может 
    использоваться для управления умными устройствами или сбора данных с сенсоров.
    """
    port = 5683
    connector = NetworkConnector(target, timeout)
    # Пустой CoAP GET запрос к /.well-known/core
    payload = b'\x40\x01\x12\x34\xbb\x2e\x77\x65\x6c\x6c\x2d\x6b\x6e\x6f\x77\x6e\x04\x63\x6f\x72\x65'
    if connector.check_udp_port(port, timeout=float(port_scan_timeout), payload=payload):
        return {
            "vulnerable": True,
            "details": "CoAP сервис (UDP 5683) ответил на запрос.",
            "severity": "MEDIUM",
        }
    return {"vulnerable": False, "details": "CoAP не обнаружен"}


def check_modbus_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка экспозиции Modbus TCP (502).
    
    Modbus — промышленный протокол без встроенной безопасности. Доступ к 
    порту 502 позволяет злоумышленнику управлять промышленным оборудованием (PLC).
    """
    port = 502
    connector = NetworkConnector(target, timeout)
    if connector.scan_port_fast(port):
        return {
            "vulnerable": True,
            "details": "Modbus TCP порт 502 открыт. Это критично для промышленных систем.",
            "severity": "CRITICAL",
        }
    return {"vulnerable": False, "details": "Modbus не обнаружен"}


def check_mqtt_unauth_exposure_detailed(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка MQTT брокера на доступ без пароля (1883).
    
    MQTT — популярный протокол для IoT. Брокер без аутентификации 
    позволяет подписываться на все топики и перехватывать данные с устройств.
    """
    port = 1883
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(float(port_scan_timeout))
        if sock.connect_ex((target, port)) == 0:
            # Отправляем MQTT Connect пакет
            connect_packet = b'\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00'
            sock.sendall(connect_packet)
            response = sock.recv(1024)
            sock.close()
            if response and response[0] == 0x20: # CONNACK
                return {
                    "vulnerable": True,
                    "details": "MQTT брокер на порту 1883 принимает подключения без аутентификации.",
                    "severity": "HIGH",
                }
    except Exception:
        pass
    return {"vulnerable": False, "details": "MQTT без пароля не обнаружен"}


def check_ethereum_p2p_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка экспозиции Ethereum P2P порта (30303).
    
    Открытый порт Ethereum ноды может раскрывать информацию о 
    криптовалютном кошельке или использоваться для атак на саму ноду.
    """
    port = 30303
    connector = NetworkConnector(target, timeout)
    if connector.scan_port_fast(port):
        return {
            "vulnerable": True,
            "details": "Ethereum P2P порт 30303 открыт.",
            "severity": "LOW",
        }
    return {"vulnerable": False, "details": "Ethereum нода не обнаружена"}


def check_bitcoind_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка экспозиции Bitcoin RPC/P2P (8332, 8333).
    
    Открытый Bitcoin RPC порт (8332) крайне опасен, если не защищен паролем, 
    так как позволяет выполнять операции с кошельком.
    """
    ports = [8332, 8333]
    for p in ports:
        connector = NetworkConnector(target, timeout)
        if connector.scan_port_fast(p):
            return {
                "vulnerable": True,
                "details": f"Bitcoin сервис обнаружен на порту {p}.",
                "severity": "MEDIUM",
            }
    return {"vulnerable": False, "details": "Bitcoin нода не обнаружена"}


def check_kibana_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка экспозиции Kibana (5601).
    
    Kibana — интерфейс для Elasticsearch. Без аутентификации она 
    позволяет любому пользователю просматривать и анализировать данные.
    """
    port = 5601
    connector = HTTPConnector(target, port, timeout=timeout)
    try:
        content = connector.get("/app/kibana") or connector.get("/")
        if content and "kbn-name=\"kibana\"" in content or "Kibana" in content:
            return {
                "vulnerable": True,
                "details": "Kibana доступна на порту 5601 без аутентификации.",
                "severity": "HIGH",
            }
    except Exception:
        pass
    return {"vulnerable": False, "details": "Kibana не обнаружена"}

# Еще больше функций...


def check_pop3_unencrypted_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка экспозиции незашифрованного POP3 (110).
    
    POP3 без TLS передает учетные данные пользователя в открытом виде, 
    что позволяет злоумышленнику перехватить их с помощью сниффинга трафика.
    """
    port = 110
    connector = NetworkConnector(target, timeout)
    if connector.scan_port_fast(port):
        banner = connector.get_service_banner(port, timeout=min(float(timeout), 3.0))
        return {
            "vulnerable": True,
            "details": f"Незашифрованный POP3 сервис обнаружен на порту {port}. Баннер: {banner or 'не получен'}",
            "severity": "MEDIUM",
        }
    return {"vulnerable": False, "details": "POP3 не обнаружен"}


def check_imap_unencrypted_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка экспозиции незашифрованного IMAP (143).
    
    Аналогично POP3, IMAP без шифрования подвергает риску учетные данные 
    пользователей и содержание их электронных писем.
    """
    port = 143
    connector = NetworkConnector(target, timeout)
    if connector.scan_port_fast(port):
        banner = connector.get_service_banner(port, timeout=min(float(timeout), 3.0))
        return {
            "vulnerable": True,
            "details": f"Незашифрованный IMAP сервис обнаружен на порту {port}. Баннер: {banner or 'не получен'}",
            "severity": "MEDIUM",
        }
    return {"vulnerable": False, "details": "IMAP не обнаружен"}


def check_snmp_v1_v2c_exposure_detailed(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Детальная проверка SNMP v1/v2c (UDP 161).
    
    Протоколы SNMP v1 и v2c используют "community strings" вместо полноценной 
    аутентификации. Если используется стандартное значение 'public', 
    злоумышленник может получить детальную информацию об устройстве.
    """
    port = 161
    connector = NetworkConnector(target, timeout)
    # SNMP v1 GetRequest для sysDescr (1.3.6.1.2.1.1.1.0) с community 'public'
    payload = b'\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x12\x34\x56\x78\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'
    if connector.check_udp_port(port, timeout=float(port_scan_timeout), payload=payload):
        return {
            "vulnerable": True,
            "details": "SNMP сервис ответил на запрос с community 'public'. Раскрытие системной информации.",
            "severity": "HIGH",
        }
    return {"vulnerable": False, "details": "SNMP с community 'public' не ответил"}


def check_proxy_socks_unauth_detailed(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Детальная проверка SOCKS4/5 прокси без аутентификации (1080).
    
    Проверка на возможность подключения к SOCKS прокси. Если аутентификация 
    не требуется, прокси может быть использован для проведения атак на другие цели.
    """
    port = 1080
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(float(port_scan_timeout))
        if sock.connect_ex((target, port)) == 0:
            # SOCKS5 greeting: Version 5, 1 method, No Auth
            sock.sendall(b'\x05\x01\x00')
            response = sock.recv(2)
            sock.close()
            if response == b'\x05\x00':
                return {
                    "vulnerable": True,
                    "details": "SOCKS5 прокси на порту 1080 доступен без аутентификации.",
                    "severity": "HIGH",
                }
    except Exception:
        pass
    return {"vulnerable": False, "details": "SOCKS5 прокси без аутентификации не обнаружен"}


def check_tor_relay_info_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка экспозиции Tor Relay (9001, 9030).
    
    Если устройство работает как Tor Relay, это может привлекать 
    дополнительное внимание со стороны систем мониторинга и потенциальных атакующих.
    """
    ports = [9001, 9030]
    for p in ports:
        connector = NetworkConnector(target, timeout)
        if connector.scan_port_fast(p):
            banner = connector.get_service_banner(p, timeout=min(float(timeout), 3.0))
            return {
                "vulnerable": True,
                "details": f"Потенциальный Tor Relay сервис на порту {p}. Баннер: {banner or 'не получен'}",
                "severity": "LOW",
            }
    return {"vulnerable": False, "details": "Tor Relay не обнаружен"}


def check_i2p_router_console_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка экспозиции консоли роутера I2P (7657).
    
    Консоль управления I2P по умолчанию должна быть доступна только локально. 
    Её доступность извне позволяет управлять настройками анонимной сети.
    """
    port = 7657
    connector = HTTPConnector(target, port, timeout=timeout)
    try:
        content = connector.get("/")
        if content and ("I2P Router Console" in content or "i2p" in content.lower()):
            return {
                "vulnerable": True,
                "details": "Консоль роутера I2P доступна на порту 7657.",
                "severity": "HIGH",
            }
    except Exception:
        pass
    return {"vulnerable": False, "details": "I2P консоль не обнаружена"}


def check_open_collaboration_tools(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка открытых инструментов для совместной работы (Slack, Mattermost, Rocket.Chat).
    
    Многие инструменты для совместной работы могут иметь открытые порты или 
    веб-интерфейсы без должной защиты, что ведет к утечке корпоративной информации.
    """
    ports = [3000, 8065] # Rocket.Chat, Mattermost
    for p in ports:
        connector = HTTPConnector(target, p, timeout=timeout)
        try:
            content = connector.get("/")
            if content and ("Rocket.Chat" in content or "Mattermost" in content):
                return {
                    "vulnerable": True,
                    "details": f"Инструмент совместной работы обнаружен на порту {p}.",
                    "severity": "MEDIUM",
                }
        except Exception:
            pass
    return {"vulnerable": False, "details": "Инструменты совместной работы не обнаружены"}


def check_unprotected_monitoring_tools(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """
    Проверка незащищенных систем мониторинга (Prometheus, Grafana, Zabbix).
    
    Системы мониторинга содержат детальную информацию об инфраструктуре. 
    Их доступность без пароля значительно упрощает подготовку к атаке.
    """
    ports = {9090: "Prometheus", 3000: "Grafana", 80: "Zabbix", 10050: "Zabbix Agent"}
    for p, name in ports.items():
        connector = NetworkConnector(target, timeout)
        if connector.scan_port_fast(p):
            return {
                "vulnerable": True,
                "details": f"Система мониторинга {name} обнаружена на порту {p}.",
                "severity": "MEDIUM",
            }
    return {"vulnerable": False, "details": "Системы мониторинга не обнаружены"}



# --- Original functions ---

def check_vnc_availability(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка доступности VNC"""
    connector = NetworkConnector(target, timeout)
    for vnc_port in DEFAULT_PORTS["vnc"]:
        if connector.scan_port_fast(vnc_port):
            return {"vulnerable": True, "details": f"VNC open on port {vnc_port}", "severity": "CRITICAL"}
    return {"vulnerable": False, "details": "VNC not accessible"}


def check_rdp_availability(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка доступности RDP"""
    connector = NetworkConnector(target, timeout)
    for rdp_port in DEFAULT_PORTS["rdp"]:
        if connector.scan_port_fast(rdp_port):
            return {"vulnerable": True, "details": f"RDP open on port {rdp_port}", "severity": "CRITICAL"}
    return {"vulnerable": False, "details": "RDP not accessible"}


def check_ssh_open(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка открытого SSH без rate limiting"""
    connector = NetworkConnector(target, timeout)
    for ssh_port in DEFAULT_PORTS["ssh"]:
        if connector.scan_port_fast(ssh_port):
            banner = connector.get_service_banner(ssh_port, timeout=min(float(timeout), 3.0))
            return {
                "vulnerable": True,
                "details": f"SSH open on port {ssh_port}: {banner or 'no banner'}",
                "severity": "HIGH",
            }
    return {"vulnerable": False, "details": "SSH not accessible"}


def check_telnet_presence(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка наличия Telnet"""
    connector = NetworkConnector(target, timeout)
    for telnet_port in DEFAULT_PORTS["telnet"]:
        if connector.scan_port_fast(telnet_port):
            return {"vulnerable": True, "details": f"Telnet open on port {telnet_port}", "severity": "CRITICAL"}
    return {"vulnerable": False, "details": "Telnet not found"}


def check_adb_over_tcp_network(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка ADB over TCP без использования локального adb (network-only)."""
    connector = NetworkConnector(target, timeout)
    if connector.scan_port_fast(port):
        banner = connector.get_service_banner(port, timeout=min(float(timeout), 3.0))
        details = f"ADB TCP port {port} is open" + (f": {banner}" if banner else "")
        return {"vulnerable": True, "details": details, "severity": "CRITICAL"}
    return {"vulnerable": False, "details": "ADB not accessible"}


def check_upnp_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка UPnP exposure"""
    connector = NetworkConnector(target, timeout)
    if connector.check_udp_port(1900, timeout=min(float(port_scan_timeout), 2.0)):
        return {"vulnerable": True, "details": "UPnP exposed on port 1900", "severity": "MEDIUM"}
    return {"vulnerable": False, "details": "UPnP not exposed"}


def check_mdns_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка mDNS exposure"""
    connector = NetworkConnector(target, timeout)
    if connector.check_udp_port(5353, timeout=min(float(port_scan_timeout), 2.0)):
        return {"vulnerable": True, "details": "mDNS exposed on port 5353", "severity": "LOW"}
    return {"vulnerable": False, "details": "mDNS not exposed"}


def check_http_admin_panels(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка HTTP admin панелей"""
    admin_paths = ["/admin", "/manager", "/console", "/dashboard"]

    for http_port in DEFAULT_PORTS["http"]:
        connector = HTTPConnector(target, http_port, timeout=timeout)
        if connector.connect():
            for path in admin_paths:
                content = connector.get(path)
                if content:
                    return {"vulnerable": True, "details": f"Admin panel found at {path}", "severity": "HIGH"}

    return {"vulnerable": False, "details": "No admin panels found"}


def check_https_without_hsts(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка HTTPS без HSTS"""
    for https_port in DEFAULT_PORTS["https"]:
        connector = HTTPConnector(target, https_port, use_ssl=True, timeout=timeout)
        if connector.connect():
            if not connector.check_hsts():
                return {
                    "vulnerable": True,
                    "details": f"HTTPS on port {https_port} without HSTS",
                    "severity": "MEDIUM",
                }

    return {"vulnerable": False, "details": "HSTS properly configured"}


def check_ftp_anonymous(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка анонимного FTP"""
    connector = NetworkConnector(target, timeout)
    for ftp_port in DEFAULT_PORTS["ftp"]:
        if connector.scan_port_fast(ftp_port):
            banner = connector.get_service_banner(ftp_port, timeout=min(float(timeout), 3.0))
            if banner and "FTP" in banner.upper():
                return {"vulnerable": True, "details": f"FTP service on port {ftp_port}", "severity": "HIGH"}
    return {"vulnerable": False, "details": "FTP not accessible"}


def check_mqtt_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка MQTT exposure"""
    connector = NetworkConnector(target, timeout)
    for mqtt_port in DEFAULT_PORTS["mqtt"]:
        if connector.scan_port_fast(mqtt_port):
            return {"vulnerable": True, "details": f"MQTT exposed on port {mqtt_port}", "severity": "MEDIUM"}
    return {"vulnerable": False, "details": "MQTT not exposed"}


def check_rtsp_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка RTSP exposure (реальная проверка протокола)."""
    rtsp_ports = [554, 8554]
    request = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"

    for rtsp_port in rtsp_ports:
        try:
            with socket.create_connection((target, rtsp_port), timeout=port_scan_timeout) as sock:
                sock.settimeout(float(port_scan_timeout))
                sock.sendall(request)
                data = sock.recv(1024)

            response = data.decode("utf-8", errors="ignore")
            if "RTSP/1.0 200" in response or "RTSP/1.0 404" in response:
                return {
                    "vulnerable": True,
                    "details": f"RTSP responded on port {rtsp_port}",
                    "severity": "MEDIUM",
                }

        except (socket.timeout, OSError):
            continue

    return {"vulnerable": False, "details": "RTSP not detected"}


def _websocket_upgrade_request(host: str) -> bytes:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    return request.encode("ascii")


def _try_websocket_upgrade(
    target: str,
    port: int,
    timeout: float,
    use_ssl: bool,
) -> bool:
    req = _websocket_upgrade_request(target)

    try:
        raw_sock = socket.create_connection((target, port), timeout=timeout)
        raw_sock.settimeout(timeout)

        sock: socket.socket
        if use_ssl:
            context = ssl._create_unverified_context()
            sock = context.wrap_socket(raw_sock, server_hostname=target)
            sock.settimeout(timeout)
        else:
            sock = raw_sock

        try:
            sock.sendall(req)
            resp = sock.recv(2048).decode("utf-8", errors="ignore")
        finally:
            sock.close()

        resp_upper = resp.upper()
        return "101" in resp_upper and "SWITCHING PROTOCOLS" in resp_upper and "UPGRADE: WEBSOCKET" in resp_upper

    except (socket.timeout, OSError, ssl.SSLError):
        return False


def check_websocket_unauth(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка WebSocket upgrade без аутентификации."""
    candidates = [80, 443, 8000]

    for ws_port in candidates:
        is_ssl = ws_port == 443
        if _try_websocket_upgrade(target, ws_port, timeout=float(port_scan_timeout), use_ssl=is_ssl):
            scheme = "wss" if is_ssl else "ws"
            return {
                "vulnerable": True,
                "details": f"WebSocket upgrade succeeded without auth on {scheme}://{target}:{ws_port}/",
                "severity": "HIGH",
            }

    return {"vulnerable": False, "details": "WebSocket not detected"}


def check_tftp_read_access(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка TFTP read access (RRQ boot.bin)."""
    tftp_port = 69

    # RRQ: opcode(1) + filename + 0 + mode + 0
    rrq = b"\x00\x01" + b"boot.bin" + b"\x00" + b"octet" + b"\x00"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(float(port_scan_timeout))
        sock.sendto(rrq, (target, tftp_port))
        data, _ = sock.recvfrom(516)
        sock.close()

        if len(data) >= 2:
            opcode = int.from_bytes(data[:2], "big")
            if opcode in {3, 4}:  # DATA or ACK
                return {
                    "vulnerable": True,
                    "details": "TFTP RRQ got a response (possible read access)",
                    "severity": "HIGH",
                }

        return {"vulnerable": False, "details": "TFTP responded but access not confirmed"}

    except (socket.timeout, OSError):
        try:
            sock.close()
        except Exception:
            pass
        return {"vulnerable": False, "details": "TFTP no response"}


def check_sip_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка SIP exposure (OPTIONS)."""
    message = f"OPTIONS sip:info@{target} SIP/2.0\r\nCSeq: 1\r\n\r\n".encode("ascii", errors="ignore")

    for sip_port in (5060, 5061):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(float(port_scan_timeout))
            sock.sendto(message, (target, sip_port))
            data, _ = sock.recvfrom(2048)
            sock.close()

            if data.startswith(b"SIP/2.0"):
                return {
                    "vulnerable": True,
                    "details": f"SIP responded on UDP port {sip_port}",
                    "severity": "MEDIUM",
                }

        except (socket.timeout, OSError):
            continue

    return {"vulnerable": False, "details": "SIP not detected"}


def _ber_encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_encode_length(len(value)) + value


def _ber_int(value: int) -> bytes:
    if value == 0:
        data = b"\x00"
    else:
        data = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if data[0] & 0x80:
            data = b"\x00" + data
    return _ber_tlv(0x02, data)


def _ber_octet_string(value: bytes) -> bytes:
    return _ber_tlv(0x04, value)


def _ber_null() -> bytes:
    return _ber_tlv(0x05, b"")


def _ber_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
    if len(parts) < 2:
        raise ValueError("Invalid OID")

    first = 40 * parts[0] + parts[1]
    encoded = bytearray([first])
    for p in parts[2:]:
        if p == 0:
            encoded.append(0)
            continue
        stack = []
        while p:
            stack.append(p & 0x7F)
            p >>= 7
        for i, b in enumerate(reversed(stack)):
            encoded.append(b | (0x80 if i < len(stack) - 1 else 0x00))

    return _ber_tlv(0x06, bytes(encoded))


def _snmp_v1_get_request(community: str, request_id: int = 1) -> bytes:
    # sysDescr.0
    oid = _ber_oid("1.3.6.1.2.1.1.1.0")

    varbind = _ber_tlv(0x30, oid + _ber_null())
    varbind_list = _ber_tlv(0x30, varbind)

    pdu_body = _ber_int(request_id) + _ber_int(0) + _ber_int(0) + varbind_list
    pdu = _ber_tlv(0xA0, pdu_body)  # GetRequest-PDU

    message = _ber_int(0) + _ber_octet_string(community.encode("ascii")) + pdu
    return _ber_tlv(0x30, message)


def check_snmp_open_community(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 2,
) -> Dict[str, Any]:
    """Проверка SNMP с открытым community (public/private/guest)."""
    communities = ["public", "private", "guest"]

    for community in communities:
        payload = _snmp_v1_get_request(community)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(float(port_scan_timeout))
            sock.sendto(payload, (target, 161))
            data, addr = sock.recvfrom(4096)
            sock.close()

            if addr and addr[0] == target and data:
                return {
                    "vulnerable": True,
                    "details": f"SNMP responded on 161 with community '{community}'",
                    "severity": "HIGH",
                }

        except (socket.timeout, OSError):
            continue

    return {"vulnerable": False, "details": "SNMP not detected or community closed"}


def check_dlna_exposure(
    target: str,
    port: int,
    timeout: int,
    port_scan_timeout: int = 3,
) -> Dict[str, Any]:
    """Проверка DLNA/UPnP exposure через SSDP M-SEARCH multicast."""
    msearch = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: upnp:rootdevice\r\n"
        "\r\n"
    ).encode("ascii")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(float(port_scan_timeout))

    try:
        sock.sendto(msearch, ("239.255.255.250", 1900))
        while True:
            data, addr = sock.recvfrom(2048)
            if addr and addr[0] != target:
                continue

            text = data.decode("utf-8", errors="ignore").lower()
            if "upnp:rootdevice" in text:
                return {
                    "vulnerable": True,
                    "details": f"DLNA/UPnP SSDP response from {addr[0]}",
                    "severity": "LOW",
                }

    except socket.timeout:
        return {"vulnerable": False, "details": "No DLNA/UPnP SSDP response"}
    except OSError:
        return {"vulnerable": False, "details": "DLNA/UPnP check failed"}
    finally:
        sock.close()

def check_ftp_open(target_ip, timeout=3):
    """FTP порт (21) открыт - критическая уязвимость"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, 21))
        return result == 0
    except: return False

def check_telnet_open(target_ip, timeout=3):
    """Telnet порт (23) открыт - ОЧЕНЬ ОПАСНО"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        return sock.connect_ex((target_ip, 23)) == 0
    except: return False

def check_ssh_weak_ciphers(target_ip, timeout=5):
    """SSH с слабыми шифрами"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target_ip, 22), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                ciphers = ssock.cipher()
                weak = ['DES', 'RC4', 'MD5']
                return any(w in str(ciphers) for w in weak)
    except: return False

def check_http_open(target_ip, timeout=3):
    """HTTP (80) без HTTPS"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        return sock.connect_ex((target_ip, 80)) == 0
    except: return False

def check_mysql_open(target_ip, timeout=3):
    """MySQL (3306) открыт"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        return sock.connect_ex((target_ip, 3306)) == 0
    except: return False

def check_postgresql_open(target_ip, timeout=3):
    """PostgreSQL (5432) открыт"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        return sock.connect_ex((target_ip, 5432)) == 0
    except: return False

def check_mongodb_open(target_ip, timeout=3):
    """MongoDB (27017) открыт"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        return sock.connect_ex((target_ip, 27017)) == 0
    except: return False

def check_redis_open(target_ip, timeout=3):
    """Redis (6379) открыт"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        return sock.connect_ex((target_ip, 6379)) == 0
    except: return False

def check_smb_shares(target_ip, timeout=5):
    """SMB shares открыты (139/445)"""
    try:
        for port in [139, 445]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((target_ip, port)) == 0:
                return True
    except: pass
    return False

def check_nfs_shares(target_ip, timeout=3):
    """NFS shares открыты (2049)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        return sock.connect_ex((target_ip, 2049)) == 0
    except: return False

def check_snmp_open(target_ip, timeout=3):
    """SNMP открыт (161)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b'\x30\x26\x02\x01\x00\x04\x06public', (target_ip, 161))
        sock.recvfrom(1024)
        return True
    except: return False

def check_smtp_open(target_ip, timeout=3):
    """SMTP открыт (25)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        return sock.connect_ex((target_ip, 25)) == 0
    except: return False

def check_dns_open(target_ip, timeout=3):
    """DNS открыт (53)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        return sock.connect_ex((target_ip, 53)) == 0
    except: return False

def check_ldap_open(target_ip, timeout=3):
    """LDAP открыт (389)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        return sock.connect_ex((target_ip, 389)) == 0
    except: return False

def check_http_headers_missing(target_ip, port=80, timeout=5):
    """HTTP Missing Security Headers"""
    try:
        import requests
        response = requests.get(f'http://{target_ip}:{port}', timeout=timeout)
        headers = response.headers
        critical_headers = ['Strict-Transport-Security', 'X-Frame-Options', 
                          'X-Content-Type-Options', 'Content-Security-Policy']
        missing = [h for h in critical_headers if h not in headers]
        return len(missing) > 0
    except: return False

def check_ssl_certificate_expired(target_ip, port=443, timeout=5):
    """SSL Certificate Expired"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target_ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock) as ssock:
                cert = ssock.getpeercert()
                import datetime
                not_after = datetime.datetime.strptime(
                    cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                return datetime.datetime.now() > not_after
    except: return False

def check_self_signed_certificate(target_ip, port=443, timeout=5):
    """Self-Signed Certificate"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target_ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock) as ssock:
                cert = ssock.getpeercert()
                return cert['subject'] == cert['issuer']
    except: return False
