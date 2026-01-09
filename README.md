# AASFA Scanner

**Android Attack Surface & Feasibility Assessment Tool**

Профессиональный инструмент для pre-attack assessment анализа поверхности атак Android-устройств в локальной сети.

## 🎯 Особенности

- ✅ **300 векторов проверки** разделенных на 4 категории
- ✅ **Chain-aware логика** с учетом зависимостей между проверками
- ✅ **Параллельное выполнение** с настраиваемым количеством потоков
- ✅ **Zero-Exploit Policy** - только проверка, без эксплуатации
- ✅ **Metasploit-style вывод** с цветным форматированием
- ✅ **Прогресс-бар** в реальном времени
- ✅ **Экспорт отчетов** в текстовом и JSON форматах
- ✅ **Graceful shutdown** по Ctrl+C

## 📦 Установка

```bash
git clone <repository-url>
cd aasfa-scanner
python3 -m pip install -r requirements.txt
```

**Требования:**
- Python 3.8+
- ADB установлен в системе (для ADB-проверок)
- Права root не требуются

## 🚀 Использование

### Базовое сканирование

```bash
python3 main.py -t 192.168.1.100
```

### Режимы сканирования

```bash
# Быстрое сканирование (приоритет 1-2)
python3 main.py -t 192.168.1.100 -m fast

# Полное сканирование (приоритет 1-3) [по умолчанию]
python3 main.py -t 192.168.1.100 -m full

# Глубокое сканирование (все 300 векторов)
python3 main.py -t 192.168.1.100 -m deep
```

### Сохранение отчета

```bash
# Текстовый отчет
python3 main.py -t 192.168.1.100 -o report.txt

# JSON отчет
python3 main.py -t 192.168.1.100 -o report.json
```

### Дополнительные опции

```bash
# Verbose режим
python3 main.py -t 192.168.1.100 -v

# Только ADB проверки
python3 main.py -t 192.168.1.100 --adb-only

# Без сетевых проверок
python3 main.py -t 192.168.1.100 --no-network

# Настройка потоков
python3 main.py -t 192.168.1.100 --threads 5

# Настройка timeout
python3 main.py -t 192.168.1.100 --timeout 60
```

## 📊 Категории векторов

### A. Network & Remote Access (1-40)
Проверки сетевого уровня: VNC, RDP, SSH, ADB over TCP, HTTP, HTTPS, FTP, MQTT, UPnP и другие.

### B. Android OS Logic (41-100)
Проверки Android OS: debuggable builds, SELinux, системные свойства, Binder, Intent, ContentProvider, KeyStore и другие.

### C. Application Layer (101-170)
Проверки приложений: hardcoded secrets, OAuth, JWT, SSL pinning, криптография, WebView, native libraries, ML models и другие.

### D. Supply Chain / Exotic (171-300)
Продвинутые проверки: OTA, firmware, baseband, sensors, биометрия, virtualization, side-channels, hardware и другие.

## 🏗️ Архитектура

```
aasfa-scanner/
├── aasfa/
│   ├── core/              # Ядро сканера
│   │   ├── scanner_engine.py
│   │   ├── vector_registry.py
│   │   ├── logical_analyzer.py
│   │   └── result_aggregator.py
│   ├── vectors/           # Определения векторов
│   │   ├── network_level.py
│   │   ├── android_os_logic.py
│   │   ├── application_layer.py
│   │   └── supply_chain_exotic.py
│   ├── checks/            # Реализации проверок
│   │   ├── network_checks.py
│   │   ├── adb_checks.py
│   │   ├── service_checks.py
│   │   ├── crypto_checks.py
│   │   ├── firmware_checks.py
│   │   ├── app_checks.py
│   │   └── physical_checks.py
│   ├── connectors/        # Сетевые коннекторы
│   │   ├── base_connector.py
│   │   ├── adb_connector.py
│   │   ├── http_connector.py
│   │   ├── network_connector.py
│   │   └── ssh_connector.py
│   ├── output/            # Форматирование вывода
│   │   ├── formatter.py
│   │   ├── progress_bar.py
│   │   └── report_generator.py
│   └── utils/             # Утилиты
│       ├── logger.py
│       ├── config.py
│       ├── validators.py
│       └── helpers.py
├── main.py
├── requirements.txt
└── README.md
```

## 🔒 Zero-Exploit Policy

AASFA Scanner придерживается строгой политики:

- ✅ Только проверка доступности сервисов
- ✅ Только чтение конфигурации и свойств
- ✅ Только логические проверки
- ❌ Никаких payload-ов или эксплуатации
- ❌ Никаких DoS атак
- ❌ Никаких модификаций системы

## 📝 Пример вывода

```
╔══════════════════════════════════════════════════════════════╗
║         AASFA Scanner - Android Attack Surface Scanner       ║
║              Pre-Attack Assessment Tool v1.0                 ║
╚══════════════════════════════════════════════════════════════╝

[*] Target: 192.168.1.100
[*] Android version: 14
[*] Device: SM-G990B
[*] Mode: full
[*] Threads: 10
[*] Total checks: 170
[*] Scanning...

[!] VECTOR_006: ADB Over TCP [CRITICAL]
[+] VECTOR_041: Debuggable Build [HIGH]
[*] VECTOR_073: Backup Flag Enabled [MEDIUM]

[████████████████████████████████████████████████] 100% | 170/170 | ETA: 0s

======================================================================
                          SCAN SUMMARY                           
======================================================================

Total checks performed: 170
Scan duration: 45.23 seconds

Vulnerabilities found:
  CRITICAL: 2
  HIGH: 5
  MEDIUM: 12
  LOW: 8

Risk Score: 68/100 [HIGH]

======================================================================
```

## 🧪 Тестирование

```bash
# Запуск тестов
python3 -m pytest tests/ -v

# Проверка покрытия
python3 -m pytest --cov=aasfa tests/
```

## 📄 Лицензия

Этот инструмент предназначен только для легального тестирования безопасности с разрешения владельца устройства.

## 👥 Авторы

AASFA Team

## 🔗 Ресурсы

- [Android Security Bulletin](https://source.android.com/security/bulletin)
- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Android Platform Security](https://source.android.com/security)

---

**⚠️ Внимание:** Используйте этот инструмент только на устройствах, которыми вы владеете или имеете письменное разрешение на тестирование. Несанкционированное сканирование может быть незаконным в вашей юрисдикции.
