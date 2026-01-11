#!/usr/bin/env python3
"""
Demo script для Network Security Vectors

Демонстрирует использование модуля network_security_vectors.py
"""

import sys
import json
from pathlib import Path

# Добавление корневой директории проекта в PYTHONPATH
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from aasfa.vectors import (
    NetworkSecurityVectors,
    scan_network_security_vectors,
    get_vector_count,
    get_vector_categories
)
from aasfa.utils.config import ScanConfig


def print_separator(title="", width=70):
    """Печать разделителя"""
    if title:
        padding = (width - len(title) - 2) // 2
        print("=" * padding + f" {title} " + "=" * padding)
    else:
        print("=" * width)


def demo_basic_usage():
    """Демонстрация базового использования"""
    print_separator("Базовое использование")
    
    # Создание конфигурации
    config = ScanConfig(
        target_ip='127.0.0.1',
        mode='fast',
        timeout=5,
        port_scan_timeout=1
    )
    
    print(f"Цель: {config.target_ip}")
    print(f"Режим: {config.mode}")
    print(f"Таймаут: {config.timeout} сек")
    print()
    
    # Создание сканера
    scanner = NetworkSecurityVectors(config)
    print("✓ Сканер создан")
    
    # Получение списка векторов
    vectors = scanner.get_all_vectors()
    print(f"✓ Доступно векторов: {len(vectors)}")
    print()


def demo_vector_categories():
    """Демонстрация категорий векторов"""
    print_separator("Категории векторов")
    
    categories = get_vector_categories()
    total_count = get_vector_count()
    
    print(f"Всего векторов: {total_count}")
    print(f"Категорий: {len(categories)}")
    print()
    
    for i, (category, vectors) in enumerate(categories.items(), 1):
        print(f"{i}. {category.upper().replace('_', ' ')}")
        print(f"   Векторов: {len(vectors)}")
        for vector in vectors:
            print(f"   - {vector}")
        print()


def demo_single_vector_check():
    """Демонстрация проверки одного вектора"""
    print_separator("Проверка одного вектора")
    
    config = ScanConfig(
        target_ip='127.0.0.1',
        mode='fast',
        timeout=3,
        port_scan_timeout=1
    )
    
    scanner = NetworkSecurityVectors(config)
    
    # Проверка HTTP вектора
    print("Проверка HTTP (порт 80) на localhost...")
    result = scanner.check_http_port_open()
    
    print(f"\nРезультат:")
    print(f"  ID вектора: {result['vector_id']}")
    print(f"  Название: {result['vector_name']}")
    print(f"  Уязвим: {'ДА' if result['vulnerable'] else 'НЕТ'}")
    print(f"  Уверенность: {result['confidence']:.2%}")
    print(f"  Временная метка: {result['timestamp']}")
    
    print(f"\n  Факторы проверки:")
    for factor in result['factors']:
        status = "✓" if factor['passed'] else "✗"
        print(f"    {status} {factor['name']}")
        print(f"      {factor['reason']}")
    
    if result.get('error'):
        print(f"\n  Ошибка: {result['error']}")
    
    print()


def demo_full_scan():
    """Демонстрация полного сканирования"""
    print_separator("Полное сканирование")
    
    config = ScanConfig(
        target_ip='127.0.0.1',
        mode='fast',
        timeout=3,
        port_scan_timeout=1
    )
    
    print(f"Запуск полного сканирования на {config.target_ip}...")
    print("Это может занять некоторое время...")
    print()
    
    # Запуск всех проверок
    results = scan_network_security_vectors(config)
    
    print(f"✓ Сканирование завершено")
    print(f"  Проверено векторов: {len(results)}")
    
    # Статистика
    vulnerable_count = sum(1 for r in results if r['vulnerable'])
    not_vulnerable_count = len(results) - vulnerable_count
    errors_count = sum(1 for r in results if r.get('error'))
    
    print(f"  Найдено уязвимостей: {vulnerable_count}")
    print(f"  Не уязвимо: {not_vulnerable_count}")
    print(f"  Ошибок: {errors_count}")
    print()
    
    # Вывод найденных уязвимостей
    if vulnerable_count > 0:
        print("Найденные уязвимости:")
        for result in results:
            if result['vulnerable']:
                print(f"  - {result['vector_name']}")
                print(f"    {result['details']}")
                print(f"    Уверенность: {result['confidence']:.2%}")
                print()
    else:
        print("Уязвимостей не обнаружено")
    
    print()


def demo_export_results():
    """Демонстрация экспорта результатов"""
    print_separator("Экспорт результатов")
    
    config = ScanConfig(
        target_ip='127.0.0.1',
        mode='fast',
        timeout=3,
        port_scan_timeout=1
    )
    
    scanner = NetworkSecurityVectors(config)
    
    # Проверка нескольких векторов
    print("Проверка нескольких векторов...")
    results = [
        scanner.check_telnet_port_open(),
        scanner.check_ssh_port_open(),
        scanner.check_http_port_open(),
    ]
    
    # Экспорт в JSON
    output_file = "network_scan_results.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"✓ Результаты экспортированы в {output_file}")
    
    # Вывод статистики
    print(f"\nСтатистика:")
    print(f"  Проверено векторов: {len(results)}")
    print(f"  Размер файла: {Path(output_file).stat().st_size} байт")
    print()


def demo_custom_target():
    """Демонстрация сканирования произвольной цели"""
    print_separator("Сканирование произвольной цели")
    
    print("Введите IP адрес цели (или нажмите Enter для 127.0.0.1): ", end='')
    
    # Для автоматического выполнения используем значение по умолчанию
    target_ip = '127.0.0.1'
    print(target_ip)
    
    config = ScanConfig(
        target_ip=target_ip,
        mode='fast',
        timeout=5,
        port_scan_timeout=2
    )
    
    print(f"\nСканирование {target_ip}...")
    print("Проверяем основные порты...\n")
    
    scanner = NetworkSecurityVectors(config)
    
    # Проверка основных портов
    port_checks = [
        ("Telnet", scanner.check_telnet_port_open),
        ("FTP", scanner.check_ftp_port_open),
        ("SSH", scanner.check_ssh_port_open),
        ("HTTP", scanner.check_http_port_open),
        ("HTTPS", scanner.check_https_port_open),
    ]
    
    for name, check_func in port_checks:
        result = check_func()
        status = "НАЙДЕНА" if result['vulnerable'] else "не найдена"
        confidence = result['confidence']
        
        print(f"  {name:10s} - {status:15s} (уверенность: {confidence:.2%})")
    
    print()


def main():
    """Главная функция"""
    print()
    print("=" * 70)
    print(" Network Security Vectors - Демонстрация ".center(70))
    print("=" * 70)
    print()
    
    demos = [
        ("1. Базовое использование", demo_basic_usage),
        ("2. Категории векторов", demo_vector_categories),
        ("3. Проверка одного вектора", demo_single_vector_check),
        ("4. Полное сканирование", demo_full_scan),
        ("5. Экспорт результатов", demo_export_results),
        ("6. Сканирование произвольной цели", demo_custom_target),
    ]
    
    try:
        for title, demo_func in demos:
            print(f"\n{title}")
            input("Нажмите Enter для продолжения...")
            print()
            demo_func()
    except KeyboardInterrupt:
        print("\n\nПрервано пользователем")
    except Exception as e:
        print(f"\n\nОшибка: {str(e)}")
        import traceback
        traceback.print_exc()
    
    print_separator()
    print("Демонстрация завершена!")
    print()


if __name__ == '__main__':
    main()
