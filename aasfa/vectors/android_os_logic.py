"""
B. Android OS Logic Vectors (41-100)
"""
from typing import Dict, Any


def get_android_os_vectors() -> Dict[int, Dict[str, Any]]:
    """Возвращает все Android OS Logic векторы (41-100)"""
    
    vectors = {}
    
    base_vectors = [
        (41, "Debuggable Build", "Build в режиме debuggable", "check_debuggable_build"),
        (42, "ro.secure Misconfiguration", "ro.secure неправильно настроен", "check_ro_secure_misconfig"),
        (43, "ro.adb.secure Disabled", "ro.adb.secure отключен", "check_ro_adb_secure"),
        (44, "Test Keys", "Build подписан test-keys", "check_test_keys"),
        (45, "SELinux Permissive", "SELinux в режиме Permissive", "check_selinux_permissive"),
        (46, "SELinux Policy Holes", "Дыры в SELinux политике", "check_selinux_policy_holes"),
        (47, "Userdebug Remnants", "Остатки userdebug build", "check_userdebug_remnants"),
        (48, "Hidden Properties", "Скрытые системные свойства", "check_hidden_properties"),
        (49, "System UID Leakage", "Утечка system UID", "check_system_uid_leakage"),
        (50, "Logcat Sensitive Data", "Чувствительные данные в logcat", "check_logcat_sensitive_data"),
        (51, "Dumpsys Unrestricted", "Dumpsys без ограничений", "check_dumpsys_unrestricted"),
        (52, "Binder Exposure", "Binder exposed", "check_binder_exposure"),
        (53, "ServiceManager Abuse", "ServiceManager может быть использован", "check_servicemanager_abuse"),
        (54, "Intent Hijacking", "Возможность Intent hijacking", "check_intent_hijacking"),
        (55, "Sticky Broadcast", "Sticky broadcast уязвимость", "check_sticky_broadcast"),
        (56, "PendingIntent Misconfiguration", "PendingIntent неправильно настроен", "check_pendingintent_misconfig"),
        (57, "Exported Activities", "Exported activities без защиты", "check_exported_activities"),
        (58, "Exported Services", "Exported services без защиты", "check_exported_services"),
        (59, "Exported Receivers", "Exported receivers без защиты", "check_exported_receivers"),
        (60, "ContentProvider Exposure", "ContentProvider exposed", "check_contentprovider_exposure"),
        (61, "URI Permission Bypass", "URI permission bypass", "check_uri_permission_bypass"),
        (62, "FileProvider Misconfiguration", "FileProvider неправильно настроен", "check_fileprovider_misconfig"),
        (63, "Insecure WebView", "WebView небезопасен", "check_insecure_webview"),
        (64, "JavaScript Interface Abuse", "JavaScript Interface может быть использован", "check_javascript_interface_abuse"),
        (65, "WebView File Access", "WebView file access включен", "check_webview_file_access"),
        (66, "Localhost Trust Abuse", "Localhost trust abuse", "check_localhost_trust_abuse"),
        (67, "Loopback Service Abuse", "Loopback service abuse", "check_loopback_service_abuse"),
        (68, "IPC Race Conditions", "IPC race conditions", "check_ipc_race_conditions"),
        (69, "Shared UID Misuse", "Shared UID misuse", "check_shared_uid_misuse"),
        (70, "Package Signature Mismatch", "Package signature mismatch", "check_package_signature_mismatch"),
        (71, "App Downgrade Allowed", "Downgrade приложения разрешен", "check_app_downgrade_allowed"),
        (72, "Rollback Protection", "Rollback protection отсутствует", "check_rollback_protection"),
        (73, "Backup Flag Enabled", "Backup flag включен", "check_backup_flag_enabled"),
        (74, "Auto Backup Leakage", "Auto backup утечка данных", "check_auto_backup_leakage"),
        (75, "Keystore Misuse", "Keystore misuse", "check_keystore_misuse"),
        (76, "StrongBox Absent", "StrongBox отсутствует", "check_strongbox_absent"),
        (77, "Hardware Backed Key", "Hardware-backed key отсутствует", "check_hardware_backed_key"),
        (78, "TrustZone API Exposure", "TrustZone API exposed", "check_trustzone_api_exposure"),
        (79, "HAL Debug Interfaces", "HAL debug interfaces", "check_hal_debug_interfaces"),
        (80, "Vendor Service Exposure", "Vendor services exposed", "check_vendor_service_exposure"),
        (81, "init.rc Services", "init.rc services уязвимы", "check_init_rc_services"),
        (82, "init.d Scripts", "init.d scripts присутствуют", "check_init_d_scripts"),
        (83, "Boot Image Configuration", "Boot image конфигурация", "check_boot_image_config"),
        (84, "Recovery Image Exposure", "Recovery image exposed", "check_recovery_image_exposure"),
        (85, "Fastboot Unlock", "Fastboot unlocked", "check_fastboot_unlock"),
        (86, "Verified Boot Disabled", "Verified boot отключен", "check_verified_boot"),
        (87, "AVB Rollback Protection", "AVB rollback protection отсутствует", "check_avb_rollback"),
        (88, "debugfs Mounted", "debugfs mounted", "check_debugfs_mounted"),
        (89, "procfs Leakage", "procfs утечка информации", "check_procfs_leakage"),
        (90, "sysfs Writeable", "sysfs доступен на запись", "check_sysfs_writeable"),
        (91, "Kernel Cmdline Exposure", "Kernel cmdline exposed", "check_kernel_cmdline"),
        (92, "Kernel Panic Info", "Kernel panic информация", "check_kernel_panic_info"),
        (93, "ptrace Misconfiguration", "ptrace неправильно настроен", "check_ptrace_misconfig"),
        (94, "seccomp Disabled", "seccomp отключен", "check_seccomp_disabled"),
        (95, "ASLR Entropy Low", "ASLR entropy низкий", "check_aslr_entropy"),
        (96, "Memory Tagging Absent", "Memory tagging отсутствует", "check_memory_tagging"),
        (97, "Zygote Hardening", "Zygote hardening отсутствует", "check_zygote_hardening"),
        (98, "Native Debug Symbols", "Native debug symbols присутствуют", "check_native_debug_symbols"),
        (99, "Engineering Menus", "Engineering menus доступны", "check_engineering_menus"),
        (100, "OEM Secret Codes", "OEM secret codes активны", "check_oem_secret_codes"),
    ]
    
    for vector_id, name, description, check_func in base_vectors:
        vectors[vector_id] = {
            "id": vector_id,
            "category": "B",
            "name": name,
            "description": description,
            "check_function": check_func,
            "requires_adb": True,
            "requires_network": False,
            "priority": 2,
            "depends_on": [6],
            "tags": ["android", "os", "system"],
        }
    
    return vectors
