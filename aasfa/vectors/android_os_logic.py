"""
B. Android OS Logic Vectors (41-100)
"""
from typing import Dict, Any, List


def get_android_os_vectors() -> Dict[int, Dict[str, Any]]:
    """Возвращает все Android OS Logic векторы (41-100)"""

    vectors = {}

    base_vectors = [
        (41, "Debuggable Build Detection", "Detection of debuggable builds", "check_debuggable_build"),
        (42, "ro.secure Misconfiguration", "Check ro.secure property", "check_ro_secure_misconfig"),
        (43, "ro.adb.secure Check", "Check ro.adb.secure property", "check_ro_adb_secure"),
        (44, "Test Keys Detection", "Detection of test keys in build", "check_test_keys"),
        (45, "SELinux Permissive Mode", "Check if SELinux is permissive", "check_selinux_permissive"),
        (46, "Userdebug Remnants", "Check for userdebug build remnants", "check_userdebug_remnants"),
        (47, "System UID Leakage", "Check for system UID leakage", "check_system_uid_leakage"),
        (48, "Logcat Sensitive Data", "Check for sensitive data in logcat", "check_logcat_sensitive_data"),
        (49, "Root Access Detection", "Check for root access", "check_root_access"),
        (50, "SELinux Policy Holes", "Check for SELinux policy holes", "check_selinux_policy_holes"),
        (51, "Hidden Properties", "Check for hidden system properties", "check_hidden_properties"),
        (52, "Dumpsys Unrestricted", "Check for unrestricted dumpsys access", "check_dumpsys_unrestricted"),
        (53, "Binder Exposure", "Check for Binder IPC exposure", "check_binder_exposure"),
        (54, "ServiceManager Abuse", "Check for ServiceManager abuse", "check_servicemanager_abuse"),
        (55, "Sticky Broadcast", "Check for sticky broadcast vulnerability", "check_sticky_broadcast"),
        (56, "PendingIntent Misconfig", "Check for PendingIntent misconfiguration", "check_pendingintent_misconfig"),
        (57, "URI Permission Bypass", "Check for URI permission bypass", "check_uri_permission_bypass"),
        (58, "FileProvider Misconfig", "Check for FileProvider misconfiguration", "check_fileprovider_misconfig"),
        (59, "Insecure WebView", "Check for insecure WebView configuration", "check_insecure_webview"),
        (60, "JavaScript Interface Abuse", "Check for JavaScript interface abuse", "check_javascript_interface_abuse"),
        (61, "WebView File Access", "Check for WebView file access", "check_webview_file_access"),
        (62, "Localhost Trust Abuse", "Check for localhost trust abuse", "check_localhost_trust_abuse"),
        (63, "Loopback Service Abuse", "Check for loopback service abuse", "check_loopback_service_abuse"),
        (64, "IPC Race Conditions", "Check for IPC race conditions", "check_ipc_race_conditions"),
        (65, "Shared UID Misuse", "Check for shared UID misuse", "check_shared_uid_misuse"),
        (66, "Package Signature Mismatch", "Check for package signature mismatch", "check_package_signature_mismatch"),
        (67, "App Downgrade Allowed", "Check if app downgrade is allowed", "check_app_downgrade_allowed"),
        (68, "Rollback Protection", "Check for rollback protection", "check_rollback_protection"),
        (69, "Auto Backup Leakage", "Check for auto backup leakage", "check_auto_backup_leakage"),
        (70, "Keystore Misuse", "Check for keystore misuse", "check_keystore_misuse"),
        (71, "StrongBox Absent", "Check for StrongBox absence", "check_strongbox_absent"),
        (72, "TrustZone API Exposure", "Check for TrustZone API exposure", "check_trustzone_api_exposure"),
        (73, "HAL Debug Interfaces", "Check for HAL debug interfaces", "check_hal_debug_interfaces"),
        (74, "Vendor Service Exposure", "Check for vendor service exposure", "check_vendor_service_exposure"),
        (75, "init.rc Services", "Check for init.rc services", "check_init_rc_services"),
        (76, "init.d Scripts", "Check for init.d scripts", "check_init_d_scripts"),
        (77, "Boot Image Configuration", "Check boot image configuration", "check_boot_image_config"),
        (78, "Recovery Image Exposure", "Check for recovery image exposure", "check_recovery_image_exposure"),
        (79, "AVB Rollback Protection", "Check AVB rollback protection", "check_avb_rollback"),
        (80, "Debugfs Mounted", "Check if debugfs is mounted", "check_debugfs_mounted"),
        (81, "Procfs Leakage", "Check for procfs leakage", "check_procfs_leakage"),
        (82, "Sysfs Writeable", "Check if sysfs is writeable", "check_sysfs_writeable"),
        (83, "Kernel Cmdline Exposure", "Check for kernel cmdline exposure", "check_kernel_cmdline"),
        (84, "Kernel Panic Info", "Check for kernel panic info", "check_kernel_panic_info"),
        (85, "Ptrace Misconfiguration", "Check for ptrace misconfiguration", "check_ptrace_misconfig"),
        (86, "Seccomp Disabled", "Check if seccomp is disabled", "check_seccomp_disabled"),
        (87, "ASLR Entropy Low", "Check if ASLR entropy is low", "check_aslr_entropy"),
        (88, "Memory Tagging Absent", "Check for memory tagging absence", "check_memory_tagging"),
        (89, "Zygote Hardening", "Check for zygote hardening", "check_zygote_hardening"),
        (90, "Native Debug Symbols", "Check for native debug symbols", "check_native_debug_symbols"),
        (91, "Engineering Menus", "Check for engineering menus", "check_engineering_menus"),
        (92, "OEM Secret Codes", "Check for OEM secret codes", "check_oem_secret_codes"),
        (93, "System Server Debug", "Check for system server debug", "check_system_server_debug"),
        (94, "Activity Manager Debug", "Check for activity manager debug", "check_activity_manager_debug"),
        (95, "Package Manager Debug", "Check for package manager debug", "check_package_manager_debug"),
        (96, "Window Manager Debug", "Check for window manager debug", "check_window_manager_debug"),
        (97, "Power Manager Debug", "Check for power manager debug", "check_power_manager_debug"),
        (98, "Telephony Debug", "Check for telephony debug", "check_telephony_debug"),
        (99, "Network Debug", "Check for network debug", "check_network_debug"),
        (100, "Location Debug", "Check for location debug", "check_location_debug"),
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
            "severity": "INFO",
            "weights": None,
            "confirmed_threshold": 0.7,
            "inconclusive_threshold": 0.4,
        }

    return vectors
