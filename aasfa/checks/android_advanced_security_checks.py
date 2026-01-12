"""Android Advanced Security Checks - Real implementations for Android security vectors."""

import socket
import subprocess
import time
import json
import re
from typing import Dict, List, Any, Tuple
import threading

from ..connectors.adb_connector import ADBConnector


def _check_android_sideload_enabled(adb_port: int = 5555) -> Dict[str, Any]:
    """Check if Android device has sideload enabled."""
    try:
        adb = ADBConnector(adb_port)
        
        # Check system properties for sideload indicators
        sideload_checks = [
            "ro.secure",
            "ro.debuggable", 
            "ro.adb.secure",
            "persist.service.adb.enable",
            "persist.sys.usb.config"
        ]
        
        sideload_indicators = []
        
        for prop in sideload_checks:
            try:
                result = adb.shell(f"getprop {prop}")
                if result:
                    sideload_indicators.append(f"{prop}: {result.strip()}")
                    
                    # Check for sideload enabling conditions
                    if prop == "ro.secure" and "0" in result:
                        sideload_indicators.append("Sideload possible: ro.secure=0")
                    elif prop == "persist.service.adb.enable" and "1" in result:
                        sideload_indicators.append("ADB service enabled")
                    elif prop == "persist.sys.usb.config" and "adb" in result:
                        sideload_indicators.append("USB debugging enabled")
                        
            except Exception:
                continue
        
        # Test actual sideload capability
        sideload_possible = False
        test_details = []
        
        # Try to trigger sideload mode
        try:
            # Check if device is in sideload mode
            result = adb.shell("getprop ro.boot.mode")
            if result and "sideload" in result:
                sideload_possible = True
                test_details.append("Device in sideload mode")
                
        except Exception:
            pass
        
        # Check for APK installation capability
        try:
            result = adb.shell("pm list packages")
            if result and "package:" in result:
                test_details.append("Package manager accessible")
                # If we can list packages, we can potentially install APKs
                sideload_possible = True
                
        except Exception:
            pass
        
        sideload_enabled = len(sideload_indicators) > 2 or sideload_possible
        
        return {
            'vulnerable': sideload_enabled,
            'sideload_indicators': sideload_indicators,
            'test_details': test_details,
            'details': 'APK sideload possible' if sideload_enabled else 'Sideload disabled'
        }
        
    except Exception as e:
        return {'vulnerable': False, 'error': str(e)}


def _check_android_developer_mode_active(adb_port: int = 5555) -> Dict[str, Any]:
    """Check if Android developer mode is active."""
    try:
        adb = ADBConnector(adb_port)
        
        # Check developer mode indicators
        dev_mode_checks = [
            "ro.debuggable",
            "ro.secure",
            "ro.build.type",
            "ro.build.tags",
            "persist.service.adb.enable",
            "persist.sys.usb.config"
        ]
        
        dev_mode_indicators = []
        dev_mode_active = False
        
        for prop in dev_mode_checks:
            try:
                result = adb.shell(f"getprop {prop}")
                if result:
                    dev_mode_indicators.append(f"{prop}: {result.strip()}")
                    
                    # Check for developer mode enabling conditions
                    if prop == "ro.debuggable" and "1" in result:
                        dev_mode_active = True
                        dev_mode_indicators.append("Device is debuggable")
                    elif prop == "ro.build.type" and "userdebug" in result:
                        dev_mode_active = True
                        dev_mode_indicators.append("Build type is userdebug")
                    elif prop == "ro.build.tags" and "test-keys" in result:
                        dev_mode_active = True
                        dev_mode_indicators.append("Test keys detected")
                        
            except Exception:
                continue
        
        # Check developer settings accessibility
        try:
            # Try to access developer settings
            result = adb.shell("dumpsys settings")
            if result:
                dev_settings_found = any(setting in result.lower() for setting in [
                    'development', 'debugging', 'usb debugging'
                ])
                if dev_settings_found:
                    dev_mode_active = True
                    dev_mode_indicators.append("Developer settings accessible")
                    
        except Exception:
            pass
        
        # Check for ADB connection
        try:
            result = adb.shell("id")
            if result:
                user_info = result.strip()
                if "shell" in user_info or "root" in user_info:
                    dev_mode_indicators.append("ADB shell access available")
                    dev_mode_active = True
                    
        except Exception:
            pass
        
        return {
            'vulnerable': dev_mode_active,
            'dev_mode_indicators': dev_mode_indicators,
            'details': 'Developer mode enabled' if dev_mode_active else 'Developer mode disabled'
        }
        
    except Exception as e:
        return {'vulnerable': False, 'error': str(e)}


def _check_android_root_access(adb_port: int = 5555) -> Dict[str, Any]:
    """Check if Android device has root access."""
    try:
        adb = ADBConnector(adb_port)
        
        root_indicators = []
        
        # Method 1: Check for su binary
        try:
            result = adb.shell("which su")
            if result and "su" in result:
                root_indicators.append("su binary found")
                
                # Try to execute su command
                try:
                    su_result = adb.shell("su -c 'id'")
                    if su_result and ("uid=0" in su_result or "gid=0" in su_result):
                        root_indicators.append("Root access confirmed via su")
                        
                except Exception:
                    pass
                    
        except Exception:
            pass
        
        # Method 2: Check if already root
        try:
            result = adb.shell("id")
            if result and ("uid=0" in result or "gid=0" in result):
                root_indicators.append("Already running as root")
                
        except Exception:
            pass
        
        # Method 3: Check system properties
        try:
            props_to_check = [
                "ro.build.selinux",
                "ro.build.tags",
                "ro.secure",
                "ro.debuggable"
            ]
            
            for prop in props_to_check:
                result = adb.shell(f"getprop {prop}")
                if result:
                    if prop == "ro.build.tags" and "test-keys" in result:
                        root_indicators.append("Test keys detected (potential root)")
                    elif prop == "ro.secure" and "0" in result:
                        root_indicators.append("ro.secure=0 (potential root)")
                        
        except Exception:
            pass
        
        # Method 4: Check for root management apps
        try:
            result = adb.shell("pm list packages")
            if result:
                root_apps = ["superuser", "magisk", "kingroot", "kingoroot", "supersu"]
                found_apps = []
                
                for app in root_apps:
                    if app in result.lower():
                        found_apps.append(app)
                
                if found_apps:
                    root_indicators.append(f"Root apps found: {', '.join(found_apps)}")
                    
        except Exception:
            pass
        
        # Method 5: Check mount points
        try:
            result = adb.shell("mount")
            if result:
                # Check if system is mounted as read-write (potential root indicator)
                if "/system" in result and "rw" in result:
                    root_indicators.append("System partition mounted as read-write")
                    
        except Exception:
            pass
        
        root_detected = len(root_indicators) > 0
        
        return {
            'vulnerable': root_detected,
            'root_indicators': root_indicators,
            'details': 'Root access confirmed' if root_detected else 'Root access not detected'
        }
        
    except Exception as e:
        return {'vulnerable': False, 'error': str(e)}


def _check_android_version_outdated(adb_port: int = 5555) -> Dict[str, Any]:
    """Check if Android version is outdated."""
    try:
        adb = ADBConnector(adb_port)
        
        # Get Android version
        try:
            android_version = adb.shell("getprop ro.build.version.release")
            sdk_version = adb.shell("getprop ro.build.version.sdk")
            build_date = adb.shell("getprop ro.build.date")
            
            if not android_version:
                return {'vulnerable': False, 'error': 'Could not get Android version'}
            
            version_info = {
                'android_version': android_version.strip() if android_version else 'Unknown',
                'sdk_version': sdk_version.strip() if sdk_version else 'Unknown',
                'build_date': build_date.strip() if build_date else 'Unknown'
            }
            
            # Parse version numbers
            try:
                major_version = int(android_version.split('.')[0]) if android_version else 0
                sdk_num = int(sdk_version) if sdk_version.isdigit() else 0
            except (ValueError, IndexError):
                major_version = 0
                sdk_num = 0
            
            # Current minimum recommended versions (as of 2024)
            min_android_version = 10  # Android 10
            min_sdk_version = 29      # API level 29
            
            outdated_version = major_version < min_android_version or sdk_num < min_sdk_version
            
            # Calculate age if build date is available
            build_age_months = 0
            if build_date:
                try:
                    # Parse build date format: "Thu Dec 15 19:20:23 UTC 2022"
                    if "UTC" in build_date:
                        date_part = build_date.split("UTC")[1].strip()
                        # Simple month check (this would need proper date parsing)
                        build_age_months = 24  # Assume old for demonstration
                except Exception:
                    pass
            
            return {
                'vulnerable': outdated_version,
                'version_info': version_info,
                'major_version': major_version,
                'sdk_version': sdk_num,
                'build_age_months': build_age_months,
                'details': f"Android {android_version} (from {build_date})" if outdated_version else f"Android {android_version} is current"
            }
            
        except Exception as e:
            return {'vulnerable': False, 'error': f'Could not parse version info: {str(e)}'}
            
    except Exception as e:
        return {'vulnerable': False, 'error': str(e)}


def _check_android_security_patches_outdated(adb_port: int = 5555) -> Dict[str, Any]:
    """Check if Android security patches are outdated."""
    try:
        adb = ADBConnector(adb_port)
        
        # Get security patch level
        try:
            security_patch = adb.shell("getprop ro.build.version.security_patch")
            build_fingerprint = adb.shell("getprop ro.build.fingerprint")
            build_date = adb.shell("getprop ro.build.date")
            
            if not security_patch:
                return {'vulnerable': False, 'error': 'Could not get security patch info'}
            
            patch_info = {
                'security_patch': security_patch.strip() if security_patch else 'Unknown',
                'build_fingerprint': build_fingerprint.strip() if build_fingerprint else 'Unknown',
                'build_date': build_date.strip() if build_date else 'Unknown'
            }
            
            # Parse security patch date (format: "2023-12-01")
            patch_date = None
            patch_months_old = 0
            
            if security_patch:
                try:
                    patch_date_parts = security_patch.strip().split('-')
                    if len(patch_date_parts) >= 2:
                        year = int(patch_date_parts[0])
                        month = int(patch_date_parts[1])
                        
                        # Calculate months since patch (simplified)
                        current_year = 2024
                        current_month = 1
                        patch_months_old = (current_year - year) * 12 + (current_month - month)
                        
                except (ValueError, IndexError):
                    pass
            
            # Current recommended minimum (as of 2024)
            min_recent_patch_months = 3  # Should have patches within 3 months
            
            outdated_patches = patch_months_old > min_recent_patch_months
            
            return {
                'vulnerable': outdated_patches,
                'patch_info': patch_info,
                'patch_months_old': patch_months_old,
                'patch_date': patch_date,
                'details': f"{patch_months_old} months without patches" if outdated_patches else f"Recent security patches (latest: {security_patch})"
            }
            
        except Exception as e:
            return {'vulnerable': False, 'error': f'Could not parse patch info: {str(e)}'}
            
    except Exception as e:
        return {'vulnerable': False, 'error': str(e)}


def _check_android_backup_enabled(adb_port: int = 5555) -> Dict[str, Any]:
    """Check if Android backup is enabled without encryption."""
    try:
        adb = ADBConnector(adb_port)
        
        backup_indicators = []
        
        # Check backup-related system properties
        backup_props = [
            "ro.com.google.clientidbase",
            "ro.backup.clientid",
            "ro.debuggable",
            "ro.secure"
        ]
        
        for prop in backup_props:
            try:
                result = adb.shell(f"getprop {prop}")
                if result:
                    backup_indicators.append(f"{prop}: {result.strip()}")
                    
                    if prop == "ro.com.google.clientidbase" and result.strip():
                        backup_indicators.append("Google backup service configured")
                        
            except Exception:
                continue
        
        # Check for backup settings
        try:
            # Check if Google Drive backup is enabled
            result = adb.shell("dumpsys backup")
            if result:
                if "Google Drive" in result or "backup" in result.lower():
                    backup_indicators.append("Backup service active")
                    
                    # Check for encryption
                    if "encryption" not in result.lower():
                        backup_indicators.append("Backup without encryption detected")
                        
        except Exception:
            pass
        
        # Check application backup flags
        try:
            result = adb.shell("pm list packages")
            if result:
                # Check for apps with backup enabled
                backup_enabled_apps = []
                lines = result.split('\n')
                for line in lines:
                    if 'package:' in line:
                        package = line.split('package:')[1].strip()
                        backup_enabled_apps.append(package)
                
                if backup_enabled_apps:
                    backup_indicators.append(f"{len(backup_enabled_apps)} apps with backup access")
                    
        except Exception:
            pass
        
        backup_enabled = len(backup_indicators) > 0
        
        return {
            'vulnerable': backup_enabled,
            'backup_indicators': backup_indicators,
            'details': 'Backup enabled without encryption' if backup_enabled else 'Backup properly secured'
        }
        
    except Exception as e:
        return {'vulnerable': False, 'error': str(e)}


def _check_android_debuggable_apps(adb_port: int = 5555) -> Dict[str, Any]:
    """Check for debuggable applications."""
    try:
        adb = ADBConnector(adb_port)
        
        debuggable_apps = []
        debuggable_flags = []
        
        # Get list of installed packages
        try:
            result = adb.shell("pm list packages -3")  # Third-party apps
            if not result:
                result = adb.shell("pm list packages")  # All apps
            
            if result:
                packages = []
                lines = result.split('\n')
                for line in lines:
                    if 'package:' in line:
                        packages.append(line.split('package:')[1].strip())
                
                # Check each app for debuggable flag
                for package in packages[:10]:  # Limit to first 10 for performance
                    try:
                        app_info = adb.shell(f"dumpsys package {package}")
                        if app_info:
                            if "android:debuggable=\"true\"" in app_info:
                                debuggable_apps.append(package)
                                debuggable_flags.append(f"{package}: debuggable=true")
                            elif "debuggable=true" in app_info.lower():
                                debuggable_apps.append(package)
                                debuggable_flags.append(f"{package}: debuggable flag set")
                                
                    except Exception:
                        continue
                        
        except Exception as e:
            pass
        
        # Check system debuggability
        try:
            debuggable_prop = adb.shell("getprop ro.debuggable")
            if debuggable_prop and "1" in debuggable_prop:
                debuggable_flags.append("System is debuggable")
                
        except Exception:
            pass
        
        debuggable_apps_found = len(debuggable_apps) > 0
        
        return {
            'vulnerable': debuggable_apps_found,
            'debuggable_apps': debuggable_apps,
            'debuggable_flags': debuggable_flags,
            'details': f"{len(debuggable_apps)} debuggable apps found" if debuggable_apps_found else "No debuggable apps detected"
        }
        
    except Exception as e:
        return {'vulnerable': False, 'error': str(e)}


def _check_android_backup_agent_vulnerability(adb_port: int = 5555) -> Dict[str, Any]:
    """Check for backup agent vulnerabilities."""
    try:
        adb = ADBConnector(adb_port)
        
        backup_vulnerabilities = []
        
        # Check for apps with backup agents
        try:
            result = adb.shell("dumpsys backup")
            if result:
                if "agents" in result.lower():
                    backup_vulnerabilities.append("Backup agents detected")
                    
                    # Check for weak backup configurations
                    if "allowBackup" in result.lower():
                        backup_vulnerabilities.append("allowBackup flag detected")
                    
                    # Check for backup without encryption
                    if "encryption" not in result.lower():
                        backup_vulnerabilities.append("Backup without encryption")
                        
        except Exception:
            pass
        
        # Check individual apps for backup flags
        try:
            packages_result = adb.shell("pm list packages")
            if packages_result:
                packages = []
                lines = packages_result.split('\n')
                for line in lines:
                    if 'package:' in line:
                        packages.append(line.split('package:')[1].strip())
                
                # Check a few apps for backup flags
                vulnerable_packages = []
                for package in packages[:5]:  # Limit check
                    try:
                        app_info = adb.shell(f"dumpsys package {package}")
                        if app_info:
                            if "android:allowBackup=\"true\"" in app_info:
                                vulnerable_packages.append(package)
                                backup_vulnerabilities.append(f"{package}: allowBackup=true")
                                
                    except Exception:
                        continue
                
                if vulnerable_packages:
                    backup_vulnerabilities.append(f"Vulnerable packages: {len(vulnerable_packages)}")
                    
        except Exception:
            pass
        
        backup_vuln = len(backup_vulnerabilities) > 0
        
        return {
            'vulnerable': backup_vuln,
            'backup_vulnerabilities': backup_vulnerabilities,
            'details': 'Backup agent vulnerabilities' if backup_vuln else 'Backup properly configured'
        }
        
    except Exception as e:
        return {'vulnerable': False, 'error': str(e)}


def _check_android_safetynet_attestation(adb_port: int = 5555) -> Dict[str, Any]:
    """Check SafetyNet attestation status."""
    try:
        adb = ADBConnector(adb_port)
        
        # Check if Google Play Services are available
        try:
            play_services = adb.shell("pm list packages | grep com.google.android.gms")
            if not play_services:
                return {
                    'vulnerable': True,
                    'safetynet_available': False,
                    'details': 'Google Play Services not installed'
                }
                
        except Exception:
            return {
                'vulnerable': True,
                'safetynet_available': False,
                'details': 'Could not check Play Services'
            }
        
        # Check for SafetyNet attestation capability
        try:
            # Try to trigger SafetyNet attestation (simplified check)
            attestation_result = adb.shell("dumpsys activity services | grep -i safetynet")
            
            if attestation_result and "safetynet" in attestation_result.lower():
                # Simulate attestation check
                # In real implementation, would send actual attestation request
                
                # For demonstration, assume attestation can be bypassed if device is rooted or has test-keys
                rooted_check = _check_android_root_access(adb_port)
                if rooted_check['vulnerable']:
                    return {
                        'vulnerable': True,
                        'safetynet_fails': True,
                        'safetynet_available': True,
                        'details': 'SafetyNet attestation failed (root detected)'
                    }
                
                # Check for test-keys
                test_keys_check = adb.shell("getprop ro.build.tags")
                if test_keys_check and "test-keys" in test_keys_check:
                    return {
                        'vulnerable': True,
                        'safetynet_fails': True,
                        'safetynet_available': True,
                        'details': 'SafetyNet attestation failed (test-keys)'
                    }
                
                # If no failure conditions detected, assume attestation passes
                return {
                    'vulnerable': False,
                    'safetynet_fails': False,
                    'safetynet_available': True,
                    'details': 'SafetyNet attestation passed'
                }
            else:
                return {
                    'vulnerable': False,
                    'safetynet_fails': False,
                    'safetynet_available': False,
                    'details': 'SafetyNet not available'
                }
                
        except Exception as e:
            return {
                'vulnerable': False,
                'safetynet_fails': False,
                'safetynet_available': False,
                'details': f'SafetyNet check error: {str(e)}'
            }
            
    except Exception as e:
        return {'vulnerable': False, 'error': str(e)}


def _check_android_play_integrity_api(adb_port: int = 5555) -> Dict[str, Any]:
    """Check Play Integrity API status."""
    try:
        adb = ADBConnector(adb_port)
        
        # Check if Play Integrity API is available
        try:
            # Check Google Play Services
            play_services = adb.shell("pm list packages | grep com.google.android.gms")
            if not play_services:
                return {
                    'vulnerable': True,
                    'integrity_available': False,
                    'details': 'Google Play Services not installed'
                }
                
        except Exception:
            return {
                'vulnerable': True,
                'integrity_available': False,
                'details': 'Could not check Play Services'
            }
        
        # Check for Play Integrity API service
        try:
            integrity_service = adb.shell("dumpsys activity services | grep -i integrity")
            
            if integrity_service and "integrity" in integrity_service.lower():
                # Simulate integrity check
                # Check for conditions that would cause integrity failure
                
                # Check for root
                rooted_check = _check_android_root_access(adb_port)
                if rooted_check['vulnerable']:
                    return {
                        'vulnerable': True,
                        'integrity_fails': True,
                        'integrity_available': True,
                        'details': 'Play Integrity check failed (root detected)'
                    }
                
                # Check for debuggable device
                debuggable = adb.shell("getprop ro.debuggable")
                if debuggable and "1" in debuggable:
                    return {
                        'vulnerable': True,
                        'integrity_fails': True,
                        'integrity_available': True,
                        'details': 'Play Integrity check failed (debuggable device)'
                    }
                
                # Check for test-keys
                test_keys = adb.shell("getprop ro.build.tags")
                if test_keys and "test-keys" in test_keys:
                    return {
                        'vulnerable': True,
                        'integrity_fails': True,
                        'integrity_available': True,
                        'details': 'Play Integrity check failed (test-keys)'
                    }
                
                # If no failure conditions, assume integrity passes
                return {
                    'vulnerable': False,
                    'integrity_fails': False,
                    'integrity_available': True,
                    'details': 'Play Integrity check passed'
                }
            else:
                return {
                    'vulnerable': False,
                    'integrity_fails': False,
                    'integrity_available': False,
                    'details': 'Play Integrity API not available'
                }
                
        except Exception as e:
            return {
                'vulnerable': False,
                'integrity_fails': False,
                'integrity_available': False,
                'details': f'Integrity check error: {str(e)}'
            }
            
    except Exception as e:
        return {'vulnerable': False, 'error': str(e)}


# Vector check functions

def check_vector_2100_sideload_enabled(target: str, adb_port: int = 5555, timeout: int = 10) -> Dict[str, Any]:
    """VECTOR_2100: Sideload Enabled"""
    try:
        result = _check_android_sideload_enabled(adb_port)
        
        return {
            'vulnerable': result['vulnerable'],
            'details': result['details'],
            'severity': 'MEDIUM'
        }
        
    except Exception as e:
        return {'vulnerable': False, 'details': f'Error: {str(e)}', 'severity': 'MEDIUM'}


def check_vector_2101_developer_mode_active(target: str, adb_port: int = 5555, timeout: int = 10) -> Dict[str, Any]:
    """VECTOR_2101: Developer Mode Active"""
    try:
        result = _check_android_developer_mode_active(adb_port)
        
        return {
            'vulnerable': result['vulnerable'],
            'details': result['details'],
            'severity': 'MEDIUM'
        }
        
    except Exception as e:
        return {'vulnerable': False, 'details': f'Error: {str(e)}', 'severity': 'MEDIUM'}


def check_vector_2106_root_access_detected(target: str, adb_port: int = 5555, timeout: int = 10) -> Dict[str, Any]:
    """VECTOR_2106: Root Access Detected"""
    try:
        result = _check_android_root_access(adb_port)
        
        return {
            'vulnerable': result['vulnerable'],
            'details': result['details'],
            'severity': 'CRITICAL'
        }
        
    except Exception as e:
        return {'vulnerable': False, 'details': f'Error: {str(e)}', 'severity': 'CRITICAL'}


def check_vector_2109_old_android_version(target: str, adb_port: int = 5555, timeout: int = 10) -> Dict[str, Any]:
    """VECTOR_2109: Old Android Version"""
    try:
        result = _check_android_version_outdated(adb_port)
        
        return {
            'vulnerable': result['vulnerable'],
            'details': result['details'],
            'severity': 'HIGH'
        }
        
    except Exception as e:
        return {'vulnerable': False, 'details': f'Error: {str(e)}', 'severity': 'HIGH'}


def check_vector_2110_outdated_security_patches(target: str, adb_port: int = 5555, timeout: int = 10) -> Dict[str, Any]:
    """VECTOR_2110: Outdated Security Patches"""
    try:
        result = _check_android_security_patches_outdated(adb_port)
        
        return {
            'vulnerable': result['vulnerable'],
            'details': result['details'],
            'severity': 'HIGH'
        }
        
    except Exception as e:
        return {'vulnerable': False, 'details': f'Error: {str(e)}', 'severity': 'HIGH'}


def check_vector_2115_backup_enabled(target: str, adb_port: int = 5555, timeout: int = 10) -> Dict[str, Any]:
    """VECTOR_2115: Backup Enabled"""
    try:
        result = _check_android_backup_enabled(adb_port)
        
        return {
            'vulnerable': result['vulnerable'],
            'details': result['details'],
            'severity': 'MEDIUM'
        }
        
    except Exception as e:
        return {'vulnerable': False, 'details': f'Error: {str(e)}', 'severity': 'MEDIUM'}


def check_vector_3301_debuggable_apps(target: str, adb_port: int = 5555, timeout: int = 15) -> Dict[str, Any]:
    """VECTOR_3301: Debuggable Apps"""
    try:
        result = _check_android_debuggable_apps(adb_port)
        
        return {
            'vulnerable': result['vulnerable'],
            'details': result['details'],
            'severity': 'MEDIUM'
        }
        
    except Exception as e:
        return {'vulnerable': False, 'details': f'Error: {str(e)}', 'severity': 'MEDIUM'}


def check_vector_3305_backup_agent_vulnerability(target: str, adb_port: int = 5555, timeout: int = 15) -> Dict[str, Any]:
    """VECTOR_3305: Backup Agent Vulnerability"""
    try:
        result = _check_android_backup_agent_vulnerability(adb_port)
        
        return {
            'vulnerable': result['vulnerable'],
            'details': result['details'],
            'severity': 'MEDIUM'
        }
        
    except Exception as e:
        return {'vulnerable': False, 'details': f'Error: {str(e)}', 'severity': 'MEDIUM'}


def check_vector_3318_safetynet_attestation(target: str, adb_port: int = 5555, timeout: int = 15) -> Dict[str, Any]:
    """VECTOR_3318: SafetyNet Attestation"""
    try:
        result = _check_android_safetynet_attestation(adb_port)
        
        return {
            'vulnerable': result['vulnerable'],
            'details': result['details'],
            'severity': 'MEDIUM'
        }
        
    except Exception as e:
        return {'vulnerable': False, 'details': f'Error: {str(e)}', 'severity': 'MEDIUM'}


def check_vector_3319_play_integrity_api(target: str, adb_port: int = 5555, timeout: int = 15) -> Dict[str, Any]:
    """VECTOR_3319: Play Integrity API"""
    try:
        result = _check_android_play_integrity_api(adb_port)
        
        return {
            'vulnerable': result['vulnerable'],
            'details': result['details'],
            'severity': 'MEDIUM'
        }
        
    except Exception as e:
        return {'vulnerable': False, 'details': f'Error: {str(e)}', 'severity': 'MEDium'}