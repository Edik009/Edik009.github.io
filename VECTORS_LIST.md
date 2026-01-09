# AASFA Scanner v3.0 - Complete Vectors List

## Overview

AASFA Scanner v3.0 implements **1200 security check vectors** divided into 10 categories:

- **Category A**: Network & Remote Access (Vectors 1-40)
- **Category B**: Android OS Logic (Vectors 41-100)
- **Category C**: Application Layer (Vectors 101-170)
- **Category D**: Supply Chain / Exotic (Vectors 171-300)
- **Category E**: Network Services (Vectors 301-380)
- **Category F**: Firmware/OS/Low-level (Vectors 381-520)
- **Category G**: AI/ML/Modern (Vectors 521-900)
- **Category H**: Behavioral & Correlation (Vectors 901-980) **[NEW]**
- **Category I**: OEM & Supply Chain (Vectors 981-1060) **[NEW]**
- **Category J**: AI / System Intelligence (Vectors 1061-1200) **[NEW]**

## Statistics

- **Total Vectors**: 1200
- **Implemented Checks**: 300+ fully implemented (vectors 901-1200 with real pipeline)
- **Network-based**: All vectors (1200/1200) - **Network-only analysis**
- **ADB-based**: 0 (removed in v3.0)
- **Pipeline-based**: 300 vectors (901-1200)

## v3.0 Key Changes

### Network-Only Architecture
- ❌ **Removed**: All ADB, USB, Bluetooth, UART, JTAG, fastboot access
- ✅ **Network-only**: All vectors use network-based analysis
- ✅ **Real implementations**: Vectors 901-1200 use signal pipeline architecture

### Pipeline Architecture
- Signal Collection (Network, Timing, Protocol, Behavior)
- Signal Normalization
- Feature Extraction
- Scoring
- Correlation
- Decision Making (CONFIRMED / NOT_FOUND / INCONCLUSIVE)

### Output Changes
- Only CONFIRMED vectors are displayed
- MSF-style formatting
- Legal disclaimers included
- Evidence-based reporting

## Implementation Status

### Fully Implemented Checks (30+)

#### Network Level (10 checks)
- VNC Availability
- RDP Availability
- SSH Open No Rate Limit
- Telnet Presence
- UPnP Exposure
- mDNS Exposure
- HTTP Admin Panels
- HTTPS Without HSTS
- FTP Anonymous Access
- MQTT Exposure

#### ADB Level (10 checks)
- ADB Over TCP
- Debuggable Build
- ro.secure Misconfiguration
- ro.adb.secure Check
- Test Keys Detection
- SELinux Permissive Mode
- Userdebug Remnants
- System UID Leakage
- Logcat Sensitive Data
- Root Access Detection

#### Service Level (6 checks)
- Exported Activities
- Exported Services
- Exported Receivers
- ContentProvider Exposure
- Backup Flag Enabled
- Intent Hijacking

#### Crypto & Firmware (4 checks)
- Hardware-backed Keystore
- Verified Boot Status
- Bootloader Unlock Status
- Security Patch Level

### Stub Implementations (270+)

All remaining vectors have stub implementations that:
- Return proper data structure
- Include severity classification
- Are ready for full implementation
- Can be extended without breaking the scanner

## Category Details

### A. Network & Remote Access (1-40)

Remote service exposure and network protocol vulnerabilities:
- Remote desktop protocols (VNC, RDP)
- Network services (SSH, Telnet, FTP, TFTP)
- IoT protocols (UPnP, mDNS, MQTT, DLNA)
- Web services (HTTP, HTTPS, WebSocket, WebDAV)
- Network misconfigurations (IPv6, DNS, DHCP, ARP)
- OEM diagnostic ports and backdoors

### B. Android OS Logic (41-100)

Android operating system security checks:
- Build configuration (debuggable, test-keys, userdebug)
- Security features (SELinux, verified boot, dm-verity)
- System properties and permissions
- IPC mechanisms (Binder, Intent, Broadcast)
- Component exposure (Activities, Services, Receivers, Providers)
- Keystore and cryptographic storage
- Kernel and bootloader security
- System hardening features

### C. Application Layer (101-170)

Application-level security vulnerabilities:
- Authentication and session management
- Cryptographic implementation
- WebView security
- Native code vulnerabilities
- Data leakage vectors
- Third-party SDK issues
- Hardware sensor abuse
- Machine learning model security
- Payment and wallet security

### D. Supply Chain / Exotic (171-300)

Advanced and exotic attack vectors:
- OTA update security
- Firmware and baseband security
- Hardware interfaces (USB, JTAG, UART)
- Side-channel attacks (power, acoustic, thermal)
- Biometric security
- Enterprise and MDM features
- Virtualization and containerization
- CPU and memory vulnerabilities
- Browser and rendering engine security
- AI and ML on-device features
- Factory and diagnostic residue

## Severity Distribution

Vectors are classified by severity:
- **CRITICAL**: Remote code execution, full device compromise
- **HIGH**: Privilege escalation, data theft, authentication bypass
- **MEDIUM**: Information disclosure, limited privilege escalation
- **LOW**: Information leakage, minor configuration issues
- **INFO**: Informational findings

## Usage Examples

### Scan by Category
```bash
# Only network checks (Category A)
python3 main.py -t 192.168.1.100 -m fast

# OS and Application checks (Categories B & C)
python3 main.py -t 192.168.1.100 -m full --adb-only

# All checks including exotic (All categories)
python3 main.py -t 192.168.1.100 -m deep
```

### Scan by Mode
```bash
# Fast: Priority 1-2 (Categories A-B, ~100 checks)
python3 main.py -t 192.168.1.100 -m fast

# Full: Priority 1-3 (Categories A-C, ~170 checks)
python3 main.py -t 192.168.1.100 -m full

# Deep: All priorities (All categories, 300 checks)
python3 main.py -t 192.168.1.100 -m deep
```

## Extending the Scanner

To implement a new check:

1. Add implementation in appropriate `checks/` file
2. Vector is auto-registered from `vectors/` definitions
3. Update `scanner_engine.py` module_map if needed
4. Test the check independently
5. Run full scan to verify integration

Example:
```python
def check_my_vector(target: str, port: int, timeout: int) -> Dict[str, Any]:
    """My custom security check"""
    # Implementation
    return {
        "vulnerable": True/False,
        "details": "Description of finding",
        "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO"
    }
```

## Dependencies Between Vectors

Some vectors depend on others:
- Categories B, C, D depend on Vector 6 (ADB Over TCP)
- Chain-aware execution ensures dependencies are met
- Missing dependencies are handled gracefully

## Performance

- Parallel execution with configurable threads
- Typical scan times:
  - Fast mode: 3-5 minutes
  - Full mode: 5-10 minutes
  - Deep mode: 10-20 minutes
- Network latency is the main bottleneck

## Zero-Exploit Policy

All checks follow these principles:
- ✅ Read-only operations
- ✅ Availability checks
- ✅ Configuration analysis
- ❌ No exploitation
- ❌ No payload execution
- ❌ No DoS attacks
- ❌ No system modifications
