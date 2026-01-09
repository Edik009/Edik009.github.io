# AASFA Scanner - Usage Examples

## Basic Usage

### Quick Scan
```bash
# Basic scan with default settings
python3 main.py -t 192.168.1.100

# Fast scan (network + basic OS checks)
python3 main.py -t 192.168.1.100 -m fast

# Full scan (recommended)
python3 main.py -t 192.168.1.100 -m full

# Deep scan (all 900+ vectors)
python3 main.py -t 192.168.1.100 -m deep
```

## Advanced Usage

### Custom Port
```bash
# Scan device with ADB on custom port
python3 main.py -t 192.168.1.100 -p 5556
```

### Output to File
```bash
# Text report
python3 main.py -t 192.168.1.100 -o scan_report.txt

# JSON report (for automation)
python3 main.py -t 192.168.1.100 -o scan_report.json
```

### Verbose Mode
```bash
# Verbose output with detailed logs
python3 main.py -t 192.168.1.100 -v

# This creates aasfa_scan.log file
```

### Performance Tuning
```bash
# More threads for faster scanning
python3 main.py -t 192.168.1.100 --threads 20

# Longer timeout for slow networks
python3 main.py -t 192.168.1.100 --timeout 60

# Both combined
python3 main.py -t 192.168.1.100 --threads 15 --timeout 45
```

## Filtering Checks

### Remote/Network Only
```bash
# Only remote/network checks (NO USB REQUIRED)
python3 main.py -t 192.168.1.100 --remote-only

# This will scan ports, services, protocols, endpoints
```

### ADB Only
```bash
# Only ADB-based checks (device must have ADB enabled)
python3 main.py -t 192.168.1.100 --adb-only

# Skips all network-level checks
```

### Combined Filtering
```bash
# Fast mode + ADB only + verbose
python3 main.py -t 192.168.1.100 -m fast --adb-only -v
```

## Real-World Scenarios

### Scenario 1: Initial Assessment
```bash
# Quick assessment of unknown device
python3 main.py -t 192.168.1.100 -m fast -o initial_scan.txt

# Review the report, then decide on deeper scan
```

### Scenario 2: Full Security Audit
```bash
# Comprehensive audit with all checks
python3 main.py -t 192.168.1.100 -m deep -v \
  --timeout 60 --threads 10 -o full_audit.json

# Takes 15-20 minutes, generates detailed JSON report
```

### Scenario 3: Network Penetration Test
```bash
# Focus on network exposure
python3 main.py -t 192.168.1.100 -m fast \
  --timeout 30 -o network_scan.txt

# Fast, focuses on exposed services
```

### Scenario 4: Application Security Review
```bash
# Deep dive into application layer
python3 main.py -t 192.168.1.100 -m full --adb-only \
  -v -o app_security.json

# Requires ADB access, checks app-level vulnerabilities
```

### Scenario 5: CI/CD Integration
```bash
#!/bin/bash
# scan_device.sh - Automated scanning script

TARGET_IP="192.168.1.100"
OUTPUT_DIR="./scan_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p $OUTPUT_DIR

# Run scan
python3 main.py -t $TARGET_IP -m full \
  --timeout 45 --threads 10 \
  -o "$OUTPUT_DIR/scan_${TIMESTAMP}.json"

# Check exit code
if [ $? -eq 2 ]; then
  echo "CRITICAL vulnerabilities found!"
  exit 1
fi

echo "Scan completed successfully"
```

### Scenario 6: Multiple Devices
```bash
#!/bin/bash
# scan_network.sh - Scan multiple devices

DEVICES=(
  "192.168.1.100"
  "192.168.1.101"
  "192.168.1.102"
)

for device in "${DEVICES[@]}"; do
  echo "Scanning $device..."
  python3 main.py -t $device -m fast \
    -o "reports/scan_${device}.txt" &
done

wait
echo "All scans completed"
```

## Understanding Results

### Exit Codes
```
0 - Scan completed, no critical issues
1 - Error occurred during scanning
2 - Critical vulnerabilities found
130 - Scan interrupted (Ctrl+C)
```

### Severity Levels
```
CRITICAL - Immediate action required
  - Remote code execution possible
  - Full device compromise
  - Actively exploitable

HIGH - Should be fixed soon
  - Privilege escalation
  - Data theft possible
  - Authentication bypass

MEDIUM - Should be addressed
  - Information disclosure
  - Partial privilege escalation
  - Configuration issues

LOW - Minor issues
  - Information leakage
  - Best practice violations
  - Minor misconfigurations
```

### Sample Output Interpretation
```
[!] VECTOR_006: ADB Over TCP [CRITICAL]
    → ADB is exposed on network, anyone can connect
    → Action: Disable ADB or use ADB over USB only

[+] VECTOR_041: Debuggable Build [HIGH]
    → Device is running debug build
    → Action: Use production/user build for production devices

[*] VECTOR_073: Backup Flag Enabled [MEDIUM]
    → App data can be backed up
    → Action: Review backup settings for sensitive apps
```

## Automation Examples

### Python Script
```python
#!/usr/bin/env python3
import subprocess
import json

def scan_device(ip, mode='fast'):
    """Scan a device and return results"""
    cmd = [
        'python3', 'main.py',
        '-t', ip,
        '-m', mode,
        '-o', f'/tmp/scan_{ip}.json'
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        with open(f'/tmp/scan_{ip}.json', 'r') as f:
            return json.load(f)
    return None

# Usage
results = scan_device('192.168.1.100', mode='full')
if results:
    print(f"Found {results['summary']['vulnerabilities_found']} issues")
```

### Jenkins Pipeline
```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    sh """
                        python3 main.py \
                            -t ${DEVICE_IP} \
                            -m full \
                            -o scan_results.json
                    """
                    
                    def results = readJSON file: 'scan_results.json'
                    
                    if (results.summary.critical > 0) {
                        error("Critical vulnerabilities found!")
                    }
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'scan_results.json'
        }
    }
}
```

## Troubleshooting

### ADB Connection Issues
```bash
# Check if ADB is accessible
adb connect 192.168.1.100:5555

# If connection fails, try manual port
python3 main.py -t 192.168.1.100 -p 5556

# Use network-only mode if ADB unavailable
python3 main.py -t 192.168.1.100 --no-network=false
```

### Timeout Issues
```bash
# Increase timeout for slow networks
python3 main.py -t 192.168.1.100 --timeout 120

# Reduce threads to avoid overwhelming device
python3 main.py -t 192.168.1.100 --threads 3 --timeout 60
```

### Permission Issues
```bash
# Some network scans require root (for ICMP)
sudo python3 main.py -t 192.168.1.100

# Or skip problematic checks
python3 main.py -t 192.168.1.100 --adb-only
```

## Tips & Best Practices

1. **Start with fast mode** to get quick results
2. **Use verbose mode** when debugging issues
3. **Save results to JSON** for automated processing
4. **Run periodic scans** to track security posture
5. **Compare results** over time to detect regressions
6. **Customize timeout** based on network conditions
7. **Use appropriate threads** (10 is usually optimal)
8. **Check exit codes** in automation scripts
9. **Review logs** when troubleshooting
10. **Keep scanner updated** for latest checks

## Getting Help

```bash
# Show all available options
python3 main.py --help

# Check version and statistics
python3 -c "from aasfa.core.vector_registry import VectorRegistry; \
  r = VectorRegistry(); print(f'{len(r.vectors)} vectors loaded')"
```
