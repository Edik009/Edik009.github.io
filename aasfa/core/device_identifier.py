"""
Real Device Identification System - Identifies devices through active scanning
"""

import socket
import re
import time
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..utils.config import ScanConfig
from ..connectors import network, http


class DeviceIdentifier:
    """Real device identification through network fingerprinting"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.network_connector = network.NetworkConnector(host=config.target_ip, timeout=config.timeout)
        self.http_connector = http.HTTPConnector(host=config.target_ip, port=80, use_ssl=False, timeout=config.timeout)
    
    def identify_device(self) -> Dict[str, Any]:
        """Perform real device identification"""
        print("Performing device identification...")
        
        device_info = {
            'ip_address': self.config.target_ip,
            'device_type': 'Unknown',
            'manufacturer': 'Unknown',
            'model': 'Unknown',
            'os_name': 'Unknown',
            'os_version': 'Unknown',
            'architecture': 'Unknown',
            'kernel_version': 'Unknown',
            'mac_address': 'Unknown',
            'open_ports': 0,
            'vulnerable_status': 'Unknown',
            'confidence': 0
        }
        
        # Run multiple identification methods in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            
            # Network fingerprinting
            futures.append(executor.submit(self._identify_by_port_scan))
            futures.append(executor.submit(self._identify_by_mac_address))
            futures.append(executor.submit(self._identify_by_ttl))
            
            # Service fingerprinting
            futures.append(executor.submit(self._identify_by_http_banner))
            futures.append(executor.submit(self._identify_by_ssh_banner))
            futures.append(executor.submit(self._identify_by_telnet_banner))
            
            # Android-specific checks
            futures.append(executor.submit(self._identify_by_adb))
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self._merge_device_info(device_info, result)
                except Exception as e:
                    print(f"Identification method failed: {str(e)}")
        
        # Final classification
        self._classify_device(device_info)
        
        return device_info
    
    def _identify_by_port_scan(self) -> Dict[str, Any]:
        """Identify device by open ports"""
        info = {}
        common_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 135: 'msrpc', 139: 'netbios', 143: 'imap',
            443: 'https', 445: 'smb', 993: 'imaps', 995: 'pop3s', 1723: 'pptp',
            3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc',
            8080: 'http-proxy', 8443: 'https-alt', 27017: 'mongodb',
            5555: 'adb'  # Android Debug Bridge
        }
        
        open_ports = []
        for port, service in common_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.port_scan_timeout)
            result = sock.connect_ex((self.config.target_ip, port))
            sock.close()
            
            if result == 0:
                open_ports.append((port, service))
        
        info['open_ports'] = len(open_ports)
        
        # Analyze port patterns to identify device type
        port_numbers = [p[0] for p in open_ports]
        services = [p[1] for p in open_ports]
        
        if 3389 in port_numbers:
            info['device_type'] = 'Windows Computer'
            info['os_name'] = 'Windows'
            info['confidence'] = 80
        elif 445 in port_numbers and 139 in port_numbers:
            info['device_type'] = 'Windows Computer'
            info['os_name'] = 'Windows'
            info['confidence'] = 70
        elif 22 in port_numbers and 80 in port_numbers:
            info['device_type'] = 'Linux Server'
            info['os_name'] = 'Linux'
            info['confidence'] = 60
        elif 5555 in port_numbers:
            info['device_type'] = 'Android Device'
            info['os_name'] = 'Android'
            info['confidence'] = 90
        
        return info
    
    def _identify_by_mac_address(self) -> Dict[str, Any]:
        """Get MAC address and identify manufacturer"""
        # Note: This requires ARP which may not always work
        # For now, return empty, in real implementation would use ARP or SNMP
        return {}
    
    def _identify_by_ttl(self) -> Dict[str, Any]:
        """Identify OS by TTL value"""
        try:
            # Use ping to get TTL
            result = self.network_connector.ping(self.config.target_ip, timeout=self.config.timeout)
            
            if result.get('reachable', False):
                ttl = result.get('ttl', 0)
                
                if ttl:
                    # Common TTL values
                    if ttl <= 64:
                        return {
                            'os_name': 'Linux/Unix/Android',
                            'device_type': 'Linux-based Device',
                            'confidence': 60,
                            'ttl': ttl
                        }
                    elif ttl <= 128:
                        return {
                            'os_name': 'Windows',
                            'device_type': 'Windows Device',
                            'confidence': 60,
                            'ttl': ttl
                        }
                    elif ttl <= 255:
                        return {
                            'os_name': 'Cisco/Network Device',
                            'device_type': 'Network Equipment',
                            'confidence': 60,
                            'ttl': ttl
                        }
        except:
            pass
        
        return {}
    
    def _identify_by_http_banner(self) -> Dict[str, Any]:
        """Identify by HTTP server banner"""
        info = {}
        
        try:
            # Build URL properly with port
            http_url = f"{self.config.target_ip}"
            if ':' not in http_url:
                http_url += ":80"
            
            response = self.http_connector.get(f"/{http_url}", timeout=self.config.timeout)
            
            if response is None:
                return info
                
            # Check Server header
            server = response.headers.get('Server', '')
            if server:
                info['server'] = server
                
                if 'Apache' in server:
                    info['device_type'] = 'Web Server'
                    info['os_name'] = 'Linux/Unix'
                    info['confidence'] = 70
                elif 'IIS' in server or 'Microsoft' in server:
                    info['device_type'] = 'Web Server'
                    info['os_name'] = 'Windows'
                    info['confidence'] = 70
                elif 'nginx' in server:
                    info['device_type'] = 'Web Server'
                    info['os_name'] = 'Linux/Unix'
                    info['confidence'] = 70
            
            # Check HTML content for device identifiers
            if response.text:
                if 'router' in response.text.lower() or 'modem' in response.text.lower():
                    info['device_type'] = 'Network Router/Modem'
                    info['confidence'] = 80
                elif 'camera' in response.text.lower() or 'ipcam' in response.text.lower():
                    info['device_type'] = 'IP Camera'
                    info['confidence'] = 80
                elif 'printer' in response.text.lower():
                    info['device_type'] = 'Network Printer'
                    info['confidence'] = 80
                
                # Look for specific device info in HTML
                model_match = re.search(r'(Model|model|MODEL):?\s*([A-Z0-9\-_]+)', response.text)
                if model_match:
                    info['model'] = model_match.group(2)
        
        except Exception as e:
            print(f"HTTP banner identification failed: {str(e)}")
        
        return info
    
    def _identify_by_ssh_banner(self) -> Dict[str, Any]:
        """Identify by SSH banner"""
        info = {}
        
        try:
            banner = self.network_connector.get_service_banner(22) or ""
            
            if 'ssh' in banner.lower():
                info['service_ssh'] = True
                info['ssh_banner'] = banner.strip()
                
                # Extract OS from SSH banner
                if 'OpenSSH' in banner:
                    if '_linux' in banner.lower() or 'ubuntu' in banner.lower() or 'debian' in banner.lower():
                        info['os_name'] = 'Linux'
                        info['device_type'] = 'Linux Server'
                        info['confidence'] = 80
                    elif 'freebsd' in banner.lower():
                        info['os_name'] = 'FreeBSD'
                        info['device_type'] = 'BSD Server'
                        info['confidence'] = 80
                elif 'WinSSHD' in banner or 'Windows' in banner:
                    info['os_name'] = 'Windows'
                    info['device_type'] = 'Windows Server'
                    info['confidence'] = 80
        
        except:
            pass
        
        return info
    
    def _identify_by_telnet_banner(self) -> Dict[str, Any]:
        """Identify by Telnet banner"""
        info = {}
        
        try:
            banner = self.network_connector.get_service_banner(23)
            
            if banner:
                info['service_telnet'] = True
                info['telnet_banner'] = banner.strip()
                
                # Look for device type in telnet banner
                if 'router' in banner.lower():
                    info['device_type'] = 'Network Router'
                    info['confidence'] = 70
                elif 'switch' in banner.lower():
                    info['device_type'] = 'Network Switch'
                    info['confidence'] = 70
                elif 'cisco' in banner.lower():
                    info['device_type'] = 'Cisco Device'
                    info['confidence'] = 90
                    # Extract model
                    model_match = re.search(r'Cisco\s+([A-Z0-9\-]+)', banner, re.IGNORECASE)
                    if model_match:
                        info['model'] = model_match.group(1)
        
        except:
            pass
        
        return info
    
    def _identify_by_adb(self) -> Dict[str, Any]:
        """Identify Android device via ADB"""
        info = {}
        
        try:
            # Check if ADB port is open
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.port_scan_timeout)
            result = sock.connect_ex((self.config.target_ip, 5555))
            sock.close()
            
            if result == 0:
                info['device_type'] = 'Android Device'
                info['os_name'] = 'Android'
                info['confidence'] = 90
                
                # Try to get device info via ADB
                try:
                    import subprocess
                    
                    # Connect to device
                    subprocess.run(['adb', 'connect', f'{self.config.target_ip}:5555'], 
                                 capture_output=True, timeout=5)
                    
                    # Get device properties
                    result = subprocess.run(['adb', '-s', f'{self.config.target_ip}:5555', 'shell', 'getprop'], 
                                          capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0:
                        props = result.stdout
                        
                        # Extract Android version
                        version_match = re.search(r'ro\.build\.version\.release]:\s+\[([^\]]+)\]', props)
                        if version_match:
                            info['os_version'] = version_match.group(1)
                        
                        # Extract manufacturer
                        manuf_match = re.search(r'ro\.product\.manufacturer]:\s+\[([^\]]+)\]', props)
                        if manuf_match:
                            info['manufacturer'] = manuf_match.group(1)
                        
                        # Extract model
                        model_match = re.search(r'ro\.product\.model]:\s+\[([^\]]+)\]', props)
                        if model_match:
                            info['model'] = model_match.group(1)
                        
                        info['adb_accessible'] = True
                
                except:
                    pass
        
        except:
            pass
        
        return info
    
    def _merge_device_info(self, target: Dict[str, Any], source: Dict[str, Any]):
        """Merge device information from multiple sources"""
        for key, value in source.items():
            if key == 'confidence':
                # Keep highest confidence
                if value > target.get('confidence', 0):
                    target['confidence'] = value
            else:
                # Update if current value is 'Unknown' or new value has higher confidence
                if target.get(key, 'Unknown') == 'Unknown' or source.get('confidence', 0) > target.get('confidence', 0):
                    target[key] = value
    
    def _classify_device(self, info: Dict[str, Any]):
        """Final classification and vulnerability assessment"""
        # Determine vulnerable status based on identified characteristics
        vulnerable_indicators = []
        
        if info.get('os_name') == 'Android':
            # Check Android version for vulnerabilities
            version = info.get('os_version', '')
            if version:
                try:
                    major_version = int(version.split('.')[0])
                    if major_version < 8:
                        vulnerable_indicators.append(f"Outdated Android version ({version})")
                except:
                    pass
        
        if info.get('adb_accessible'):
            vulnerable_indicators.append("ADB debugging enabled")
        
        if info['open_ports'] > 10:
            vulnerable_indicators.append(f"Too many open ports ({info['open_ports']})")
        
        # Check for risky services
        risky_ports = [21, 23, 139, 445]  # FTP, Telnet, SMB
        for port in risky_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.port_scan_timeout)
            result = sock.connect_ex((self.config.target_ip, port))
            sock.close()
            
            if result == 0:
                service_name = {21: 'FTP', 23: 'Telnet', 139: 'NetBIOS', 445: 'SMB'}.get(port)
                vulnerable_indicators.append(f"{service_name} service running")
        
        # Set vulnerability status
        if len(vulnerable_indicators) >= 3:
            info['vulnerable_status'] = 'КРИТИЧЕСКИ УЯЗВИМОЕ'
        elif len(vulnerable_indicators) >= 2:
            info['vulnerable_status'] = 'ВЫСОКО УЯЗВИМОЕ'
        elif len(vulnerable_indicators) >= 1:
            info['vulnerable_status'] = 'УЯЗВИМОЕ'
        else:
            info['vulnerable_status'] = 'ОТНОСИТЕЛЬНО БЕЗОПАСНОЕ'
        
        info['vulnerable_indicators'] = vulnerable_indicators
        
        return info


def identify_device_real(config: ScanConfig) -> Dict[str, Any]:
    """Public function to identify device"""
    identifier = DeviceIdentifier(config)
    return identifier.identify_device()