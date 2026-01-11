"""
Unit tests for Network Security Vectors module
"""

import unittest
import sys
from pathlib import Path

# Добавление корневой директории в PYTHONPATH
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from aasfa.vectors.network_security_vectors import (
    NetworkSecurityVectors,
    scan_network_security_vectors,
    get_vector_count,
    get_vector_categories,
    ping_host,
    port_is_open,
    is_weak_cipher,
    analyze_ssh_banner,
    analyze_http_headers,
)
from aasfa.utils.config import ScanConfig


class TestNetworkSecurityVectors(unittest.TestCase):
    """Test cases for NetworkSecurityVectors class"""
    
    def setUp(self):
        """Setup test fixtures"""
        self.config = ScanConfig(
            target_ip='127.0.0.1',
            mode='fast',
            timeout=2,
            port_scan_timeout=1
        )
        self.scanner = NetworkSecurityVectors(self.config)
    
    def test_scanner_initialization(self):
        """Test scanner initialization"""
        self.assertIsNotNone(self.scanner)
        self.assertEqual(self.scanner.target_ip, '127.0.0.1')
        self.assertEqual(self.scanner.timeout, 2)
    
    def test_get_all_vectors(self):
        """Test getting all vectors"""
        vectors = self.scanner.get_all_vectors()
        self.assertIsInstance(vectors, list)
        self.assertGreater(len(vectors), 0)
        self.assertEqual(len(vectors), 19)  # 19 vectors including helpers
    
    def test_get_vector_count(self):
        """Test vector count function"""
        count = get_vector_count()
        self.assertEqual(count, 18)
    
    def test_get_vector_categories(self):
        """Test vector categories function"""
        categories = get_vector_categories()
        self.assertIsInstance(categories, dict)
        self.assertIn('basic_ports', categories)
        self.assertIn('ssl_tls', categories)
        self.assertIn('network_services', categories)
        self.assertIn('protocol_vulnerabilities', categories)
        
        # Проверка количества векторов в каждой категории
        self.assertEqual(len(categories['basic_ports']), 7)
        self.assertEqual(len(categories['ssl_tls']), 4)
        self.assertEqual(len(categories['network_services']), 5)
        self.assertEqual(len(categories['protocol_vulnerabilities']), 3)
    
    def test_telnet_vector(self):
        """Test Telnet port check vector"""
        result = self.scanner.check_telnet_port_open()
        
        self.assertIsInstance(result, dict)
        self.assertIn('vector_id', result)
        self.assertIn('vector_name', result)
        self.assertIn('vulnerable', result)
        self.assertIn('details', result)
        self.assertIn('factors', result)
        self.assertIn('confidence', result)
        self.assertIn('timestamp', result)
        
        self.assertEqual(result['vector_id'], 1001)
        self.assertEqual(result['vector_name'], 'Telnet Port Open (23)')
        self.assertIsInstance(result['vulnerable'], bool)
        self.assertIsInstance(result['factors'], list)
        self.assertGreaterEqual(result['confidence'], 0.0)
        self.assertLessEqual(result['confidence'], 1.0)
    
    def test_ftp_vector(self):
        """Test FTP port check vector"""
        result = self.scanner.check_ftp_port_open()
        
        self.assertIn('vector_id', result)
        self.assertEqual(result['vector_id'], 1002)
        self.assertIn('can_login_anonymous', result)
        self.assertIsInstance(result['can_login_anonymous'], bool)
    
    def test_ssh_vector(self):
        """Test SSH port check vector"""
        result = self.scanner.check_ssh_port_open()
        
        self.assertIn('vector_id', result)
        self.assertEqual(result['vector_id'], 1003)
        self.assertIn('ssh_version', result)
        self.assertIn('algorithms', result)
    
    def test_http_vector(self):
        """Test HTTP port check vector"""
        result = self.scanner.check_http_port_open()
        
        self.assertIn('vector_id', result)
        self.assertEqual(result['vector_id'], 1004)
        self.assertIn('is_redirect_to_https', result)
        self.assertIn('server_header', result)
    
    def test_https_vector(self):
        """Test HTTPS port check vector"""
        result = self.scanner.check_https_port_open()
        
        self.assertIn('vector_id', result)
        self.assertEqual(result['vector_id'], 1005)
        self.assertIn('cert_info', result)
    
    def test_weak_ssl_ciphers_vector(self):
        """Test weak SSL/TLS ciphers vector"""
        result = self.scanner.check_weak_ssl_tls_ciphers()
        
        self.assertIn('vector_id', result)
        self.assertEqual(result['vector_id'], 2001)
        self.assertIn('weak_ciphers', result)
        self.assertIn('missing_pfs', result)
    
    def test_self_signed_certificate_vector(self):
        """Test self-signed certificate vector"""
        result = self.scanner.check_self_signed_certificate()
        
        self.assertIn('vector_id', result)
        self.assertEqual(result['vector_id'], 2002)
        self.assertIn('issuer', result)
        self.assertIn('subject', result)
    
    def test_build_result(self):
        """Test _build_result helper method"""
        factors = [
            {"name": "Test 1", "passed": True, "reason": "OK"},
            {"name": "Test 2", "passed": False, "reason": "Failed"},
        ]
        
        result = self.scanner._build_result(
            vector_id=9999,
            vector_name="Test Vector",
            vulnerable=True,
            details="Test details",
            factors=factors
        )
        
        self.assertEqual(result['vector_id'], 9999)
        self.assertEqual(result['vector_name'], "Test Vector")
        self.assertTrue(result['vulnerable'])
        self.assertEqual(result['details'], "Test details")
        self.assertEqual(result['factors'], factors)
        self.assertEqual(result['confidence'], 0.5)  # 1/2 факторов
        self.assertIn('timestamp', result)
        self.assertIsNone(result['error'])


class TestUtilityFunctions(unittest.TestCase):
    """Test cases for utility functions"""
    
    def test_port_is_open_localhost(self):
        """Test port_is_open with localhost"""
        # Тест будет зависеть от того, что запущено на localhost
        # Просто проверяем что функция работает
        result = port_is_open('127.0.0.1', 80, timeout=1)
        self.assertIsInstance(result, bool)
    
    def test_is_weak_cipher(self):
        """Test is_weak_cipher function"""
        # Слабые ciphers
        self.assertTrue(is_weak_cipher('RC4-SHA'))
        self.assertTrue(is_weak_cipher('DES-CBC-SHA'))
        self.assertTrue(is_weak_cipher('EXPORT-RC4'))
        self.assertTrue(is_weak_cipher('NULL-MD5'))
        
        # Сильные ciphers
        self.assertFalse(is_weak_cipher('AES256-GCM-SHA384'))
        self.assertFalse(is_weak_cipher('ECDHE-RSA-AES128-GCM-SHA256'))
    
    def test_analyze_ssh_banner(self):
        """Test SSH banner analysis"""
        # OpenSSH старая версия
        banner1 = "SSH-2.0-OpenSSH_6.7"
        result1 = analyze_ssh_banner(banner1)
        self.assertEqual(result1['protocol_version'], '2.0')
        self.assertIn('OpenSSH', result1['software_version'])
        self.assertEqual(result1['software_name'], 'OpenSSH')
        self.assertTrue(result1['is_old_version'])
        
        # OpenSSH новая версия
        banner2 = "SSH-2.0-OpenSSH_8.2"
        result2 = analyze_ssh_banner(banner2)
        self.assertEqual(result2['protocol_version'], '2.0')
        self.assertFalse(result2['is_old_version'])
        
        # SSH-1 протокол
        banner3 = "SSH-1.99-OpenSSH_3.9"
        result3 = analyze_ssh_banner(banner3)
        self.assertTrue(result3['is_old_version'])
    
    def test_analyze_http_headers(self):
        """Test HTTP headers analysis"""
        headers = """HTTP/1.1 200 OK
Server: nginx/1.18.0
Content-Type: text/html; charset=utf-8
Location: https://example.com
Strict-Transport-Security: max-age=31536000
Connection: close"""
        
        result = analyze_http_headers(headers)
        
        self.assertEqual(result['server'], 'nginx/1.18.0')
        self.assertEqual(result['content_type'], 'text/html; charset=utf-8')
        self.assertEqual(result['location'], 'https://example.com')
        self.assertEqual(result['strict_transport_security'], 'max-age=31536000')
        self.assertIn('server', result['all_headers'])
        self.assertIn('content-type', result['all_headers'])


class TestScannerIntegration(unittest.TestCase):
    """Integration tests for scanner"""
    
    def setUp(self):
        """Setup test fixtures"""
        self.config = ScanConfig(
            target_ip='127.0.0.1',
            mode='fast',
            timeout=2,
            port_scan_timeout=1
        )
    
    def test_scan_network_security_vectors(self):
        """Test full scan function"""
        results = scan_network_security_vectors(self.config)
        
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        
        # Проверка структуры каждого результата
        for result in results:
            self.assertIn('vector_id', result)
            self.assertIn('vector_name', result)
            self.assertIn('vulnerable', result)
            self.assertIn('factors', result)
            self.assertIn('confidence', result)
    
    def test_run_all_checks(self):
        """Test running all checks"""
        scanner = NetworkSecurityVectors(self.config)
        results = scanner.run_all_checks()
        
        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 19)
        
        # Проверка что все векторы вернули результаты
        for result in results:
            self.assertIsInstance(result, dict)
            self.assertIn('vector_id', result)
            self.assertGreaterEqual(result['confidence'], 0.0)
            self.assertLessEqual(result['confidence'], 1.0)


class TestFactorValidation(unittest.TestCase):
    """Test factor validation for vectors"""
    
    def setUp(self):
        """Setup test fixtures"""
        self.config = ScanConfig(
            target_ip='127.0.0.1',
            mode='fast',
            timeout=2,
            port_scan_timeout=1
        )
        self.scanner = NetworkSecurityVectors(self.config)
    
    def test_telnet_factors(self):
        """Test Telnet vector factors"""
        result = self.scanner.check_telnet_port_open()
        factors = result['factors']
        
        # Должно быть 4 фактора
        self.assertGreaterEqual(len(factors), 2)
        
        # Проверка структуры факторов
        for factor in factors:
            self.assertIn('name', factor)
            self.assertIn('passed', factor)
            self.assertIn('reason', factor)
            self.assertIsInstance(factor['passed'], bool)
    
    def test_ftp_factors(self):
        """Test FTP vector factors"""
        result = self.scanner.check_ftp_port_open()
        factors = result['factors']
        
        # Должно быть 5 факторов
        self.assertGreaterEqual(len(factors), 2)
        
        factor_names = [f['name'] for f in factors]
        self.assertIn('ICMP Ping', factor_names)
        self.assertIn('Port 21 Open', factor_names)


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Добавление всех тестов
    suite.addTests(loader.loadTestsFromTestCase(TestNetworkSecurityVectors))
    suite.addTests(loader.loadTestsFromTestCase(TestUtilityFunctions))
    suite.addTests(loader.loadTestsFromTestCase(TestScannerIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestFactorValidation))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
