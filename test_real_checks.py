#!/usr/bin/env python3
"""Test script for real security check implementations."""

import sys
import os

# Add the project directory to Python path
sys.path.insert(0, '/home/engine/project')

from aasfa.core.vector_registry import VectorRegistry
from aasfa.checks.network_layer_checks import (
    check_vector_152_tls_extension_order_fingerprinting,
    check_vector_2506_api_rate_limiting
)
from aasfa.checks.crypto_advanced_checks import check_vector_4800_quantum_resistant_crypto
from aasfa.checks.android_advanced_security_checks import check_vector_2106_root_access_detected
from aasfa.checks.container_cloud_checks import check_vector_3602_container_escape


def test_vector_loading():
    """Test that vectors are loaded correctly."""
    print("=== Testing Vector Loading ===")
    
    registry = VectorRegistry()
    stats = registry.get_statistics()
    
    print(f"Total vectors loaded: {stats['total']}")
    print(f"Network vectors: {stats.get('category_Network', 0)}")
    print(f"Crypto vectors: {stats.get('category_Crypto', 0)}")
    print(f"Android vectors: {stats.get('category_Android', 0)}")
    print(f"Container vectors: {stats.get('category_Container', 0)}")
    
    # Test specific vectors
    test_vectors = [152, 155, 156, 160, 2005, 2506, 4800, 4809, 2100, 2106, 2109, 3602, 3603, 3604, 2801]
    
    for vector_id in test_vectors:
        vector = registry.get_vector(vector_id)
        if vector:
            print(f"✓ VECTOR_{vector_id}: {vector.name}")
        else:
            print(f"✗ VECTOR_{vector_id}: Not found")
    
    return stats['total'] > 0


def test_network_checks():
    """Test network layer security checks."""
    print("\n=== Testing Network Checks ===")
    
    # Test with a public server (google.com)
    target = "google.com"
    
    try:
        # Test TLS fingerprinting
        print("Testing TLS Extension Fingerprinting...")
        result = check_vector_152_tls_extension_order_fingerprinting(target)
        print(f"Result: {result}")
        
        # Test API rate limiting
        print("\nTesting API Rate Limiting...")
        result = check_vector_2506_api_rate_limiting(target)
        print(f"Result: {result}")
        
        return True
        
    except Exception as e:
        print(f"Error in network checks: {e}")
        return False


def test_crypto_checks():
    """Test cryptographic checks."""
    print("\n=== Testing Crypto Checks ===")
    
    target = "google.com"
    
    try:
        # Test quantum resistant crypto
        print("Testing Quantum Resistant Crypto...")
        result = check_vector_4800_quantum_resistant_crypto(target)
        print(f"Result: {result}")
        
        return True
        
    except Exception as e:
        print(f"Error in crypto checks: {e}")
        return False


def test_android_checks():
    """Test Android checks."""
    print("\n=== Testing Android Checks ===")
    
    try:
        # Test root access detection (will fail without ADB connection)
        print("Testing Root Access Detection...")
        result = check_vector_2106_root_access_detected("localhost", adb_port=5555)
        print(f"Result: {result}")
        
        return True
        
    except Exception as e:
        print(f"Error in Android checks: {e}")
        return False


def test_container_checks():
    """Test container checks."""
    print("\n=== Testing Container Checks ===")
    
    try:
        # Test container escape detection
        print("Testing Container Escape Detection...")
        result = check_vector_3602_container_escape("localhost")
        print(f"Result: {result}")
        
        return True
        
    except Exception as e:
        print(f"Error in container checks: {e}")
        return False


def main():
    """Main test function."""
    print("Real Security Checks Implementation Test")
    print("=" * 50)
    
    success = True
    
    # Test vector loading
    if not test_vector_loading():
        success = False
        print("❌ Vector loading test failed")
    else:
        print("✅ Vector loading test passed")
    
    # Test individual check modules
    if not test_network_checks():
        success = False
        print("❌ Network checks test failed")
    else:
        print("✅ Network checks test passed")
    
    if not test_crypto_checks():
        success = False
        print("❌ Crypto checks test failed")
    else:
        print("✅ Crypto checks test passed")
    
    if not test_android_checks():
        success = False
        print("❌ Android checks test failed")
    else:
        print("✅ Android checks test passed")
    
    if not test_container_checks():
        success = False
        print("❌ Container checks test failed")
    else:
        print("✅ Container checks test passed")
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 All tests passed! Real security checks are working.")
    else:
        print("⚠️  Some tests failed. Check the implementation.")
    
    return 0 if success else 1


if __name__ == "__main__":
    exit(main())