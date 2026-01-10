"""
Additional Side-Channel Analysis Check Functions for AASFA Scanner v4.0
Part 2 - CDN, Push, DNS, and Advanced Protocol Analysis

Continuing the implementation of side-channel vectors with more advanced protocols.
"""
import requests
import socket
import ssl
import time
import hashlib
from typing import Dict, Any, List
from urllib.parse import urljoin

from ..utils.baseline import load_baseline_db


def check_cdn_response_headers(target: str, adb_port: int, timeout: int) -> Dict[str, Any]:
    """Проверка CDN response headers"""
    try:
        response = requests.get(f"https://{target}/", timeout=timeout, verify=False)
        headers = response.headers
        
        # Common CDN headers
        cdn_headers = {
            "cloudflare": ["cf-ray", "cf-cache-status", "cf-origin-host"],
            "akamai": ["x-cache", "x-served-by", "x-cache-status"],
            "fastly": ["x-served-by", "x-cache", "x-cache-status"],
            "aws_cloudfront": ["x-amz-cf-id", "x-amz-cf-pop"],
            "google_cdn": ["x-goog-meta-", "x-goog-"]
        }
        
        detected_cdns = []
        for cdn, header_patterns in cdn_headers.items():
            for pattern in header_patterns:
                for header in headers:
                    if pattern.lower() in header.lower():
                        detected_cdns.append(cdn)
                        break
        
        if detected_cdns:
            unique_cdns = list(set(detected_cdns))
            return {
                "vulnerable": True,
                "details": f"CDN detected: {', '.join(unique_cdns)}",
                "confidence": 0.9,
                "detected_cdns": unique_cdns,
                "cdn_headers": headers
            }
        else:
            return {
                "vulnerable": False,
                "details": "No CDN headers detected",
                "confidence": 0.3,
                "cdn_headers": headers
            }
    except Exception as e:
        return {"vulnerable": False, "details": f"CDN check error: {e}", "confidence": 0.0}


def check_edge_server_signature(target: str, adb_port: int, timeout: int) -> Dict[str, Any]:
    """Анализ edge server signatures"""
    try:
        response = requests.get(f"https://{target}/", timeout=timeout, verify=False)
        headers = response.headers
        
        # Look for server signatures
        server_headers = []
        if "server" in headers:
            server_headers.append(("server", headers["server"]))
        if "x-powered-by" in headers:
            server_headers.append(("x-powered-by", headers["x-powered-by"]))
        if "x-served-by" in headers:
            server_headers.append(("x-served-by", headers["x-served-by"]))
        
        # Generate signature hash
        signature = "-".join([f"{h}:{v}" for h, v in server_headers])
        signature_hash = hashlib.sha256(signature.encode()).hexdigest()
        
        return {
            "vulnerable": len(server_headers) > 0,
            "details": f"Edge server fingerprint: {signature_hash[:16]}... ({len(server_headers)} identifiers)",
            "confidence": min(0.8, len(server_headers) * 0.3),
            "server_headers": server_headers,
            "signature_hash": signature_hash
        }
    except Exception as e:
        return {"vulnerable": False, "details": f"Edge server check error: {e}", "confidence": 0.0}


def check_geo_location_leak(target: str, adb_port: int, timeout: int) -> Dict[str, Any]:
    """Анализ географической информации в ответах"""
    try:
        response = requests.get(f"https://{target}/", timeout=timeout, verify=False)
        
        # Check for geo-related headers
        geo_headers = ["x-geo-country", "x-geo-region", "x-geo-city", "cf-ipcountry", "x-amz-cf-pop"]
        found_geo = []
        
        for header in geo_headers:
            if header in response.headers:
                found_geo.append((header, response.headers[header]))
        
        # Check response content for geo references
        geo_in_content = any(keyword in response.text.lower() for keyword in [
            "country", "region", "city", "timezone", "location"
        ])
        
        if found_geo or geo_in_content:
            return {
                "vulnerable": True,
                "details": f"Geographic information leakage detected: {len(found_geo)} headers, content={geo_in_content}",
                "confidence": min(0.8, (len(found_geo) + int(geo_in_content)) * 0.3),
                "geo_headers": found_geo,
                "geo_in_content": geo_in_content
            }
        else:
            return {
                "vulnerable": False,
                "details": "No geographic information leakage detected",
                "confidence": 0.7
            }
    except Exception as e:
        return {"vulnerable": False, "details": f"Geo location check error: {e}", "confidence": 0.0}


def check_fcm_endpoint_access(target: str, adb_port: int, timeout: int) -> Dict[str, Any]:
    """Проверка доступности FCM endpoint"""
    try:
        fcm_endpoints = [
            "/fcm/send",
            "/api/fcm/send", 
            "/firebase/send",
            "/push/fcm"
        ]
        
        accessible_endpoints = []
        
        for endpoint in fcm_endpoints:
            try:
                response = requests.post(
                    f"https://{target}{endpoint}",
                    json={"to": "/topics/test"},
                    timeout=timeout,
                    verify=False
                )
                
                if response.status_code in [200, 201, 400, 401]:  # Accessible
                    accessible_endpoints.append({
                        "endpoint": endpoint,
                        "status": response.status_code,
                        "accessible": True
                    })
            except:
                accessible_endpoints.append({
                    "endpoint": endpoint,
                    "accessible": False
                })
        
        accessible_count = sum(1 for ep in accessible_endpoints if ep.get("accessible", False))
        
        if accessible_count > 0:
            return {
                "vulnerable": True,
                "details": f"FCM endpoints accessible: {accessible_count}/{len(fcm_endpoints)}",
                "confidence": min(0.8, accessible_count * 0.3),
                "accessible_endpoints": accessible_endpoints
            }
        else:
            return {
                "vulnerable": False,
                "details": "No accessible FCM endpoints detected",
                "confidence": 0.6,
                "accessible_endpoints": accessible_endpoints
            }
    except Exception as e:
        return {"vulnerable": False, "details": f"FCM endpoint check error: {e}", "confidence": 0.0}


def check_push_token_format(target: str, adb_port: int, timeout: int) -> Dict[str, Any]:
    """Анализ формата push token"""
    try:
        # Test various endpoints that might return or validate push tokens
        token_endpoints = [
            "/api/auth/token",
            "/push/register",
            "/firebase/register",
            "/notifications/register"
        ]
        
        token_patterns = []
        
        for endpoint in token_endpoints:
            try:
                response = requests.get(f"https://{target}{endpoint}", timeout=timeout, verify=False)
                
                # Look for token-like patterns in response
                import re
                token_patterns_found = re.findall(r'[a-zA-Z0-9]{32,}', response.text)
                
                if token_patterns_found:
                    token_patterns.append({
                        "endpoint": endpoint,
                        "token_length": len(token_patterns_found[0]) if token_patterns_found else 0,
                        "patterns_found": len(token_patterns_found)
                    })
            except:
                continue
        
        if token_patterns:
            return {
                "vulnerable": True,
                "details": f"Push token patterns detected: {len(token_patterns)} endpoints",
                "confidence": min(0.7, len(token_patterns) * 0.3),
                "token_patterns": token_patterns
            }
        else:
            return {
                "vulnerable": False,
                "details": "No push token patterns detected",
                "confidence": 0.5
            }
    except Exception as e:
        return {"vulnerable": False, "details": f"Push token format check error: {e}", "confidence": 0.0}


def check_retry_behavior(target: str, adb_port: int, timeout: int) -> Dict[str, Any]:
    """Анализ retry patterns"""
    try:
        # Test retry behavior on failed endpoints
        test_endpoints = ["/api/nonexistent", "/push/invalid", "/auth/invalid"]
        retry_indicators = []
        
        for endpoint in test_endpoints:
            responses = []
            for attempt in range(3):  # Multiple attempts
                try:
                    start_time = time.time()
                    response = requests.get(f"https://{target}{endpoint}", timeout=timeout, verify=False)
                    end_time = time.time()
                    
                    responses.append({
                        "attempt": attempt + 1,
                        "status": response.status_code,
                        "time": end_time - start_time,
                        "retry_after": response.headers.get("retry-after")
                    })
                except:
                    responses.append({
                        "attempt": attempt + 1,
                        "error": "timeout"
                    })
            
            # Analyze retry patterns
            has_retry_after = any(r.get("retry_after") for r in responses)
            has_progressive_delay = len(set(r.get("time", 0) for r in responses)) > 1
            
            if has_retry_after or has_progressive_delay:
                retry_indicators.append({
                    "endpoint": endpoint,
                    "has_retry_after": has_retry_after,
                    "has_progressive_delay": has_progressive_delay,
                    "responses": responses
                })
        
        if retry_indicators:
            return {
                "vulnerable": True,
                "details": f"Retry behavior detected: {len(retry_indicators)} endpoints",
                "confidence": min(0.8, len(retry_indicators) * 0.4),
                "retry_indicators": retry_indicators
            }
        else:
            return {
                "vulnerable": False,
                "details": "No retry behavior patterns detected",
                "confidence": 0.6
            }
    except Exception as e:
        return {"vulnerable": False, "details": f"Retry behavior check error: {e}", "confidence": 0.0}


def check_ticket_entropy(target: str, adb_port: int, timeout: int) -> Dict[str, Any]:
    """Анализ энтропии TLS session tickets"""
    try:
        # Connect multiple times to analyze session ticket patterns
        ticket_hashes = []
        
        for i in range(5):
            try:
                sock = socket.create_connection((target, 443), timeout=timeout)
                context = ssl.SSLContext()
                conn = context.wrap_socket(sock, server_hostname=target)
                
                # Extract session ticket if available
                if hasattr(conn, 'session'):
                    session_data = conn.session
                    if session_data:
                        ticket_hash = hashlib.sha256(str(session_data).encode()).hexdigest()
                        ticket_hashes.append(ticket_hash)
                
                conn.close()
            except:
                continue
        
        # Analyze entropy (unique tickets vs repeated)
        unique_tickets = len(set(ticket_hashes))
        entropy_score = unique_tickets / max(len(ticket_hashes), 1)
        
        if len(ticket_hashes) > 0:
            if entropy_score < 0.5:  # Low entropy = predictable
                return {
                    "vulnerable": True,
                    "details": f"Low TLS session ticket entropy: {unique_tickets}/{len(ticket_hashes)} unique",
                    "confidence": min(0.9, 1 - entropy_score),
                    "entropy_score": entropy_score,
                    "unique_tickets": unique_tickets
                }
            else:
                return {
                    "vulnerable": False,
                    "details": f"Good TLS session ticket entropy: {unique_tickets}/{len(ticket_hashes)} unique",
                    "confidence": min(0.8, entropy_score),
                    "entropy_score": entropy_score
                }
        else:
            return {
                "vulnerable": False,
                "details": "No session tickets observed",
                "confidence": 0.3
            }
    except Exception as e:
        return {"vulnerable": False, "details": f"Ticket entropy check error: {e}", "confidence": 0.0}


def check_ticket_reusability(target: str, adb_port: int, timeout: int) -> Dict[str, Any]:
    """Анализ переиспользования session tickets"""
    try:
        # Test session resumption
        session_times = []
        
        for i in range(3):
            start_time = time.time()
            try:
                sock = socket.create_connection((target, 443), timeout=timeout)
                context = ssl.SSLContext()
                conn = context.wrap_socket(sock, server_hostname=target)
                
                # Check if session resumption is happening
                if hasattr(conn, 'session_reused') and conn.session_reused:
                    session_times.append(time.time() - start_time)
                else:
                    # Full handshake
                    time.sleep(0.1)
                    session_times.append(time.time() - start_time + 0.1)
                
                conn.close()
            except:
                continue
        
        if len(session_times) >= 2:
            # Compare first connection vs resumed connections
            first_time = session_times[0]
            resumed_times = session_times[1:]
            
            avg_resumed = sum(resumed_times) / len(resumed_times)
            speedup = (first_time - avg_resumed) / first_time if first_time > 0 else 0
            
            if speedup > 0.3:  # 30% speedup indicates session resumption
                return {
                    "vulnerable": True,
                    "details": f"TLS session resumption detected: {speedup:.1%} speedup",
                    "confidence": min(0.8, speedup),
                    "speedup": speedup,
                    "session_times": session_times
                }
            else:
                return {
                    "vulnerable": False,
                    "details": f"No significant session resumption: {speedup:.1%} speedup",
                    "confidence": 0.6,
                    "speedup": speedup
                }
        else:
            return {
                "vulnerable": False,
                "details": "Insufficient data for session resumption analysis",
                "confidence": 0.3
            }
    except Exception as e:
        return {"vulnerable": False, "details": f"Ticket reusability check error: {e}", "confidence": 0.0}


def check_ticket_lifetime(target: str, adb_port: int, timeout: int) -> Dict[str, Any]:
    """Анализ lifetime session tickets"""
    try:
        # Test session ticket lifetime by making requests at intervals
        lifetimes = []
        
        for interval in [1, 5, 10, 30, 60]:  # seconds
            try:
                # First connection - get session ticket
                sock1 = socket.create_connection((target, 443), timeout=timeout)
                context1 = ssl.SSLContext()
                conn1 = context1.wrap_socket(sock1, server_hostname=target)
                
                # Wait interval
                time.sleep(interval)
                
                # Second connection - try to resume
                sock2 = socket.create_connection((target, 443), timeout=timeout)
                context2 = ssl.SSLContext()
                conn2 = context2.wrap_socket(sock2, server_hostname=target)
                
                # Check if session was resumed
                resumed = hasattr(conn2, 'session_reused') and conn2.session_reused
                
                lifetimes.append({
                    "interval": interval,
                    "resumed": resumed
                })
                
                conn1.close()
                conn2.close()
                
            except:
                lifetimes.append({
                    "interval": interval,
                    "error": True
                })
        
        # Analyze ticket lifetime
        valid_intervals = [l["interval"] for l in lifetimes if not l.get("error")]
        resumed_intervals = [l["interval"] for l in lifetimes if l.get("resumed")]
        
        if resumed_intervals:
            max_lifetime = max(resumed_intervals)
            return {
                "vulnerable": True,
                "details": f"TLS session tickets valid for at least {max_lifetime}s",
                "confidence": min(0.7, max_lifetime / 60),  # Confidence increases with lifetime
                "max_lifetime": max_lifetime,
                "lifetimes": lifetimes
            }
        else:
            return {
                "vulnerable": False,
                "details": "No session ticket resumption detected",
                "confidence": 0.4,
                "lifetimes": lifetimes
            }
    except Exception as e:
        return {"vulnerable": False, "details": f"Ticket lifetime check error: {e}", "confidence": 0.0}


def check_doh_support(target: str, adb_port: int, timeout: int) -> Dict[str, Any]:
    """Проверка поддержки DNS-over-HTTPS"""
    try:
        # Test common DoH endpoints
        doh_endpoints = [
            "https://dns.google/resolve?name=example.com",
            "https://cloudflare-dns.com/dns-query?name=example.com",
            "https://dns.quad9.net/dns-query?name=example.com"
        ]
        
        accessible_doh = []
        
        for endpoint in doh_endpoints:
            try:
                response = requests.get(endpoint, timeout=timeout, verify=False)
                
                if response.status_code == 200 and "application/dns-json" in response.headers.get("content-type", ""):
                    accessible_doh.append({
                        "endpoint": endpoint.split("/")[2],  # Extract domain
                        "status": "dns-json"
                    })
                elif response.status_code == 200:
                    accessible_doh.append({
                        "endpoint": endpoint.split("/")[2],
                        "status": "other-format"
                    })
            except:
                continue
        
        if accessible_doh:
            return {
                "vulnerable": True,
                "details": f"DoH support detected: {len(accessible_doh)} providers",
                "confidence": min(0.8, len(accessible_doh) * 0.3),
                "accessible_doh": accessible_doh
            }
        else:
            return {
                "vulnerable": False,
                "details": "No DoH support detected",
                "confidence": 0.5
            }
    except Exception as e:
        return {"vulnerable": False, "details": f"DoH support check error: {e}", "confidence": 0.0}


def check_fallback_to_plaintext(target: str, adb_port: int, timeout: int) -> Dict[str, Any]:
    """Проверка fallback на plaintext DNS"""
    try:
        # Test DNS resolution behavior
        test_domains = ["google.com", "github.com", "stackoverflow.com"]
        resolution_results = []
        
        import subprocess
        
        for domain in test_domains:
            try:
                # Try DoH first
                doh_response = requests.get(
                    f"https://dns.google/resolve?name={domain}",
                    timeout=timeout,
                    verify=False
                )
                
                # Try plaintext DNS
                try:
                    result = subprocess.run(
                        ["nslookup", domain],
                        capture_output=True,
                        text=True,
                        timeout=timeout
                    )
                    plaintext_success = result.returncode == 0
                except:
                    plaintext_success = False
                
                resolution_results.append({
                    "domain": domain,
                    "doh_success": doh_response.status_code == 200,
                    "plaintext_success": plaintext_success,
                    "fallback": plaintext_success and doh_response.status_code != 200
                })
                
            except:
                resolution_results.append({
                    "domain": domain,
                    "error": True
                })
        
        fallback_count = sum(1 for r in resolution_results if r.get("fallback"))
        
        if fallback_count > 0:
            return {
                "vulnerable": True,
                "details": f"DNS fallback detected: {fallback_count}/{len(test_domains)} domains",
                "confidence": min(0.7, fallback_count / len(test_domains)),
                "fallback_count": fallback_count,
                "resolution_results": resolution_results
            }
        else:
            return {
                "vulnerable": False,
                "details": "No DNS fallback behavior detected",
                "confidence": 0.6,
                "resolution_results": resolution_results
            }
    except Exception as e:
        return {"vulnerable": False, "details": f"DNS fallback check error: {e}", "confidence": 0.0}


def check_plaintext_dns_consistency(target: str, adb_port: int, timeout: int) -> Dict[str, Any]:
    """Проверка консистентности plaintext DNS"""
    try:
        import subprocess
        
        # Test DNS consistency
        test_domains = ["google.com", "1.1.1.1", "8.8.8.8"]
        dns_results = []
        
        for domain in test_domains:
            try:
                # Multiple DNS queries to same domain
                results = []
                for attempt in range(3):
                    try:
                        result = subprocess.run(
                            ["nslookup", domain],
                            capture_output=True,
                            text=True,
                            timeout=timeout
                        )
                        if result.returncode == 0:
                            results.append(result.stdout.strip())
                    except:
                        continue
                
                # Check consistency
                unique_results = len(set(results))
                
                dns_results.append({
                    "domain": domain,
                    "attempts": len(results),
                    "unique_results": unique_results,
                    "consistent": unique_results <= 1
                })
                
            except:
                dns_results.append({
                    "domain": domain,
                    "error": True
                })
        
        consistent_domains = sum(1 for r in dns_results if r.get("consistent", False))
        total_tested = sum(1 for r in dns_results if not r.get("error"))
        
        if total_tested > 0:
            consistency_rate = consistent_domains / total_tested
            
            if consistency_rate < 0.8:  # Less than 80% consistent
                return {
                    "vulnerable": True,
                    "details": f"Inconsistent DNS responses: {consistent_domains}/{total_tested} domains",
                    "confidence": min(0.7, 1 - consistency_rate),
                    "consistency_rate": consistency_rate,
                    "dns_results": dns_results
                }
            else:
                return {
                    "vulnerable": False,
                    "details": f"Consistent DNS responses: {consistent_domains}/{total_tested} domains",
                    "confidence": consistency_rate,
                    "consistency_rate": consistency_rate
                }
        else:
            return {
                "vulnerable": False,
                "details": "No DNS consistency data collected",
                "confidence": 0.3
            }
    except Exception as e:
        return {"vulnerable": False, "details": f"DNS consistency check error: {e}", "confidence": 0.0}