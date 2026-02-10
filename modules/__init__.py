#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bitrix Pentest Tool - Modules Package
Security testing modules for Bitrix CMS
"""

__version__ = "1.1.0"
__author__ = "Security Researcher"
__modules__ = [
    'recon', 
    'info_disclosure', 
    'auth_bypass', 
    'sqli_scanner', 
    'xss_scanner', 
    'file_upload', 
    'rce_tester',
    'xxe_ssrf',
    'integration_1c',
    'excel_rce',
    'api_scanner'
]

# Module exports
from .recon import BitrixRecon, ReconResult
from .info_disclosure import BitrixInfoDisclosure, DisclosureResult, DisclosureFinding
from .auth_bypass import BitrixAuthBypass, AuthResult, AuthFinding
from .sqli_scanner import BitrixSQLiScanner, SQLiResult, SQLiFinding
from .xss_scanner import BitrixXSSScanner, XSSResult, XSSFinding
from .file_upload import BitrixFileUploadScanner, UploadResult, UploadFinding
from .rce_tester import BitrixRCETester, RCEResult, RCEFinding
from .xxe_ssrf import BitrixXXESSRFScanner, XXESSRFResult, XXESSRFFinding
from .integration_1c import Bitrix1CIntegrationScanner, Integration1CResult, Integration1CFinding
from .excel_rce import BitrixExcelRCEScanner, ExcelRCEResult, ExcelRCEFinding
from .api_scanner import BitrixAPIScanner, APIResult, APIFinding

__all__ = [
    # Recon
    'BitrixRecon', 
    'ReconResult',
    # Info Disclosure
    'BitrixInfoDisclosure', 
    'DisclosureResult',
    'DisclosureFinding',
    # Auth Bypass
    'BitrixAuthBypass',
    'AuthResult',
    'AuthFinding',
    # SQL Injection
    'BitrixSQLiScanner',
    'SQLiResult',
    'SQLiFinding',
    # XSS
    'BitrixXSSScanner',
    'XSSResult',
    'XSSFinding',
    # File Upload
    'BitrixFileUploadScanner',
    'UploadResult',
    'UploadFinding',
    # RCE
    'BitrixRCETester',
    'RCEResult',
    'RCEFinding',
    # XXE/SSRF
    'BitrixXXESSRFScanner',
    'XXESSRFResult',
    'XXESSRFFinding',
    # 1C Integration
    'Bitrix1CIntegrationScanner',
    'Integration1CResult',
    'Integration1CFinding',
    # Excel RCE
    'BitrixExcelRCEScanner',
    'ExcelRCEResult',
    'ExcelRCEFinding',
    # API Scanner
    'BitrixAPIScanner',
    'APIResult',
    'APIFinding',
]