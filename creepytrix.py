#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bitrix Pentest Tool v1.1
Main entry point for the penetration testing tool
Modules: Recon | Info Disclosure | Auth Bypass | SQLi | XSS | Upload | RCE | XXE/SSRF | 1C Integration | Excel RCE | API Scanner
Based on: https://pentestnotes.ru/notes/bitrix_pentest_full/
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from typing import Optional, Dict, Any

# Import modules
from modules.recon import BitrixRecon, ReconResult
from modules.info_disclosure import BitrixInfoDisclosure, DisclosureResult
from modules.auth_bypass import BitrixAuthBypass, AuthResult
from modules.sqli_scanner import BitrixSQLiScanner, SQLiResult
from modules.xss_scanner import BitrixXSSScanner, XSSResult
from modules.file_upload import BitrixFileUploadScanner, UploadResult
from modules.rce_tester import BitrixRCETester, RCEResult
from modules.xxe_ssrf import BitrixXXESSRFScanner, XXESSRFResult
from modules.integration_1c import Bitrix1CIntegrationScanner, Integration1CResult
from modules.excel_rce import BitrixExcelRCEScanner, ExcelRCEResult
from modules.api_scanner import BitrixAPIScanner, APIResult
from utils.requester import Requester
from utils.logger import ColoredLogger
from utils.parser import BitrixParser


def create_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser"""
    parser = argparse.ArgumentParser(
        description='Bitrix Pentest Tool - Comprehensive security testing suite for Bitrix CMS',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modules:
  recon        - Reconnaissance (version detection, structure analysis)
  disclosure   - Information Disclosure (configs, backups, logs)
  auth         - Authentication Bypass (default creds, session issues)
  sqli         - SQL Injection Scanner (error, boolean, time, union-based)
  xss          - XSS Scanner (reflected, stored, DOM-based, blind)
  upload       - File Upload Scanner (arbitrary, bypass, traversal, race)
  rce          - RCE Tester (command injection, code eval, known CVEs)
  xxe_ssrf     - XXE/SSRF Scanner (XML External Entity, Server-Side Request Forgery)
  1c           - 1C Integration Scanner (1C Exchange, Enterprise data leakage)
  excel        - Excel RCE Scanner (Formula injection, DDE, CSV injection, Power Query)
  api          - API Scanner (REST, SOAP, GraphQL, JWT, IDOR, Mass Assignment)
  
Examples:
  %(prog)s https://example.com                      # Run all modules
  %(prog)s https://example.com -m api -a            # Aggressive API testing
  %(prog)s https://example.com -m rce -a            # Aggressive RCE test
  %(prog)s https://example.com -m excel -a          # Test Excel RCE vectors
  %(prog)s https://example.com -m 1c -a             # Test 1C integration
  %(prog)s https://example.com -m xxe_ssrf -a       # Aggressive XXE/SSRF test
  %(prog)s https://example.com -o result.json       # Save full results
  %(prog)s https://example.com --proxy http://127.0.0.1:8080
        """
    )
    
    parser.add_argument(
        'target',
        help='Target URL (e.g., https://example.com or example.com)'
    )
    
    parser.add_argument(
        '-m', '--module',
        choices=['all', 'recon', 'disclosure', 'auth', 'sqli', 'xss', 'upload', 'rce', 'xxe_ssrf', '1c', 'excel', 'api'],
        default='all',
        help='Module to run (default: all)'
    )
    
    parser.add_argument(
        '-a', '--aggressive',
        action='store_true',
        help='Enable aggressive scanning mode (destructive tests, RCE attempts, blind XXE/OOB, 1C data modification, Excel payload execution, API mass assignment)'
    )
    
    parser.add_argument(
        '-o', '--output',
        metavar='FILE',
        help='Output file for results (JSON format)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output (DEBUG level)'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode (only errors and critical findings)'
    )
    
    parser.add_argument(
        '--proxy',
        metavar='URL',
        help='HTTP/HTTPS proxy (e.g., http://127.0.0.1:8080)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        metavar='SECONDS',
        help='Request timeout in seconds (default: 10)'
    )
    
    parser.add_argument(
        '--delay',
        type=float,
        default=0.5,
        metavar='SECONDS',
        help='Delay between requests (default: 0.5)'
    )
    
    parser.add_argument(
        '--oob-server',
        metavar='URL',
        help='Out-of-band server for blind XXE testing (e.g., http://your-server.com)'
    )
    
    parser.add_argument(
        '--callback-server',
        metavar='URL',
        help='Callback server for Excel RCE detection (e.g., http://your-server.com)'
    )
    
    return parser


def print_banner(logger: ColoredLogger):
    """Print tool banner"""
    banner = """
                                                                       
                                                                        
    ▄█████ █████▄  ██████ ██████ █████▄ ██  ██ ██████ █████▄  ██ ██  ██ 
    ██     ██▄▄██▄ ██▄▄   ██▄▄   ██▄▄█▀  ▀██▀    ██   ██▄▄██▄ ██  ████  
    ▀█████ ██   ██ ██▄▄▄▄ ██▄▄▄▄ ██       ██     ██   ██   ██ ██ ██  ██ 
                                                                        
                                                        
    Bitrix Security Testing Tool v1.1 by KL3FT3Z (https://github.com/V3kt0r39)
    Modules: Recon | Info Disclosure | Auth Bypass | SQLi | XSS | Upload | RCE | XXE/SSRF | 1C | Excel RCE | API
    Based on: https://pentestnotes.ru/notes/bitrix_pentest_full/
    """
    logger.info(banner)


def print_recon_results(result: ReconResult, logger: ColoredLogger):
    """Print reconnaissance results"""
    logger.info("=" * 60)
    logger.info("RECONNAISSANCE RESULTS")
    logger.info("=" * 60)
    
    logger.info(f"Target URL: {result.url}")
    logger.info(f"Bitrix Detected: {'Yes' if result.bitrix_detected else 'No'}")
    
    if not result.bitrix_detected:
        logger.warning("Bitrix CMS not detected on target")
        return
    
    if result.version:
        logger.success(f"Version: {result.version}")
    
    if result.edition:
        logger.success(f"Edition: {result.edition}")
    
    if result.admin_url:
        logger.success(f"Admin Panel: {result.admin_url}")


def print_disclosure_results(result: DisclosureResult, logger: ColoredLogger):
    """Print information disclosure results"""
    logger.info("=" * 60)
    logger.info("INFORMATION DISCLOSURE RESULTS")
    logger.info("=" * 60)
    
    summary = result.to_dict()['summary']
    
    if summary['critical'] > 0:
        logger.critical(f"CRITICAL: {summary['critical']}")
    if summary['high'] > 0:
        logger.error(f"HIGH: {summary['high']}")
    
    logger.info(f"\nTotal Findings: {summary['total_findings']}")


def print_auth_results(result: AuthResult, logger: ColoredLogger):
    """Print authentication testing results"""
    logger.info("=" * 60)
    logger.info("AUTHENTICATION TEST RESULTS")
    logger.info("=" * 60)
    
    summary = result.to_dict()['summary']
    
    if summary['critical'] > 0:
        logger.critical(f"CRITICAL: {summary['critical']}")
    
    if result.valid_credentials:
        logger.critical("\n!!! VALID CREDENTIALS FOUND !!!")


def print_sqli_results(result: SQLiResult, logger: ColoredLogger):
    """Print SQL injection results"""
    logger.info("=" * 60)
    logger.info("SQL INJECTION RESULTS")
    logger.info("=" * 60)
    
    if result.dbms_detected:
        logger.success(f"DBMS Detected: {result.dbms_detected.upper()}")
    
    summary = result.to_dict()['summary']
    
    if summary['critical'] > 0:
        logger.critical(f"CRITICAL: {summary['critical']}")
    
    logger.info(f"\nTotal Findings: {summary['total_findings']}")


def print_xss_results(result: XSSResult, logger: ColoredLogger):
    """Print XSS results"""
    logger.info("=" * 60)
    logger.info("XSS SCAN RESULTS")
    logger.info("=" * 60)
    
    summary = result.to_dict()['summary']
    
    if summary['critical'] > 0:
        logger.critical(f"CRITICAL: {summary['critical']}")
    if summary['high'] > 0:
        logger.error(f"HIGH: {summary['high']}")
    
    logger.info(f"\nTotal Findings: {summary['total_findings']}")


def print_upload_results(result: UploadResult, logger: ColoredLogger):
    """Print file upload results"""
    logger.info("=" * 60)
    logger.info("FILE UPLOAD SCAN RESULTS")
    logger.info("=" * 60)
    
    summary = result.to_dict()['summary']
    
    if summary['critical'] > 0:
        logger.critical(f"CRITICAL: {summary['critical']}")
    
    logger.info(f"\nTotal Findings: {summary['total_findings']}")


def print_rce_results(result: RCEResult, logger: ColoredLogger):
    """Print RCE results"""
    logger.info("=" * 60)
    logger.info("RCE TEST RESULTS")
    logger.info("=" * 60)
    
    summary = result.to_dict()['summary']
    
    if summary['critical'] > 0:
        logger.critical(f"CRITICAL: {summary['critical']}")
        logger.critical("!!! REMOTE CODE EXECUTION POSSIBLE !!!")
    
    logger.info(f"\nTotal Findings: {summary['total_findings']}")
    logger.info(f"Command Injections: {summary['command_injections']}")
    logger.info(f"Code Evaluations: {summary['code_evaluations']}")
    logger.info(f"Deserializations: {summary['deserializations']}")
    logger.info(f"Template Injections: {summary['template_injections']}")
    logger.info(f"Known CVEs: {summary['known_cves']}")
    
    # Print shell URLs
    shells = [f for f in result.findings if f.shell_url]
    if shells:
        logger.critical(f"\n!!! SHELLS AVAILABLE: {len(shells)} !!!")
        for finding in shells:
            logger.critical(f"  {finding.shell_url}?cmd=whoami")


def print_xxe_ssrf_results(result: XXESSRFResult, logger: ColoredLogger):
    """Print XXE/SSRF results"""
    logger.info("=" * 60)
    logger.info("XXE/SSRF SCAN RESULTS")
    logger.info("=" * 60)
    
    summary = result.to_dict()['summary']
    
    if summary['critical'] > 0:
        logger.critical(f"CRITICAL: {summary['critical']}")
    if summary['high'] > 0:
        logger.error(f"HIGH: {summary['high']}")
    
    logger.info(f"\nTotal Findings: {summary['total_findings']}")
    logger.info(f"XXE Vulnerabilities: {summary['xxe']}")
    logger.info(f"SSRF Vulnerabilities: {summary['ssrf']}")
    logger.info(f"Blind XXE: {summary['blind_xxe']}")
    logger.info(f"OOB Findings: {summary['oob']}")
    
    if summary['internal_services_discovered'] > 0:
        logger.critical(f"\n!!! INTERNAL SERVICES DISCOVERED: {summary['internal_services_discovered']} !!!")
        for service in set(result.internal_services):
            logger.critical(f"  - {service}")


def print_integration_1c_results(result: Integration1CResult, logger: ColoredLogger):
    """Print 1C Integration results"""
    logger.info("=" * 60)
    logger.info("1C INTEGRATION SCAN RESULTS")
    logger.info("=" * 60)
    
    summary = result.to_dict()['summary']
    
    if summary['critical'] > 0:
        logger.critical(f"CRITICAL: {summary['critical']}")
    if summary['high'] > 0:
        logger.error(f"HIGH: {summary['high']}")
    
    logger.info(f"\nTotal Findings: {summary['total_findings']}")
    logger.info(f"Exchange Vulnerabilities: {summary['exchange_vulns']}")
    logger.info(f"XML Vulnerabilities: {summary['xml_vulns']}")
    logger.info(f"Data Leaks: {summary['data_leaks']}")
    logger.info(f"API Issues: {summary['api_issues']}")
    
    if summary['exposed_endpoints'] > 0:
        logger.critical(f"\n!!! EXPOSED 1C ENDPOINTS: {summary['exposed_endpoints']} !!!")
        for endpoint in result.exposed_endpoints:
            logger.critical(f"  - {endpoint}")
    
    # Print exposed data details
    data_leaks = [f for f in result.findings if f.vuln_type == 'data_leak' and f.exposed_data]
    if data_leaks:
        logger.warning(f"\nExposed Enterprise Data:")
        for finding in data_leaks:
            data_info = ", ".join([f"{k}: {v}" for k, v in finding.exposed_data.items()])
            logger.warning(f"  {finding.url}: {data_info}")


def print_excel_rce_results(result: ExcelRCEResult, logger: ColoredLogger):
    """Print Excel RCE results"""
    logger.info("=" * 60)
    logger.info("EXCEL RCE SCAN RESULTS")
    logger.info("=" * 60)
    
    summary = result.to_dict()['summary']
    
    if summary['critical'] > 0:
        logger.critical(f"CRITICAL: {summary['critical']}")
        logger.critical("!!! EXCEL RCE VULNERABILITIES FOUND !!!")
    if summary['high'] > 0:
        logger.error(f"HIGH: {summary['high']}")
    
    logger.info(f"\nTotal Findings: {summary['total_findings']}")
    logger.info(f"Formula Injections: {summary['formula_injections']}")
    logger.info(f"DDE Injections: {summary['dde_injections']}")
    logger.info(f"CSV Injections: {summary['csv_injections']}")
    logger.info(f"Power Query Vulns: {summary['power_query_vulns']}")
    logger.info(f"Macro Vulnerabilities: {summary['macro_vulns']}")
    
    if summary['exposed_export_points'] > 0:
        logger.warning(f"\nExposed Export Points: {summary['exposed_export_points']}")
        for point in result.exposed_export_points:
            logger.warning(f"  - {point}")
    
    # Print confirmed executions
    confirmed = [f for f in result.findings if f.execution_confirmed]
    if confirmed:
        logger.critical(f"\n!!! CONFIRMED CODE EXECUTION: {len(confirmed)} !!!")
        for finding in confirmed:
            logger.critical(f"  {finding.vuln_type}: {finding.url}")


def print_api_results(result: APIResult, logger: ColoredLogger):
    """Print API Scanner results"""
    logger.info("=" * 60)
    logger.info("API SCANNER RESULTS")
    logger.info("=" * 60)
    
    summary = result.to_dict()['summary']
    
    if summary['critical'] > 0:
        logger.critical(f"CRITICAL: {summary['critical']}")
        logger.critical("!!! CRITICAL API VULNERABILITIES FOUND !!!")
    if summary['high'] > 0:
        logger.error(f"HIGH: {summary['high']}")
    
    logger.info(f"\nTotal Findings: {summary['total_findings']}")
    logger.info(f"Authentication Issues: {summary['auth_issues']}")
    logger.info(f"IDOR Vulnerabilities: {summary['idor_vulns']}")
    logger.info(f"Injection Vulnerabilities: {summary['injection_vulns']}")
    logger.info(f"Mass Assignment: {summary['mass_assignment_vulns']}")
    logger.info(f"Information Disclosure: {summary['info_disclosure']}")
    logger.info(f"Misconfigurations: {summary['misconfigurations']}")
    
    if summary['discovered_endpoints'] > 0:
        logger.info(f"\nDiscovered API Endpoints: {summary['discovered_endpoints']}")
        if result.api_versions:
            logger.info(f"API Versions: {', '.join(result.api_versions)}")
    
    # Print unauthenticated endpoints
    auth_bypass = [f for f in result.findings if f.vuln_type == 'auth_bypass']
    if auth_bypass:
        logger.critical(f"\n!!! UNPROTECTED API ENDPOINTS: {len(auth_bypass)} !!!")
        for finding in auth_bypass[:5]:  # Show first 5
            logger.critical(f"  {finding.method} {finding.url}")
    
    # Print JWT issues
    jwt_issues = [f for f in result.findings if 'jwt' in f.description.lower() or 'JWT' in str(f.payload)]
    if jwt_issues:
        logger.warning(f"\nJWT Vulnerabilities: {len(jwt_issues)}")
        for finding in jwt_issues:
            logger.warning(f"  {finding.description}")


def save_results(results: dict, output_file: str, logger: ColoredLogger) -> bool:
    """Save results to JSON file"""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        return True
    except Exception as e:
        logger.error(f"Failed to save results: {e}")
        return False


def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup logger
    if args.quiet:
        log_level = logging.ERROR
    elif args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
        
    logger = ColoredLogger(
        name="BitrixPentest",
        level=log_level,
        log_file="bitrix_pentest.log"
    )
    
    print_banner(logger)
    
    # Validate target
    target = args.target
    if not target.startswith(('http://', 'https://')):
        logger.warning(f"No protocol specified, assuming https://")
        target = 'https://' + target
    
    logger.info(f"Target: {target}")
    logger.info(f"Module: {args.module}")
    logger.info(f"Mode: {'Aggressive' if args.aggressive else 'Standard'}")
    
    # Warning for destructive modules
    if args.module in ['rce', 'xxe_ssrf', '1c', 'excel', 'api'] or (args.module == 'all' and args.aggressive):
        logger.warning("=" * 60)
        logger.warning("WARNING: Destructive modules enabled!")
        logger.warning("RCE, XXE/SSRF, 1C Integration, Excel RCE and API tests can be dangerous!")
        logger.warning("Only test systems you have permission to test!")
        logger.warning("=" * 60)
    
    # Initialize components
    try:
        requester = Requester(
            timeout=args.timeout,
            delay=args.delay,
            proxy=args.proxy
        )
        parser = BitrixParser()
        logger.debug(f"Components initialized")
    except Exception as e:
        logger.error(f"Initialization failed: {e}")
        sys.exit(1)
    
    # Storage for results
    all_results = {
        'target': target,
        'scan_time': str(datetime.now()),
        'modules': {}
    }
    
    # Run selected modules
    try:
        # RECON Module
        if args.module in ['all', 'recon']:
            logger.info("\n" + "=" * 60)
            logger.info("STARTING RECONNAISSANCE MODULE")
            logger.info("=" * 60)
            
            recon = BitrixRecon(requester, logger)
            recon_result = recon.scan(target, aggressive=args.aggressive)
            all_results['modules']['reconnaissance'] = recon_result.to_dict()
            print_recon_results(recon_result, logger)
        
        # INFO DISCLOSURE Module
        if args.module in ['all', 'disclosure']:
            logger.info("\n" + "=" * 60)
            logger.info("STARTING INFORMATION DISCLOSURE MODULE")
            logger.info("=" * 60)
            
            disclosure = BitrixInfoDisclosure(requester, logger, parser)
            disc_result = disclosure.scan(target, aggressive=args.aggressive)
            all_results['modules']['information_disclosure'] = disc_result.to_dict()
            print_disclosure_results(disc_result, logger)
        
        # AUTH BYPASS Module
        if args.module in ['all', 'auth']:
            logger.info("\n" + "=" * 60)
            logger.info("STARTING AUTHENTICATION BYPASS MODULE")
            logger.info("=" * 60)
            
            auth = BitrixAuthBypass(requester, logger, parser)
            auth_result = auth.scan(target, aggressive=args.aggressive)
            all_results['modules']['authentication'] = auth_result.to_dict()
            print_auth_results(auth_result, logger)
        
        # SQL INJECTION Module
        if args.module in ['all', 'sqli']:
            logger.info("\n" + "=" * 60)
            logger.info("STARTING SQL INJECTION SCANNER MODULE")
            logger.info("=" * 60)
            
            sqli = BitrixSQLiScanner(requester, logger, parser)
            sqli_result = sqli.scan(target, aggressive=args.aggressive)
            all_results['modules']['sql_injection'] = sqli_result.to_dict()
            print_sqli_results(sqli_result, logger)
        
        # XSS Module
        if args.module in ['all', 'xss']:
            logger.info("\n" + "=" * 60)
            logger.info("STARTING XSS SCANNER MODULE")
            logger.info("=" * 60)
            
            xss = BitrixXSSScanner(requester, logger, parser)
            xss_result = xss.scan(target, aggressive=args.aggressive)
            all_results['modules']['xss'] = xss_result.to_dict()
            print_xss_results(xss_result, logger)
        
        # FILE UPLOAD Module
        if args.module in ['all', 'upload']:
            logger.info("\n" + "=" * 60)
            logger.info("STARTING FILE UPLOAD SCANNER MODULE")
            logger.info("=" * 60)
            
            upload = BitrixFileUploadScanner(requester, logger, parser)
            upload_result = upload.scan(target, aggressive=args.aggressive)
            all_results['modules']['file_upload'] = upload_result.to_dict()
            print_upload_results(upload_result, logger)
        
        # RCE Module
        if args.module in ['all', 'rce']:
            logger.info("\n" + "=" * 60)
            logger.info("STARTING RCE TESTER MODULE")
            logger.info("=" * 60)
            
            rce = BitrixRCETester(requester, logger, parser)
            rce_result = rce.scan(target, aggressive=args.aggressive)
            all_results['modules']['rce'] = rce_result.to_dict()
            print_rce_results(rce_result, logger)
        
        # XXE/SSRF Module
        if args.module in ['all', 'xxe_ssrf']:
            logger.info("\n" + "=" * 60)
            logger.info("STARTING XXE/SSRF SCANNER MODULE")
            logger.info("=" * 60)
            
            xxe_ssrf = BitrixXXESSRFScanner(requester, logger, parser)
            
            # Configure OOB server if provided
            if args.oob_server:
                xxe_ssrf.oob_server = args.oob_server
                logger.info(f"OOB Server configured: {args.oob_server}")
            
            xxe_ssrf_result = xxe_ssrf.scan(target, aggressive=args.aggressive)
            all_results['modules']['xxe_ssrf'] = xxe_ssrf_result.to_dict()
            print_xxe_ssrf_results(xxe_ssrf_result, logger)
        
        # 1C Integration Module
        if args.module in ['all', '1c']:
            logger.info("\n" + "=" * 60)
            logger.info("STARTING 1C INTEGRATION SCANNER MODULE")
            logger.info("=" * 60)
            
            integration_1c = Bitrix1CIntegrationScanner(requester, logger, parser)
            integration_1c_result = integration_1c.scan(target, aggressive=args.aggressive)
            all_results['modules']['integration_1c'] = integration_1c_result.to_dict()
            print_integration_1c_results(integration_1c_result, logger)
        
        # Excel RCE Module
        if args.module in ['all', 'excel']:
            logger.info("\n" + "=" * 60)
            logger.info("STARTING EXCEL RCE SCANNER MODULE")
            logger.info("=" * 60)
            
            excel_rce = BitrixExcelRCEScanner(requester, logger, parser)
            
            # Configure callback server if provided
            if args.callback_server:
                excel_rce.callback_server = args.callback_server
                logger.info(f"Callback Server configured: {args.callback_server}")
            
            excel_rce_result = excel_rce.scan(target, aggressive=args.aggressive)
            all_results['modules']['excel_rce'] = excel_rce_result.to_dict()
            print_excel_rce_results(excel_rce_result, logger)
        
        # API Scanner Module
        if args.module in ['all', 'api']:
            logger.info("\n" + "=" * 60)
            logger.info("STARTING API SCANNER MODULE")
            logger.info("=" * 60)
            
            api_scanner = BitrixAPIScanner(requester, logger, parser)
            api_result = api_scanner.scan(target, aggressive=args.aggressive)
            all_results['modules']['api_scanner'] = api_result.to_dict()
            print_api_results(api_result, logger)
        
        # Final summary
        logger.info("\n" + "=" * 60)
        logger.info("SCAN COMPLETED")
        logger.info("=" * 60)
        
        # Calculate totals
        total_findings = 0
        critical_count = 0
        
        for module_name, module_data in all_results['modules'].items():
            if 'summary' in module_data:
                total_findings += module_data['summary'].get('total_findings', 0)
                critical_count += module_data['summary'].get('critical', 0)
        
        if critical_count > 0:
            logger.critical(f"Found {critical_count} CRITICAL issues!")
            logger.critical("Immediate action required!")
        elif total_findings > 0:
            logger.warning(f"Found {total_findings} potential issues")
        else:
            logger.success("No obvious security issues found")
        
        # Save results
        if args.output:
            if save_results(all_results, args.output, logger):
                logger.success(f"\nFull results saved to: {args.output}")
        
        sys.exit(0 if critical_count == 0 else 1)
        
    except KeyboardInterrupt:
        logger.warning("\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        if args.verbose:
            import traceback
            logger.debug(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
