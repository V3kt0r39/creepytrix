#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Information Disclosure Module for Bitrix Pentest Tool
Searches for exposed configs, backups, logs, version control files
"""

import re
import base64
import hashlib
from urllib.parse import urljoin, urlparse, quote
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class DisclosureFinding:
    """Single information disclosure finding"""
    severity: str  # critical, high, medium, low, info
    category: str  # config, backup, log, vcs, source, other
    url: str
    description: str
    evidence: Optional[str] = None  # Snippet of exposed data
    remediation: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        # Truncate long evidence
        if self.evidence and len(self.evidence) > 500:
            result['evidence'] = self.evidence[:500] + "... [truncated]"
        return result


@dataclass
class DisclosureResult:
    """Results of information disclosure scan"""
    target: str
    findings: List[DisclosureFinding] = field(default_factory=list)
    configs_found: List[Dict] = field(default_factory=list)
    backups_found: List[Dict] = field(default_factory=list)
    logs_found: List[Dict] = field(default_factory=list)
    vcs_exposed: List[Dict] = field(default_factory=list)
    source_exposed: List[Dict] = field(default_factory=list)
    
    def add_finding(self, finding: DisclosureFinding):
        self.findings.append(finding)
        
        # Categorize
        finding_dict = finding.to_dict()
        if finding.category == 'config':
            self.configs_found.append(finding_dict)
        elif finding.category == 'backup':
            self.backups_found.append(finding_dict)
        elif finding.category == 'log':
            self.logs_found.append(finding_dict)
        elif finding.category == 'vcs':
            self.vcs_exposed.append(finding_dict)
        elif finding.category == 'source':
            self.source_exposed.append(finding_dict)
    
    def get_critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'critical')
    
    def get_high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'high')
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'target': self.target,
            'summary': {
                'total_findings': len(self.findings),
                'critical': self.get_critical_count(),
                'high': self.get_high_count(),
                'medium': sum(1 for f in self.findings if f.severity == 'medium'),
                'low': sum(1 for f in self.findings if f.severity == 'low'),
                'info': sum(1 for f in self.findings if f.severity == 'info'),
            },
            'configs_found': self.configs_found,
            'backups_found': self.backups_found,
            'logs_found': self.logs_found,
            'vcs_exposed': self.vcs_exposed,
            'source_exposed': self.source_exposed,
            'all_findings': [f.to_dict() for f in self.findings]
        }


class BitrixInfoDisclosure:
    """
    Information Disclosure scanner for Bitrix CMS
    """
    
    # Critical configuration files
    CONFIG_FILES = [
        # Main config files
        ('/bitrix/.settings.php', 'critical', 'Bitrix D7 config with DB credentials'),
        ('/bitrix/php_interface/dbconn.php', 'critical', 'Legacy DB connection config'),
        ('/bitrix/php_interface/after_connect.php', 'high', 'Post-connection DB script'),
        ('/bitrix/php_interface/after_connect_d7.php', 'high', 'D7 Post-connection DB script'),
        ('/.env', 'critical', 'Environment variables file'),
        ('/.env.local', 'critical', 'Local environment file'),
        ('/.env.production', 'critical', 'Production environment'),
        ('/.env.backup', 'high', 'Backup of env file'),
        
        # Apache/Nginx configs
        ('/.htaccess', 'medium', 'Apache configuration'),
        ('/.htpasswd', 'critical', 'Apache password file'),
        ('/bitrix/.htaccess', 'low', 'Bitrix folder Apache config'),
        ('/nginx.conf', 'medium', 'Nginx configuration'),
        ('/bitrix/nginx.conf', 'low', 'Bitrix Nginx config'),
        
        # PHP settings
        ('/php.ini', 'medium', 'PHP configuration'),
        ('/.user.ini', 'medium', 'User PHP configuration'),
        ('/bitrix/php.ini', 'low', 'Bitrix PHP config'),
        
        # Other configs
        ('/bitrix/modules/main/classes/general/version.php', 'info', 'Version info'),
        ('/bitrix/modules/main/lib/version.php', 'info', 'D7 Version info'),
        ('/composer.json', 'low', 'Composer dependencies'),
        ('/composer.lock', 'low', 'Composer lock file'),
        ('/package.json', 'low', 'Node.js dependencies'),
        ('/bitrix/composer.json', 'low', 'Bitrix composer file'),
    ]
    
    # Backup files patterns
    BACKUP_PATTERNS = [
        # Database backups
        ('/bitrix/backup/', 'critical', 'Bitrix backup directory'),
        ('/upload/backup/', 'critical', 'Upload backup directory'),
        ('/backup/', 'critical', 'Root backup directory'),
        ('/backups/', 'critical', 'Alternative backup directory'),
        ('/bitrix/backup/site_', 'critical', 'Site backup archive'),
        ('/bitrix/backup/mysql_', 'critical', 'Database backup'),
        
        # File backups
        ('/bitrix/.settings.php.bak', 'critical', 'Config backup'),
        ('/bitrix/.settings.php~', 'critical', 'Config backup (vim)'),
        ('/bitrix/.settings.php.old', 'critical', 'Old config'),
        ('/bitrix/.settings.php.save', 'critical', 'Config save'),
        ('/bitrix/.settings.php.swp', 'high', 'Vim swap file'),
        ('/bitrix/.settings.php.swo', 'high', 'Vim swap file'),
        ('/bitrix/php_interface/dbconn.php.bak', 'critical', 'DB config backup'),
        ('/bitrix/php_interface/dbconn.php~', 'critical', 'DB config backup (vim)'),
        ('/bitrix/php_interface/dbconn.php.old', 'critical', 'Old DB config'),
        
        # Archive files
        ('/backup.tar.gz', 'critical', 'Archive backup'),
        ('/backup.zip', 'critical', 'ZIP backup'),
        ('/backup.sql', 'critical', 'SQL backup'),
        ('/backup.sql.gz', 'critical', 'Compressed SQL backup'),
        ('/dump.sql', 'critical', 'Database dump'),
        ('/dump.sql.gz', 'critical', 'Compressed dump'),
        ('/bitrix.tar.gz', 'high', 'Bitrix folder archive'),
        ('/upload.tar.gz', 'high', 'Upload folder archive'),
        ('/www.tar.gz', 'high', 'WWW archive'),
        ('/html.tar.gz', 'high', 'HTML archive'),
        ('/public_html.tar.gz', 'critical', 'Public HTML archive'),
        ('/site.tar.gz', 'high', 'Site archive'),
        
        # Log backups
        ('/bitrix/modules/sale/export/', 'high', 'Sale module exports'),
        ('/bitrix/modules/catalog/export/', 'high', 'Catalog exports'),
    ]
    
    # Log files
    LOG_FILES = [
        ('/bitrix/modules/main/admin/restore.php.log', 'medium', 'Restore log'),
        ('/bitrix/modules/sale/export/log.txt', 'medium', 'Sale export log'),
        ('/bitrix/ajax.log', 'medium', 'AJAX error log'),
        ('/bitrix/error.log', 'medium', 'Bitrix error log'),
        ('/bitrix/modules/error.log', 'medium', 'Modules error log'),
        ('/bitrix/php_interface/error.log', 'medium', 'PHP interface errors'),
        ('/bitrix/site.log', 'medium', 'Site log'),
        ('/bitrix/.log', 'medium', 'Generic log'),
        ('/error.log', 'low', 'Server error log'),
        ('/access.log', 'low', 'Server access log'),
        ('/bitrix/modules/main/log/', 'high', 'Main module logs'),
        ('/bitrix/logs/', 'high', 'Bitrix logs directory'),
        ('/logs/', 'medium', 'Logs directory'),
        ('/var/log/', 'medium', 'Var logs'),
        ('/bitrix/modules/sale/orders.log', 'critical', 'Orders log with PII'),
    ]
    
    # Version Control Systems
    VCS_PATHS = [
        ('/.git/', 'critical', 'Git repository exposed'),
        ('/.git/config', 'critical', 'Git config with remote URLs'),
        ('/.git/HEAD', 'high', 'Git HEAD reference'),
        ('/.git/index', 'high', 'Git index'),
        ('/.git/logs/HEAD', 'medium', 'Git logs'),
        ('/.svn/', 'critical', 'SVN repository exposed'),
        ('/.svn/entries', 'critical', 'SVN entries'),
        ('/.svn/wc.db', 'critical', 'SVN database'),
        ('/.hg/', 'critical', 'Mercurial repository'),
        ('/.bzr/', 'critical', 'Bazaar repository'),
        ('/.DS_Store', 'low', 'macOS metadata'),
        ('/Thumbs.db', 'low', 'Windows thumbnails'),
    ]
    
    # Source code exposure
    SOURCE_FILES = [
        # Uncompiled source
        ('/bitrix/modules/', 'info', 'Modules directory listing'),
        ('/bitrix/components/', 'info', 'Components directory'),
        ('/bitrix/templates/', 'info', 'Templates directory'),
        ('/local/templates/', 'info', 'Local templates'),
        ('/local/components/', 'info', 'Local components'),
        ('/local/php_interface/', 'high', 'Local PHP interface'),
        
        # Source with sensitive data
        ('/bitrix/modules/main/admin/site_checker.php', 'medium', 'Admin tools source'),
        ('/bitrix/modules/main/admin/sql.php', 'critical', 'SQL admin tool'),
        ('/bitrix/modules/main/admin/dump.php', 'critical', 'Database dump tool'),
        ('/bitrix/admin/restore.php', 'critical', 'Restore tool'),
        
        # IDE files
        ('/.idea/', 'medium', 'PHPStorm project files'),
        ('/.vscode/', 'medium', 'VSCode settings'),
        ('/nbproject/', 'medium', 'NetBeans project'),
        ('/.project', 'low', 'Eclipse project'),
        ('/.classpath', 'low', 'Java classpath'),
        
        # Temp files
        ('/tmp/', 'medium', 'Temporary files'),
        ('/temp/', 'medium', 'Temp directory'),
        ('/bitrix/tmp/', 'medium', 'Bitrix temp'),
        ('/bitrix/cache/', 'low', 'Cache directory'),
        ('/bitrix/managed_cache/', 'low', 'Managed cache'),
        ('/bitrix/stack_cache/', 'low', 'Stack cache'),
    ]
    
    # PHP info and debug
    DEBUG_ENDPOINTS = [
        ('/bitrix/admin/phpinfo.php', 'critical', 'PHP Info'),
        ('/phpinfo.php', 'critical', 'PHP Info'),
        ('/info.php', 'critical', 'PHP Info'),
        ('/test.php', 'high', 'Test script'),
        ('/debug.php', 'high', 'Debug script'),
        ('/_profiler/', 'high', 'Symfony profiler'),
        ('/app_dev.php', 'high', 'Symfony dev mode'),
    ]
    
    # 1C Exchange endpoints (often misconfigured)
    EXCHANGE_ENDPOINTS = [
        ('/bitrix/admin/1c_exchange.php', 'critical', '1C Exchange (check auth)'),
        ('/bitrix/admin/exchange_integration.php', 'high', 'Exchange integration'),
        ('/bitrix/admin/1c_intranet.php', 'high', '1C Intranet'),
        ('/exchange/', 'high', 'Exchange folder'),
        ('/1c/', 'high', '1C folder'),
    ]
    
    def __init__(self, requester, logger, parser):
        """
        Args:
            requester: HTTP request handler
            logger: Logging instance
            parser: Content parser instance
        """
        self.requester = requester
        self.logger = logger
        self.parser = parser
        self.findings = []
        
    def scan(self, target_url: str, aggressive: bool = False) -> DisclosureResult:
        """
        Main scanning method
        
        Args:
            target_url: Base URL to scan
            aggressive: Enable aggressive checks (more requests)
        
        Returns:
            DisclosureResult with all findings
        """
        self.logger.info(f"Starting Information Disclosure scan for {target_url}")
        result = DisclosureResult(target=target_url)
        
        # Normalize URL
        base_url = self._normalize_url(target_url)
        
        # 1. Check configuration files
        self.logger.info("Checking for exposed configuration files...")
        self._check_configs(base_url, result)
        
        # 2. Check backup files
        self.logger.info("Checking for backup files...")
        self._check_backups(base_url, result)
        
        # 3. Check logs
        self.logger.info("Checking for exposed logs...")
        self._check_logs(base_url, result)
        
        # 4. Check VCS
        self.logger.info("Checking for version control exposure...")
        self._check_vcs(base_url, result)
        
        # 5. Check source exposure
        self.logger.info("Checking for source code exposure...")
        self._check_source_exposure(base_url, result)
        
        # 6. Check debug endpoints
        self.logger.info("Checking for debug endpoints...")
        self._check_debug_endpoints(base_url, result)
        
        # 7. Check 1C exchange (Bitrix specific)
        self.logger.info("Checking for 1C Exchange endpoints...")
        self._check_1c_exchange(base_url, result)
        
        # 8. Aggressive checks
        if aggressive:
            self.logger.info("Running aggressive checks...")
            self._aggressive_checks(base_url, result)
        
        # Summary
        total = len(result.findings)
        critical = result.get_critical_count()
        high = result.get_high_count()
        
        self.logger.info(f"Scan complete: {total} findings ({critical} critical, {high} high)")
        
        return result
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _check_configs(self, base_url: str, result: DisclosureResult):
        """Check for exposed configuration files"""
        for path, severity, description in self.CONFIG_FILES:
            url = urljoin(base_url, path)
            resp = self.requester.get(url, allow_redirects=False)
            
            if not resp:
                continue
            
            if resp.status_code == 200:
                content = resp.text
                
                # Check if it's really a config, not 404 page
                if self._is_valid_config(content, path):
                    evidence = self._extract_config_snippet(content, path)
                    
                    finding = DisclosureFinding(
                        severity=severity,
                        category='config',
                        url=url,
                        description=description,
                        evidence=evidence,
                        remediation=f"Remove or restrict access to {path}"
                    )
                    result.add_finding(finding)
                    self.logger.critical(f"CONFIG EXPOSED: {path}") if severity == 'critical' else self.logger.warning(f"Config exposed: {path}")
                    
                    # Special handling for .settings.php to extract DB info
                    if 'settings.php' in path:
                        db_info = self.parser.parse_bitrix_config(content)
                        if db_info:
                            self.logger.critical(f"Database credentials found in {path}!")
    
    def _check_backups(self, base_url: str, result: DisclosureResult):
        """Check for backup files"""
        for path, severity, description in self.BACKUP_PATTERNS:
            url = urljoin(base_url, path)
            
            # For directories, check with and without trailing slash
            urls_to_check = [url]
            if path.endswith('/'):
                urls_to_check.append(url.rstrip('/'))
            
            for check_url in urls_to_check:
                resp = self.requester.get(check_url, allow_redirects=False)
                
                if not resp:
                    continue
                
                if resp.status_code in [200, 301, 302, 307]:
                    # Check if it's directory listing
                    if self._is_directory_listing(resp.text):
                        finding = DisclosureFinding(
                            severity=severity,
                            category='backup',
                            url=check_url,
                            description=f"{description} (Directory listing enabled)",
                            evidence="Directory listing found",
                            remediation=f"Disable directory listing and remove {path}"
                        )
                        result.add_finding(finding)
                        self.logger.critical(f"BACKUP DIR EXPOSED: {path}")
                    
                    # Check if it's actual file
                    elif resp.status_code == 200 and len(resp.content) > 100:
                        content_type = resp.headers.get('Content-Type', '')
                        if any(ct in content_type for ct in ['sql', 'gz', 'zip', 'tar']):
                            finding = DisclosureFinding(
                                severity=severity,
                                category='backup',
                                url=check_url,
                                description=f"{description} (Size: {len(resp.content)} bytes)",
                                evidence=f"Content-Type: {content_type}",
                                remediation=f"Remove backup file: {path}"
                            )
                            result.add_finding(finding)
                            self.logger.critical(f"BACKUP FILE FOUND: {path} ({len(resp.content)} bytes)")
    
    def _check_logs(self, base_url: str, result: DisclosureResult):
        """Check for exposed log files"""
        for path, severity, description in self.LOG_FILES:
            url = urljoin(base_url, path)
            resp = self.requester.get(url, allow_redirects=False)
            
            if not resp or resp.status_code != 200:
                continue
            
            content = resp.text
            
            # Check if it's really a log
            if self._is_log_file(content):
                # Extract interesting entries
                evidence = self._extract_log_entries(content)
                
                finding = DisclosureFinding(
                    severity=severity,
                    category='log',
                    url=url,
                    description=description,
                    evidence=evidence,
                    remediation=f"Restrict access to log files: {path}"
                )
                result.add_finding(finding)
                self.logger.warning(f"Log file exposed: {path}")
                
                # Check for SQL errors (might contain injection hints)
                if 'SQL' in content or 'MySQL' in content or 'ORA-' in content:
                    sql_errors = self.parser.extract_sql_errors(content)
                    if sql_errors:
                        self.logger.critical(f"SQL errors found in log: {path}")
    
    def _check_vcs(self, base_url: str, result: DisclosureResult):
        """Check for version control exposure"""
        for path, severity, description in self.VCS_PATHS:
            url = urljoin(base_url, path)
            resp = self.requester.get(url, allow_redirects=False)
            
            if not resp:
                continue
            
            if resp.status_code == 200:
                content = resp.text
                
                # Validate it's really VCS
                is_valid = False
                if '.git/' in path and ('[core]' in content or 'repositoryformatversion' in content):
                    is_valid = True
                elif '.svn/' in path and ('sqlite' in resp.headers.get('Content-Type', '') or '<?xml' in content):
                    is_valid = True
                elif '.hg/' in path and path.endswith('/') and ('store' in content or '00changelog.i' in content):
                    is_valid = True
                
                if is_valid or len(content) > 50:
                    finding = DisclosureFinding(
                        severity=severity,
                        category='vcs',
                        url=url,
                        description=description,
                        evidence=content[:200] if '.git/config' in path else "VCS directory accessible",
                        remediation=f"Remove .htaccess restriction or delete {path}"
                    )
                    result.add_finding(finding)
                    self.logger.critical(f"VCS EXPOSED: {path}")
                    
                    # Special handling for .git/config
                    if path == '/.git/config':
                        remotes = self.parser.parse_git_config(content)
                        if remotes:
                            self.logger.critical(f"Git remotes found: {remotes}")
    
    def _check_source_exposure(self, base_url: str, result: DisclosureResult):
        """Check for source code exposure"""
        for path, severity, description in self.SOURCE_FILES:
            url = urljoin(base_url, path)
            resp = self.requester.get(url, allow_redirects=False)
            
            if not resp:
                continue
            
            if resp.status_code == 200:
                content = resp.text
                
                # Check for directory listing
                if self._is_directory_listing(content):
                    finding = DisclosureFinding(
                        severity=severity,
                        category='source',
                        url=url,
                        description=f"{description} (Directory listing)",
                        evidence="Directory listing enabled",
                        remediation=f"Disable directory listing for {path}"
                    )
                    result.add_finding(finding)
                    self.logger.warning(f"Source directory listing: {path}")
                
                # Check for PHP source exposure
                elif '<?php' in content and not content.strip().startswith('<!'):
                    # Might be unexecuted PHP
                    finding = DisclosureFinding(
                        severity='high',
                        category='source',
                        url=url,
                        description="PHP source code exposed (not executed)",
                        evidence=content[:300],
                        remediation="Check web server configuration"
                    )
                    result.add_finding(finding)
                    self.logger.critical(f"PHP SOURCE EXPOSED: {path}")
    
    def _check_debug_endpoints(self, base_url: str, result: DisclosureResult):
        """Check for debug/info endpoints"""
        for path, severity, description in self.DEBUG_ENDPOINTS:
            url = urljoin(base_url, path)
            resp = self.requester.get(url, allow_redirects=False)
            
            if not resp or resp.status_code != 200:
                continue
            
            content = resp.text
            
            # Validate it's really phpinfo
            if 'phpinfo()' in content or '<title>phpinfo()</title>' in content:
                # Extract key info
                modules = self.parser.parse_phpinfo(content)
                
                finding = DisclosureFinding(
                    severity=severity,
                    category='config',
                    url=url,
                    description=f"{description} - Modules: {', '.join(modules[:5])}...",
                    evidence="phpinfo() exposed",
                    remediation="Remove phpinfo files from production"
                )
                result.add_finding(finding)
                self.logger.critical(f"PHPINFO EXPOSED: {path}")
    
    def _check_1c_exchange(self, base_url: str, result: DisclosureResult):
        """Check 1C Exchange endpoints (common misconfiguration)"""
        for path, severity, description in self.EXCHANGE_ENDPOINTS:
            url = urljoin(base_url, path)
            resp = self.requester.get(url, allow_redirects=False)
            
            if not resp:
                continue
            
            if resp.status_code == 200:
                content = resp.text
                
                # Check if it's actual exchange endpoint without auth
                if '1C' in content or 'exchange' in content.lower() or 'CommerceML' in content:
                    finding = DisclosureFinding(
                        severity=severity,
                        category='config',
                        url=url,
                        description=f"{description} - Authentication may be bypassed",
                        evidence=content[:200],
                        remediation="Enable authentication for 1C exchange endpoints"
                    )
                    result.add_finding(finding)
                    self.logger.critical(f"1C EXCHANGE EXPOSED: {path}")
            
            elif resp.status_code == 401:
                self.logger.info(f"1C Exchange protected (401): {path}")
    
    def _aggressive_checks(self, base_url: str, result: DisclosureResult):
        """Aggressive checks - more requests, wordlists"""
        # Common backup naming patterns
        import datetime
        now = datetime.datetime.now()
        
        date_patterns = [
            now.strftime('%Y%m%d'),
            now.strftime('%Y-%m-%d'),
            now.strftime('%d%m%Y'),
            (now - datetime.timedelta(days=1)).strftime('%Y%m%d'),
            (now - datetime.timedelta(days=7)).strftime('%Y%m%d'),
        ]
        
        # Check dated backups
        for date_str in date_patterns:
            backup_urls = [
                f'/backup_{date_str}.sql',
                f'/backup_{date_str}.sql.gz',
                f'/backup_{date_str}.tar.gz',
                f'/bitrix/backup/site_{date_str}.tar.gz',
                f'/bitrix/backup/mysql_{date_str}.sql',
            ]
            
            for path in backup_urls:
                url = urljoin(base_url, path)
                resp = self.requester.head(url)
                
                if resp and resp.status_code == 200:
                    finding = DisclosureFinding(
                        severity='critical',
                        category='backup',
                        url=url,
                        description=f'Dated backup file found: {path}',
                        evidence=f'Date pattern: {date_str}',
                        remediation='Remove dated backup files'
                    )
                    result.add_finding(finding)
                    self.logger.critical(f"DATED BACKUP FOUND: {path}")
        
        # Check common subdomain/config variations
        parsed = urlparse(base_url)
        domain = parsed.netloc
        
        variations = [
            f'/bitrix/.settings.{domain}.php',
            f'/bitrix/.settings.local.php',
            f'/bitrix/php_interface/dbconn.{domain}.php',
        ]
        
        for path in variations:
            url = urljoin(base_url, path)
            resp = self.requester.get(url)
            
            if resp and resp.status_code == 200 and '<?php' in resp.text:
                finding = DisclosureFinding(
                    severity='critical',
                    category='config',
                    url=url,
                    description=f'Alternative config file: {path}',
                    evidence=self._extract_config_snippet(resp.text, path),
                    remediation=f'Remove alternative config: {path}'
                )
                result.add_finding(finding)
                self.logger.critical(f"ALT CONFIG FOUND: {path}")
    
    def _is_valid_config(self, content: str, path: str) -> bool:
        """Check if response is valid config file, not 404 page"""
        if len(content) < 50:
            return False
        
        # Check for common config patterns
        config_patterns = [
            '<?php',
            'return array',
            'connections',
            'database',
            'host',
            'password',
            'DBLogin',
            'DBPassword',
        ]
        
        content_lower = content.lower()
        matches = sum(1 for pattern in config_patterns if pattern.lower() in content_lower)
        
        return matches >= 2
    
    def _extract_config_snippet(self, content: str, path: str) -> str:
        """Extract non-sensitive snippet from config"""
        lines = content.split('\n')
        snippets = []
        
        for i, line in enumerate(lines[:30]):  # First 30 lines
            # Skip lines with actual passwords
            if any(keyword in line.lower() for keyword in ['password', 'pass', 'pwd', 'secret']):
                if '=>' in line or '=' in line:
                    # Replace value with ***
                    line = re.sub(r'(["\'])(.*?)\1', r'\1***\1', line)
                    snippets.append(line)
                else:
                    snippets.append(line)
            else:
                snippets.append(line)
        
        return '\n'.join(snippets)
    
    def _is_directory_listing(self, content: str) -> bool:
        """Check if content is Apache/Nginx directory listing"""
        indicators = [
            '<title>Index of',
            'Directory Listing',
            '<h1>Index of',
            'Parent Directory',
            'Last modified</a>',
            'Size</a>',
            'Description</a>',
        ]
        return any(ind in content for ind in indicators)
    
    def _is_log_file(self, content: str) -> bool:
        """Check if content looks like a log file"""
        log_patterns = [
            r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}',  # Timestamp
            r'\[\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\]',  # Apache log
            'ERROR',
            'WARNING',
            'NOTICE',
            'DEBUG',
        ]
        
        return any(re.search(pattern, content) for pattern in log_patterns)
    
    def _extract_log_entries(self, content: str, max_entries: int = 5) -> str:
        """Extract first N interesting log entries"""
        lines = content.split('\n')
        entries = []
        
        for line in lines:
            if any(level in line for level in ['ERROR', 'CRITICAL', 'WARNING', 'EXCEPTION']):
                entries.append(line)
                if len(entries) >= max_entries:
                    break
        
        if not entries:
            entries = lines[:max_entries]
        
        return '\n'.join(entries)


# Testing
if __name__ == "__main__":
    import sys
    sys.path.append('..')
    
    from utils.requester import Requester
    from utils.logger import ColoredLogger
    from utils.parser import BitrixParser
    
    # Test
    logger = ColoredLogger(level=logging.DEBUG)
    requester = Requester()
    parser = BitrixParser()
    
    scanner = BitrixInfoDisclosure(requester, logger, parser)
    
    if len(sys.argv) > 1:
        result = scanner.scan(sys.argv[1], aggressive=True)
        print(f"\n{'='*60}")
        print(f"CRITICAL: {result.get_critical_count()}")
        print(f"HIGH: {result.get_high_count()}")
        print(f"Findings: {len(result.findings)}")