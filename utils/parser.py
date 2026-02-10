#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Parser utilities for Bitrix-specific content
Extracts credentials, errors, config data from responses
"""

import re
import json
import base64
from typing import Dict, List, Optional, Any, Tuple
from html.parser import HTMLParser
from urllib.parse import urlparse, parse_qs


class BitrixParser:
    """
    Specialized parser for Bitrix CMS content
    """
    
    def __init__(self):
        # Regex patterns for common Bitrix data
        self.patterns = {
            'db_credentials': re.compile(
                r'(["\'])(DBHost|DBLogin|DBPassword|DBName|database|host|username|password)\1\s*=>\s*\1(.*?)\1',
                re.IGNORECASE
            ),
            'bitrix_version': re.compile(
                r'(SM_VERSION|bitrix_version|VERSION)\s*[=:]\s*["\']?(\d+\.\d+\.?\d*)["\']?'
            ),
            'email': re.compile(
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ),
            'phone': re.compile(
                r'(\+7|8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}'
            ),
            'ip_address': re.compile(
                r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ),
            'sql_error': re.compile(
                r'(SQL\s*ERROR|MySQL\s*ERROR|ORA-\d+|PostgreSQL|PDOException|sqlsrv)',
                re.IGNORECASE
            ),
            'stack_trace': re.compile(
                r'(Stack\s*trace|Traceback|#\d+\s+\w+)'
            ),
            'api_key': re.compile(
                r'(api[_-]?key|apikey|auth[_-]?token)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
                re.IGNORECASE
            ),
            'secret_key': re.compile(
                r'(secret|private[_-]?key)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
                re.IGNORECASE
            ),
            'session_id': re.compile(
                r'(PHPSESSID|BITRIX_SM_GUEST_ID|BITRIX_SM_LAST_VISIT|session_id)\s*[=:]\s*["\']?([a-zA-Z0-9\-]{10,})["\']?',
                re.IGNORECASE
            ),
        }
    
    def parse_bitrix_config(self, content: str) -> Optional[Dict[str, str]]:
        """
        Parse Bitrix configuration file (.settings.php or dbconn.php)
        
        Returns:
            Dictionary with connection parameters or None
        """
        result = {}
        
        # Parse D7 style .settings.php
        if 'connections' in content and 'value' in content:
            # Extract connection block
            conn_match = re.search(
                r"'connections'.*?=>.*?array\s*\((.*?)\)\s*,\s*'",
                content,
                re.DOTALL
            )
            if conn_match:
                conn_block = conn_match.group(1)
                
                # Extract database credentials
                db_patterns = {
                    'host': r"'host'\s*=>\s*'([^']+)'",
                    'database': r"'database'\s*=>\s*'([^']+)'",
                    'login': r"'login'\s*=>\s*'([^']+)'",
                    'password': r"'password'\s*=>\s*'([^']+)'",
                }
                
                for key, pattern in db_patterns.items():
                    match = re.search(pattern, conn_block)
                    if match:
                        result[key] = match.group(1)
        
        # Parse legacy dbconn.php
        else:
            legacy_patterns = {
                'host': r"\$DBHost\s*=\s*['\"]([^'\"]+)['\"]",
                'login': r"\$DBLogin\s*=\s*['\"]([^'\"]+)['\"]",
                'password': r"\$DBPassword\s*=\s*['\"]([^'\"]+)['\"]",
                'database': r"\$DBName\s*=\s*['\"]([^'\"]+)['\"]",
            }
            
            for key, pattern in legacy_patterns.items():
                match = re.search(pattern, content)
                if match:
                    result[key] = match.group(1)
        
        return result if result else None
    
    def parse_git_config(self, content: str) -> List[str]:
        """Parse .git/config file and extract remote URLs"""
        remotes = []
        
        # Match [remote "origin"] or similar
        remote_sections = re.findall(
            r'\[remote\s+["\'](\w+)["\']\]\s*(.*?)(?=\[|\Z)',
            content,
            re.DOTALL
        )
        
        for remote_name, remote_content in remote_sections:
            url_match = re.search(r'url\s*=\s*(\S+)', remote_content)
            if url_match:
                remotes.append(f"{remote_name}: {url_match.group(1)}")
        
        return remotes
    
    def parse_phpinfo(self, content: str) -> List[str]:
        """
        Parse phpinfo() output and extract key modules/info
        
        Returns:
            List of interesting modules/settings
        """
        modules = []
        
        # Check for dangerous settings
        dangerous = [
            'allow_url_fopen', 'allow_url_include', 'display_errors',
            'expose_php', 'file_uploads', 'magic_quotes_gpc',
        ]
        
        for setting in dangerous:
            pattern = rf'<td class="e">{setting}</td><td class="v">(On|1|Enabled)</td>'
            if re.search(pattern, content, re.IGNORECASE):
                modules.append(f"{setting}=ON")
        
        # Check for loaded modules
        module_indicators = [
            'mysqli', 'pdo_mysql', 'pgsql', 'oci8', 'sqlsrv',  # DB
            'curl', 'openssl', 'zlib', 'gd', 'mbstring',       # Common
            'xdebug', 'apc', 'memcached', 'redis', 'opcache',  # Cache/Debug
            'suhosin', 'mod_security',                         # Security
        ]
        
        for module in module_indicators:
            if module in content.lower():
                modules.append(module)
        
        return modules
    
    def parse_version_from_js(self, content: str) -> Optional[str]:
        """Extract Bitrix version from JS files"""
        # Pattern: bitrix_version:"20.0.0"
        match = re.search(r'bitrix_version["\']?\s*:\s*["\']?(\d+\.\d+\.\d+)', content)
        if match:
            return match.group(1)
        
        # Pattern: BX.message({... SM_VERSION: "20.0.0" ...})
        match = re.search(r'SM_VERSION["\']?\s*:\s*["\']?(\d+\.\d+\.\d+)', content)
        if match:
            return match.group(1)
        
        return None
    
    def extract_sql_errors(self, content: str) -> List[Dict[str, str]]:
        """Extract SQL error messages from content"""
        errors = []
        
        # MySQL errors
        mysql_pattern = r'(MySQL error.*?)(?:<br|\n|<|$)'
        for match in re.finditer(mysql_pattern, content, re.IGNORECASE | re.DOTALL):
            errors.append({
                'type': 'MySQL',
                'message': match.group(1).strip()[:200]
            })
        
        # General SQL errors
        sql_pattern = r'(SQLSTATE\[\w+\].*?)(?:<br|\n|<|$)'
        for match in re.finditer(sql_pattern, content, re.IGNORECASE | re.DOTALL):
            errors.append({
                'type': 'SQLSTATE',
                'message': match.group(1).strip()[:200]
            })
        
        # Oracle errors
        ora_pattern = r'(ORA-\d+.*?)'
        for match in re.finditer(ora_pattern, content):
            errors.append({
                'type': 'Oracle',
                'message': match.group(0).strip()[:200]
            })
        
        return errors
    
    def extract_stack_trace(self, content: str) -> List[str]:
        """Extract stack traces from error pages"""
        traces = []
        
        # PHP stack trace
        trace_pattern = r'(Stack trace:.*?(?=\n\n|\Z))'
        match = re.search(trace_pattern, content, re.DOTALL)
        if match:
            trace_lines = match.group(1).split('\n')[:10]  # First 10 lines
            traces.append('\n'.join(trace_lines))
        
        # Bitrix specific trace
        bx_trace = re.search(
            r'(Bitrix\s+Main\s+Diag.*?Exception.*?(?=\n\n|\Z))',
            content,
            re.DOTALL | re.IGNORECASE
        )
        if bx_trace:
            traces.append(bx_trace.group(1)[:500])
        
        return traces
    
    def extract_emails(self, content: str) -> List[str]:
        """Extract email addresses from content"""
        return list(set(self.patterns['email'].findall(content)))
    
    def extract_phones(self, content: str) -> List[str]:
        """Extract phone numbers (Russian format) from content"""
        return list(set(self.patterns['phone'].findall(content)))
    
    def extract_api_keys(self, content: str) -> List[Tuple[str, str]]:
        """Extract API keys and tokens"""
        matches = self.patterns['api_key'].findall(content)
        # Return type hints fix
        return [(m[0], m[1]) for m in matches]
    
    def extract_secrets(self, content: str) -> List[Dict[str, str]]:
        """Extract various secrets (keys, tokens, passwords)"""
        secrets = []
        
        # Check for hardcoded passwords
        pwd_pattern = r'(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{3,})["\']'
        for match in re.finditer(pwd_pattern, content, re.IGNORECASE):
            secrets.append({
                'type': 'hardcoded_password',
                'key': match.group(1),
                'value': '***hidden***',
                'context': match.group(0)[:50]
            })
        
        # Check for AWS keys
        aws_pattern = r'(AKIA[0-9A-Z]{16})'
        for match in re.finditer(aws_pattern, content):
            secrets.append({
                'type': 'aws_access_key',
                'value': match.group(1)[:8] + '...',
            })
        
        # Check for generic tokens
        token_pattern = r'(token|key|secret)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']'
        for match in re.finditer(token_pattern, content, re.IGNORECASE):
            secrets.append({
                'type': 'token',
                'key': match.group(1),
                'value': match.group(2)[:10] + '...',
            })
        
        return secrets
    
    def parse_html_forms(self, html: str) -> List[Dict[str, Any]]:
        """
        Extract form information from HTML
        
        Returns:
            List of form dictionaries with action, method, inputs
        """
        from bs4 import BeautifulSoup
        
        forms = []
        soup = BeautifulSoup(html, 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': [],
                'has_file_upload': False,
            }
            
            # Parse inputs
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'required': input_tag.has_attr('required'),
                }
                
                if input_data['type'] == 'file':
                    form_data['has_file_upload'] = True
                
                form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    def extract_bitrix_sessid(self, content: str) -> Optional[str]:
        """Extract Bitrix session ID (CSRF token)"""
        # Pattern: bitrix_sessid='abc123...'
        match = re.search(r"bitrix_sessid['\"]?\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?", content)
        if match:
            return match.group(1)
        
        # Pattern in input field
        match = re.search(r'name="sessid"\s+value="([a-f0-9]{32})"', content)
        if match:
            return match.group(1)
        
        return None
    
    def analyze_response_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze HTTP response headers for security issues
        
        Returns:
            Dictionary with findings
        """
        findings = {
            'security_headers_missing': [],
            'information_disclosure': [],
            'positive_security': [],
        }
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Check security headers
        security_headers = {
            'x-frame-options': 'Clickjacking protection',
            'content-security-policy': 'CSP',
            'x-content-type-options': 'MIME sniffing protection',
            'strict-transport-security': 'HSTS',
            'x-xss-protection': 'XSS filter',
            'referrer-policy': 'Referrer control',
        }
        
        for header, description in security_headers.items():
            if header not in headers_lower:
                findings['security_headers_missing'].append(f"{header} ({description})")
        
        # Check for information disclosure
        disclosure_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']
        for header in disclosure_headers:
            if header in headers_lower:
                findings['information_disclosure'].append(f"{header}: {headers_lower[header]}")
        
        # Check for Bitrix-specific headers
        if 'x-bitrix-composite' in headers_lower:
            findings['positive_security'].append('Bitrix Composite Cache detected')
        
        if 'x-bitrix-cdn' in headers_lower:
            findings['positive_security'].append('Bitrix CDN in use')
        
        return findings
    
    def decode_base64_in_url(self, url: str) -> Optional[str]:
        """Try to decode base64 parameter in URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for key, values in params.items():
            for value in values:
                try:
                    decoded = base64.b64decode(value).decode('utf-8')
                    return f"{key}={decoded[:100]}"
                except:
                    continue
        
        return None
    
    def is_error_page(self, content: str, status_code: int) -> Tuple[bool, str]:
        """
        Determine if content is an error page
        
        Returns:
            (is_error, error_type)
        """
        if status_code >= 400:
            return True, f"HTTP_{status_code}"
        
        error_indicators = [
            ('404 not found', '404'),
            ('error 404', '404'),
            ('страница не найдена', '404_ru'),
            ('server error', '500'),
            ('internal server error', '500'),
            ('bad gateway', '502'),
            ('service unavailable', '503'),
            ('fatal error', 'fatal'),
            ('exception', 'exception'),
            ('ошибка', 'error_ru'),
        ]
        
        content_lower = content.lower()
        for indicator, error_type in error_indicators:
            if indicator in content_lower:
                return True, error_type
        
        return False, ""
    
    def extract_paths_from_robots(self, content: str) -> List[str]:
        """Extract paths from robots.txt"""
        paths = []
        for line in content.split('\n'):
            line = line.strip().lower()
            if line.startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                if path and path != '/':
                    paths.append(path)
            elif line.startswith('allow:'):
                path = line.split(':', 1)[1].strip()
                if path:
                    paths.append(f"[ALLOW] {path}")
        return paths


# HTML entity decoder for special cases
class HTMLTextExtractor(HTMLParser):
    """Extract text from HTML, handling entities"""
    
    def __init__(self):
        super().__init__()
        self.text = []
    
    def handle_data(self, data):
        self.text.append(data)
    
    def handle_entityref(self, name):
        import html
        self.text.append(html.unescape(f'&{name};'))
    
    def get_text(self):
        return ''.join(self.text)


def strip_html(html: str) -> str:
    """Remove HTML tags and decode entities"""
    extractor = HTMLTextExtractor()
    try:
        extractor.feed(html)
        return extractor.get_text()
    except:
        # Fallback to regex
        import re
        return re.sub(r'<[^>]+>', '', html)