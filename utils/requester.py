#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unified HTTP client for pentest tool
Handles timeouts, retries, User-Agent rotation
"""

import requests
import urllib3
from typing import Optional, Dict, Any
import time
import random
import socket

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Requester:
    """
    Unified HTTP client for pentest tool
    """
    
    DEFAULT_USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    ]
    
    def __init__(self, 
                 timeout: int = 10,
                 retries: int = 3,
                 delay: float = 0.5,
                 proxy: Optional[str] = None,
                 cookies: Optional[Dict[str, str]] = None,
                 headers: Optional[Dict[str, str]] = None):
        """
        Initialize the HTTP client
        
        Args:
            timeout: Request timeout in seconds
            retries: Number of retry attempts
            delay: Delay between requests in seconds
            proxy: Proxy URL (e.g., http://127.0.0.1:8080)
            cookies: Default cookies to send
            headers: Default headers to send
        """
        self.timeout = timeout
        self.retries = retries
        self.delay = delay
        self.session = requests.Session()
        self.session.verify = False
        
        # Set DNS timeout
        socket.setdefaulttimeout(timeout)
        
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        
        if cookies:
            self.session.cookies.update(cookies)
        
        self.default_headers = headers or {}
        self.default_headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        self.default_headers['Accept-Language'] = 'en-US,en;q=0.9'
        self.default_headers['Accept-Encoding'] = 'gzip, deflate, br'
        self.default_headers['Connection'] = 'keep-alive'
        self.default_headers['Upgrade-Insecure-Requests'] = '1'
    
    def _get_headers(self) -> Dict[str, str]:
        """Generate headers with User-Agent rotation"""
        headers = self.default_headers.copy()
        headers['User-Agent'] = random.choice(self.DEFAULT_USER_AGENTS)
        return headers
    
    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Base request method with retries"""
        for attempt in range(self.retries):
            try:
                headers = self._get_headers()
                if 'headers' in kwargs:
                    headers.update(kwargs.pop('headers'))
                
                time.sleep(self.delay)  # Rate limiting
                
                response = self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    timeout=self.timeout,
                    **kwargs
                )
                return response
                
            except requests.exceptions.Timeout:
                if attempt == self.retries - 1:
                    return None
                time.sleep(self.delay * 2)
                
            except requests.exceptions.ConnectionError:
                if attempt == self.retries - 1:
                    return None
                time.sleep(self.delay * 2)
                
            except requests.exceptions.TooManyRedirects:
                return None
                
            except Exception as e:
                if attempt == self.retries - 1:
                    return None
        
        return None
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Send GET request"""
        return self._request('GET', url, **kwargs)
    
    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Send POST request"""
        return self._request('POST', url, **kwargs)
    
    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Send HEAD request"""
        return self._request('HEAD', url, **kwargs)
    
    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Send OPTIONS request"""
        return self._request('OPTIONS', url, **kwargs)
    
    def put(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Send PUT request"""
        return self._request('PUT', url, **kwargs)
    
    def delete(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Send DELETE request"""
        return self._request('DELETE', url, **kwargs)
