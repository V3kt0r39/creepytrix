import re
import json
import hashlib
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from bs4 import BeautifulSoup

@dataclass
class ReconResult:
    """Structure of reconnaissance results"""
    url: str
    bitrix_detected: bool
    version: Optional[str] = None
    edition: Optional[str] = None
    license_key_hash: Optional[str] = None  # hash of key, not the key itself
    admin_url: Optional[str] = None
    exposed_paths: List[str] = None
    technologies: List[str] = None
    robots_disallow: List[str] = None
    sitemap_urls: List[str] = None
    
    def __post_init__(self):
        if self.exposed_paths is None:
            self.exposed_paths = []
        if self.technologies is None:
            self.technologies = []
        if self.robots_disallow is None:
            self.robots_disallow = []
        if self.sitemap_urls is None:
            self.sitemap_urls = []
    
    def to_dict(self):
        return asdict(self)


class BitrixRecon:
    """
    Bitrix website reconnaissance module
    Detects version, edition, structure, entry points
    """
    
    # Bitrix signatures
    BITRIX_SIGNATURES = [
        '/bitrix/',
        'bx-core',
        'BX.setCSS',
        'bitrix_sessid',
        'bx-ajax-id',
        'bitrix24',
    ]
    
    # Paths for version detection
    VERSION_PATHS = [
        '/bitrix/js/main/core/core.js',           # JS version
        '/bitrix/js/main/core/core_ajax.js',      # Alternative JS
        '/bitrix/js/main/core/core_fx.js',        # Another variant
        '/bitrix/modules/main/classes/general/version.php',  # PHP (rarely accessible)
        '/bitrix/modules/main/lib/version.php',   # D7 version
    ]
    
    # Critical paths to check for accessibility
    SENSITIVE_PATHS = [
        '/bitrix/admin/',
        '/bitrix/backup/',
        '/bitrix/php_interface/',
        '/bitrix/.settings.php',
        '/bitrix/php_interface/dbconn.php',
        '/bitrix/.access.php',
        '/upload/',
        '/upload/backup/',
        '/.access.php',
        '/robots.txt',
        '/sitemap.xml',
        '/bitrix/html_pages/',  # Composite cache
        '/bitrix/cache/',
        '/bitrix/stack_cache/',
        '/bitrix/managed_cache/',
        '/local/',
        '/local/php_interface/',
        '/local/templates/',
    ]
    
    # Headers and their values indicating Bitrix
    BITRIX_HEADERS = [
        'X-Bitrix-Composite',
        'X-Bitrix-Param-CACHE',
        'Bitrix-SM-',
    ]
    
    def __init__(self, requester, logger):
        """
        Args:
            requester: Object for HTTP requests
            logger: Object for logging
        """
        self.requester = requester
        self.logger = logger
        self.results = {}
        
    def scan(self, target_url: str, aggressive: bool = False) -> ReconResult:
        """
        Main scanning method
        
        Args:
            target_url: Target URL (with http/https)
            aggressive: Aggressive scanning (more requests)
        
        Returns:
            ReconResult: Structure with results
        """
        self.logger.info(f"Starting reconnaissance for {target_url}")
        
        # URL normalization
        base_url = self._normalize_url(target_url)
        result = ReconResult(url=base_url, bitrix_detected=False)
        
        # 1. Check if this is Bitrix at all
        if not self._detect_bitrix(base_url):
            self.logger.warning(f"Bitrix not detected on {base_url}")
            return result
        
        result.bitrix_detected = True
        self.logger.success(f"Bitrix detected on {base_url}")
        
        # 2. Version detection
        result.version = self._detect_version(base_url)
        if result.version:
            self.logger.info(f"Detected version: {result.version}")
        
        # 3. Edition detection
        result.edition = self._detect_edition(base_url)
        if result.edition:
            self.logger.info(f"Detected edition: {result.edition}")
        
        # 4. Find admin panel
        result.admin_url = self._find_admin_panel(base_url)
        
        # 5. Check exposed paths
        result.exposed_paths = self._check_sensitive_paths(base_url)
        
        # 6. Analyze robots.txt
        result.robots_disallow = self._analyze_robots(base_url)
        
        # 7. Find sitemaps
        result.sitemap_urls = self._find_sitemaps(base_url)
        
        # 8. Detect technologies (CDN, server, etc.)
        result.technologies = self._detect_technologies(base_url)
        
        # 9. Aggressive scanning (if enabled)
        if aggressive:
            self._aggressive_scan(base_url, result)
        
        self.results[base_url] = result
        return result
    
    def _normalize_url(self, url: str) -> str:
        """URL normalization"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def _detect_bitrix(self, base_url: str) -> bool:
        """Check if the site is Bitrix"""
        indicators = []
        
        # Check home page
        response = self.requester.get(base_url)
        if not response:
            return False
        
        content = response.text.lower()
        headers = response.headers
        
        # Check HTML signatures
        for sig in self.BITRIX_SIGNATURES:
            if sig.lower() in content:
                indicators.append(f"html_signature:{sig}")
        
        # Check headers
        for header_name, header_value in headers.items():
            header_name_lower = header_name.lower()
            for bx_header in self.BITRIX_HEADERS:
                if bx_header.lower() in header_name_lower:
                    indicators.append(f"header:{header_name}")
        
        # Check for /bitrix/ directory
        test_paths = ['/bitrix/js/', '/bitrix/templates/', '/bitrix/components/']
        for path in test_paths:
            resp = self.requester.get(urljoin(base_url, path), allow_redirects=False)
            if resp and resp.status_code in [200, 401, 403, 301, 302]:
                indicators.append(f"directory:{path}")
                break
        
        # Check cookies
        if 'set-cookie' in headers:
            cookies = headers['set-cookie'].lower()
            if 'bitrix' in cookies or 'bx_' in cookies:
                indicators.append("cookie:bitrix")
        
        self.logger.debug(f"Bitrix indicators found: {indicators}")
        return len(indicators) > 0
    
    def _detect_version(self, base_url: str) -> Optional[str]:
        """Version detection through various paths"""
        versions = []
        
        # Method 1: Through JS files
        for path in self.VERSION_PATHS[:3]:  # Only JS paths
            url = urljoin(base_url, path)
            response = self.requester.get(url)
            
            if response and response.status_code == 200:
                # Pattern: BX.message({ ... 'bitrix_version':'20.0.0' ... })
                patterns = [
                    r"bitrix_version['\"]\s*:\s*['\"](\d+\.\d+\.\d+)['\"]",
                    r'version\s*[=:]\s*["\'](\d+\.\d+\.\d+)["\']',
                    r'@version\s+(\d+\.\d+\.\d+)',
                    r'v?(\d+\.\d+\.\d+)\s*-\s*Bitrix',
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, response.text)
                    if match:
                        versions.append((path, match.group(1)))
                        break
        
        # Method 2: Through meta generator
        response = self.requester.get(base_url)
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            meta = soup.find('meta', attrs={'name': 'bitrix'})
            if meta:
                versions.append(('meta', meta.get('content', '')))
            
            # Search in scripts
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script['src']
                if 'bitrix' in src:
                    # /bitrix/js/main/core/core.js?16668882262993
                    ver_match = re.search(r'\?(\d{10,})', src)
                    if ver_match:
                        timestamp = ver_match.group(1)
                        # Can roughly determine version by timestamp
                        versions.append(('js_timestamp', timestamp))
        
        # Method 3: Through CSS
        css_url = urljoin(base_url, '/bitrix/css/main/style.css')
        css_resp = self.requester.get(css_url)
        if css_resp and css_resp.status_code == 200:
            # Bitrix sometimes writes version in CSS comment
            ver_match = re.search(r'Bitrix\s+v\.?(\d+\.\d+\.\d+)', css_resp.text, re.I)
            if ver_match:
                versions.append(('css', ver_match.group(1)))
        
        # Return the most common or first found version
        if versions:
            version_counts = {}
            for source, ver in versions:
                version_counts[ver] = version_counts.get(ver, 0) + 1
            
            most_common = max(version_counts.items(), key=lambda x: x[1])
            self.logger.debug(f"Version sources: {versions}")
            return most_common[0]
        
        return None
    
    def _detect_edition(self, base_url: str) -> Optional[str]:
        """Detection of Bitrix edition"""
        editions = {
            'business': ['/bitrix/modules/sale/', '/bitrix/modules/catalog/'],
            'small_business': ['/bitrix/modules/sale/', '/bitrix/modules/catalog/'],
            'standard': ['/bitrix/modules/form/', '/bitrix/modules/iblock/'],
            'start': ['/bitrix/modules/iblock/'],
            'enterprise': ['/bitrix/modules/bizproc/', '/bitrix/modules/crm/'],
            '24': ['/bitrix/components/bitrix/socialnetwork/', '/bitrix/components/bitrix/crm/'],
        }
        
        detected_modules = set()
        
        # Check for module presence
        module_paths = [
            '/bitrix/modules/sale/',
            '/bitrix/modules/catalog/',
            '/bitrix/modules/iblock/',
            '/bitrix/modules/crm/',
            '/bitrix/modules/bizproc/',
            '/bitrix/modules/form/',
            '/bitrix/modules/blog/',
            '/bitrix/modules/forum/',
            '/bitrix/modules/socialnetwork/',
            '/bitrix/modules/intranet/',
        ]
        
        for path in module_paths:
            resp = self.requester.head(urljoin(base_url, path))
            if resp and resp.status_code in [200, 401, 403]:
                module_name = path.strip('/').split('/')[-1]
                detected_modules.add(module_name)
        
        # Determine edition by modules
        if 'intranet' in detected_modules or 'socialnetwork' in detected_modules:
            return "Bitrix24/Enterprise"
        elif 'crm' in detected_modules and 'bizproc' in detected_modules:
            return "Business/Enterprise"
        elif 'sale' in detected_modules and 'catalog' in detected_modules:
            return "Business/Small Business"
        elif 'iblock' in detected_modules:
            return "Standard/Start"
        
        return None
    
    def _find_admin_panel(self, base_url: str) -> Optional[str]:
        """Find admin panel URL"""
        admin_paths = [
            '/bitrix/admin/',
            '/bitrix/admin/index.php',
            '/local/admin/',  # Rare case
        ]
        
        for path in admin_paths:
            url = urljoin(base_url, path)
            resp = self.requester.get(url, allow_redirects=True)
            
            if resp and resp.status_code == 200:
                # Check if this is actually an admin panel
                if 'bitrix' in resp.text.lower() and ('auth' in resp.text.lower() or 
                                                       'login' in resp.text.lower() or
                                                       'authorization form' in resp.text.lower()):
                    return url
                
                # Check by headers
                if 'bitrix' in resp.headers.get('X-Bitrix-Composite', '').lower():
                    return url
        
        return None
    
    def _check_sensitive_paths(self, base_url: str) -> List[str]:
        """Check accessibility of sensitive paths"""
        exposed = []
        
        for path in self.SENSITIVE_PATHS:
            url = urljoin(base_url, path)
            resp = self.requester.get(url, allow_redirects=False)
            
            if not resp:
                continue
            
            status = resp.status_code
            
            # 200 - accessible, 401/403 - exists but protected, 301/302 - redirect
            if status in [200, 401, 403]:
                exposed.append(f"{path} (HTTP {status})")
                self.logger.warning(f"Exposed path found: {path} ({status})")
            
            # For backup directories, even redirects are important
            elif status in [301, 302] and 'backup' in path:
                exposed.append(f"{path} (Redirect -> {resp.headers.get('Location', 'unknown')})")
        
        return exposed
    
    def _analyze_robots(self, base_url: str) -> List[str]:
        """Analysis of robots.txt"""
        url = urljoin(base_url, '/robots.txt')
        resp = self.requester.get(url)
        
        disallow_paths = []
        
        if resp and resp.status_code == 200:
            lines = resp.text.split('\n')
            for line in lines:
                line = line.strip().lower()
                if line.startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        disallow_paths.append(path)
                        # Especially interesting paths containing bitrix, admin, backup
                        if any(keyword in path for keyword in ['bitrix', 'admin', 'backup', 'upload']):
                            self.logger.info(f"Interesting robots.txt entry: {path}")
        
        return disallow_paths
    
    def _find_sitemaps(self, base_url: str) -> List[str]:
        """Find sitemap.xml and related files"""
        sitemaps = []
        
        # Check standard sitemap.xml
        sitemap_urls = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/robots.txt',  # Often contains sitemap link
        ]
        
        for path in sitemap_urls:
            url = urljoin(base_url, path)
            resp = self.requester.get(url)
            
            if resp and resp.status_code == 200:
                if path == '/robots.txt':
                    # Look for Sitemap: directive
                    for line in resp.text.split('\n'):
                        if line.lower().startswith('sitemap:'):
                            sitemap_url = line.split(':', 1)[1].strip()
                            sitemaps.append(sitemap_url)
                else:
                    sitemaps.append(urljoin(base_url, path))
                    
                    # Parse sitemap for other sitemaps
                    if 'xml' in resp.headers.get('Content-Type', ''):
                        try:
                            soup = BeautifulSoup(resp.text, 'xml')
                            for loc in soup.find_all('loc'):
                                if loc.string:
                                    sitemaps.append(loc.string)
                        except:
                            pass
        
        # Remove duplicates
        return list(set(sitemaps))
    
    def _detect_technologies(self, base_url: str) -> List[str]:
        """Detection of used technologies"""
        techs = []
        
        resp = self.requester.get(base_url)
        if not resp:
            return techs
        
        headers = resp.headers
        server = headers.get('Server', '')
        powered = headers.get('X-Powered-By', '')
        
        # Web server
        if 'nginx' in server.lower():
            techs.append(f"nginx ({server})")
        elif 'apache' in server.lower():
            techs.append(f"Apache ({server})")
        
        # PHP
        if 'php' in powered.lower():
            techs.append(f"PHP ({powered})")
        
        # Caching
        if 'x-bitrix-composite' in headers:
            techs.append("Bitrix Composite Cache")
        
        if 'x-bitrix-cdn' in headers:
            techs.append("Bitrix CDN")
        
        # Varnish/Nginx cache
        if 'x-varnish' in headers or 'x-cache' in headers:
            techs.append("Reverse Proxy Cache")
        
        # Cloudflare
        if 'cf-ray' in headers or 'cloudflare' in headers.get('Server', '').lower():
            techs.append("Cloudflare")
        
        # Check CDN by header
        cdn_headers = ['X-Cache', 'X-Edge-Location', 'X-CDN', 'CF-Cache-Status']
        for h in cdn_headers:
            if h in headers:
                techs.append(f"CDN: {h}")
        
        # Check database (through errors or features)
        # This can be extended in the future
        
        return techs
    
    def _aggressive_scan(self, base_url: str, result: ReconResult):
        """Aggressive scanning (more requests, deeper checking)"""
        self.logger.info("Starting aggressive scan...")
        
        # Search for typical Bitrix pages
        common_pages = [
            '/bitrix/rk.php',  # Redirects
            '/bitrix/redirect.php',
            '/bitrix/tools/',
            '/bitrix/components/',
            '/search/',
            '/catalog/',
            '/news/',
            '/about/',
            '/contacts/',
        ]
        
        found_pages = []
        for page in common_pages:
            url = urljoin(base_url, page)
            resp = self.requester.head(url)
            if resp and resp.status_code == 200:
                found_pages.append(page)
        
        if found_pages:
            self.logger.info(f"Common pages found: {found_pages}")
        
        # Search for API endpoints
        api_paths = [
            '/rest/',
            '/api/',
            '/bitrix/services/rest/',
            '/bitrix/tools/sale_order_ajax.php',
            '/bitrix/tools/upload.php',
        ]
        
        for path in api_paths:
            url = urljoin(base_url, path)
            resp = self.requester.options(url)  # OPTIONS request
            if resp and resp.status_code != 405:  # 405 = Method Not Allowed
                self.logger.info(f"API endpoint might exist: {path}")
        
        # Check configuration files with different extensions
        config_variants = [
            '/bitrix/.settings.php',
            '/bitrix/.settings.php.bak',
            '/bitrix/.settings.php~',
            '/bitrix/.settings.php.old',
            '/bitrix/php_interface/dbconn.php.bak',
            '/bitrix/php_interface/dbconn.php~',
            '/.env',
            '/.env.local',
        ]
        
        for path in config_variants:
            url = urljoin(base_url, path)
            resp = self.requester.get(url)
            if resp and resp.status_code == 200 and len(resp.text) > 0:
                # Check that this is not a 404 page
                if resp.status_code == 200 and '<?php' in resp.text:
                    result.exposed_paths.append(f"{path} (CRITICAL: Config file exposed!)")
                    self.logger.critical(f"Config file exposed: {path}")


# Example usage and testing
if __name__ == "__main__":
    # Mock objects for testing
    class MockRequester:
        def get(self, url, **kwargs):
            import requests
            try:
                return requests.get(url, timeout=10, verify=False, **kwargs)
            except:
                return None
        
        def head(self, url, **kwargs):
            import requests
            try:
                return requests.head(url, timeout=5, verify=False, **kwargs)
            except:
                return None
        
        def options(self, url, **kwargs):
            import requests
            try:
                return requests.options(url, timeout=5, verify=False, **kwargs)
            except:
                return None
    
    class MockLogger:
        def debug(self, msg): print(f"[DEBUG] {msg}")
        def info(self, msg): print(f"[INFO] {msg}")
        def warning(self, msg): print(f"[WARN] {msg}")
        def success(self, msg): print(f"[OK] {msg}")
        def critical(self, msg): print(f"[CRIT] {msg}")
    
    # Test
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        recon = BitrixRecon(MockRequester(), MockLogger())
        result = recon.scan(target, aggressive=False)
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        print("Usage: python recon.py <url>")
