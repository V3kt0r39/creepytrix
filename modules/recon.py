# modules/recon.py
import re
import json
import hashlib
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from bs4 import BeautifulSoup

@dataclass
class ReconResult:
    """Структура результатов разведки"""
    url: str
    bitrix_detected: bool
    version: Optional[str] = None
    edition: Optional[str] = None
    license_key_hash: Optional[str] = None  # хеш ключа, не сам ключ
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
    Модуль разведки Bitrix-сайтов
    Определяет версию, редакцию, структуру, точки входа
    """
    
    # Сигнатуры Bitrix
    BITRIX_SIGNATURES = [
        '/bitrix/',
        'bx-core',
        'BX.setCSS',
        'bitrix_sessid',
        'bx-ajax-id',
        'bitrix24',
    ]
    
    # Пути для определения версии
    VERSION_PATHS = [
        '/bitrix/js/main/core/core.js',           # JS версия
        '/bitrix/js/main/core/core_ajax.js',      # Альтернативный JS
        '/bitrix/js/main/core/core_fx.js',        # Еще один вариант
        '/bitrix/modules/main/classes/general/version.php',  # PHP (редко доступен)
        '/bitrix/modules/main/lib/version.php',   # D7 версия
    ]
    
    # Критичные пути для проверки доступности
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
        '/bitrix/html_pages/',  # Композитный кэш
        '/bitrix/cache/',
        '/bitrix/stack_cache/',
        '/bitrix/managed_cache/',
        '/local/',
        '/local/php_interface/',
        '/local/templates/',
    ]
    
    # Заголовки и их значения, указывающие на Bitrix
    BITRIX_HEADERS = [
        'X-Bitrix-Composite',
        'X-Bitrix-Param-CACHE',
        'Bitrix-SM-',
    ]
    
    def __init__(self, requester, logger):
        """
        Args:
            requester: объект для HTTP-запросов
            logger: объект для логирования
        """
        self.requester = requester
        self.logger = logger
        self.results = {}
        
    def scan(self, target_url: str, aggressive: bool = False) -> ReconResult:
        """
        Основной метод сканирования
        
        Args:
            target_url: URL цели (с http/https)
            aggressive: агрессивное сканирование (больше запросов)
        
        Returns:
            ReconResult: структура с результатами
        """
        self.logger.info(f"Starting reconnaissance for {target_url}")
        
        # Нормализация URL
        base_url = self._normalize_url(target_url)
        result = ReconResult(url=base_url, bitrix_detected=False)
        
        # 1. Проверка, что это вообще Bitrix
        if not self._detect_bitrix(base_url):
            self.logger.warning(f"Bitrix not detected on {base_url}")
            return result
        
        result.bitrix_detected = True
        self.logger.success(f"Bitrix detected on {base_url}")
        
        # 2. Определение версии
        result.version = self._detect_version(base_url)
        if result.version:
            self.logger.info(f"Detected version: {result.version}")
        
        # 3. Определение редакции
        result.edition = self._detect_edition(base_url)
        if result.edition:
            self.logger.info(f"Detected edition: {result.edition}")
        
        # 4. Поиск админки
        result.admin_url = self._find_admin_panel(base_url)
        
        # 5. Проверка exposed paths
        result.exposed_paths = self._check_sensitive_paths(base_url)
        
        # 6. Анализ robots.txt
        result.robots_disallow = self._analyze_robots(base_url)
        
        # 7. Поиск sitemap
        result.sitemap_urls = self._find_sitemaps(base_url)
        
        # 8. Определение технологий (CDN, сервер и т.д.)
        result.technologies = self._detect_technologies(base_url)
        
        # 9. Агрессивное сканирование (если включено)
        if aggressive:
            self._aggressive_scan(base_url, result)
        
        self.results[base_url] = result
        return result
    
    def _normalize_url(self, url: str) -> str:
        """Нормализация URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def _detect_bitrix(self, base_url: str) -> bool:
        """Определение, является ли сайт Bitrix"""
        indicators = []
        
        # Проверка главной страницы
        response = self.requester.get(base_url)
        if not response:
            return False
        
        content = response.text.lower()
        headers = response.headers
        
        # Проверка сигнатур в HTML
        for sig in self.BITRIX_SIGNATURES:
            if sig.lower() in content:
                indicators.append(f"html_signature:{sig}")
        
        # Проверка заголовков
        for header_name, header_value in headers.items():
            header_name_lower = header_name.lower()
            for bx_header in self.BITRIX_HEADERS:
                if bx_header.lower() in header_name_lower:
                    indicators.append(f"header:{header_name}")
        
        # Проверка наличия /bitrix/ директории
        test_paths = ['/bitrix/js/', '/bitrix/templates/', '/bitrix/components/']
        for path in test_paths:
            resp = self.requester.get(urljoin(base_url, path), allow_redirects=False)
            if resp and resp.status_code in [200, 401, 403, 301, 302]:
                indicators.append(f"directory:{path}")
                break
        
        # Проверка cookies
        if 'set-cookie' in headers:
            cookies = headers['set-cookie'].lower()
            if 'bitrix' in cookies or 'bx_' in cookies:
                indicators.append("cookie:bitrix")
        
        self.logger.debug(f"Bitrix indicators found: {indicators}")
        return len(indicators) > 0
    
    def _detect_version(self, base_url: str) -> Optional[str]:
        """Определение версии Bitrix через различные пути"""
        versions = []
        
        # Метод 1: Через JS файлы
        for path in self.VERSION_PATHS[:3]:  # Только JS пути
            url = urljoin(base_url, path)
            response = self.requester.get(url)
            
            if response and response.status_code == 200:
                # Паттерн: BX.message({ ... 'bitrix_version':'20.0.0' ... })
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
        
        # Метод 2: Через meta generator
        response = self.requester.get(base_url)
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            meta = soup.find('meta', attrs={'name': 'bitrix'})
            if meta:
                versions.append(('meta', meta.get('content', '')))
            
            # Поиск в скриптах
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script['src']
                if 'bitrix' in src:
                    # /bitrix/js/main/core/core.js?16668882262993
                    ver_match = re.search(r'\?(\d{10,})', src)
                    if ver_match:
                        timestamp = ver_match.group(1)
                        # Можно примерно определить версию по timestamp
                        versions.append(('js_timestamp', timestamp))
        
        # Метод 3: Через CSS
        css_url = urljoin(base_url, '/bitrix/css/main/style.css')
        css_resp = self.requester.get(css_url)
        if css_resp and css_resp.status_code == 200:
            # Bitrix иногда пишет версию в комментарии CSS
            ver_match = re.search(r'Bitrix\s+v\.?(\d+\.\d+\.\d+)', css_resp.text, re.I)
            if ver_match:
                versions.append(('css', ver_match.group(1)))
        
        # Возвращаем наиболее частую или первую найденную версию
        if versions:
            version_counts = {}
            for source, ver in versions:
                version_counts[ver] = version_counts.get(ver, 0) + 1
            
            most_common = max(version_counts.items(), key=lambda x: x[1])
            self.logger.debug(f"Version sources: {versions}")
            return most_common[0]
        
        return None
    
    def _detect_edition(self, base_url: str) -> Optional[str]:
        """Определение редакции Bitrix"""
        editions = {
            'business': ['/bitrix/modules/sale/', '/bitrix/modules/catalog/'],
            'small_business': ['/bitrix/modules/sale/', '/bitrix/modules/catalog/'],
            'standard': ['/bitrix/modules/form/', '/bitrix/modules/iblock/'],
            'start': ['/bitrix/modules/iblock/'],
            'enterprise': ['/bitrix/modules/bizproc/', '/bitrix/modules/crm/'],
            '24': ['/bitrix/components/bitrix/socialnetwork/', '/bitrix/components/bitrix/crm/'],
        }
        
        detected_modules = set()
        
        # Проверяем наличие модулей
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
        
        # Определяем редакцию по модулям
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
        """Поиск URL админ-панели"""
        admin_paths = [
            '/bitrix/admin/',
            '/bitrix/admin/index.php',
            '/local/admin/',  # Редкий случай
        ]
        
        for path in admin_paths:
            url = urljoin(base_url, path)
            resp = self.requester.get(url, allow_redirects=True)
            
            if resp and resp.status_code == 200:
                # Проверяем, что это действительно админка
                if 'bitrix' in resp.text.lower() and ('auth' in resp.text.lower() or 
                                                       'login' in resp.text.lower() or
                                                       'форма авторизации' in resp.text.lower()):
                    return url
                
                # Проверка по заголовкам
                if 'bitrix' in resp.headers.get('X-Bitrix-Composite', '').lower():
                    return url
        
        return None
    
    def _check_sensitive_paths(self, base_url: str) -> List[str]:
        """Проверка доступности чувствительных путей"""
        exposed = []
        
        for path in self.SENSITIVE_PATHS:
            url = urljoin(base_url, path)
            resp = self.requester.get(url, allow_redirects=False)
            
            if not resp:
                continue
            
            status = resp.status_code
            
            # 200 - доступен, 401/403 - существует но защищен, 301/302 - редирект
            if status in [200, 401, 403]:
                exposed.append(f"{path} (HTTP {status})")
                self.logger.warning(f"Exposed path found: {path} ({status})")
            
            # Для backup директорий важно даже перенаправление
            elif status in [301, 302] and 'backup' in path:
                exposed.append(f"{path} (Redirect -> {resp.headers.get('Location', 'unknown')})")
        
        return exposed
    
    def _analyze_robots(self, base_url: str) -> List[str]:
        """Анализ robots.txt"""
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
                        # Особенно интересны пути содержащие bitrix, admin, backup
                        if any(keyword in path for keyword in ['bitrix', 'admin', 'backup', 'upload']):
                            self.logger.info(f"Interesting robots.txt entry: {path}")
        
        return disallow_paths
    
    def _find_sitemaps(self, base_url: str) -> List[str]:
        """Поиск sitemap.xml и связанных файлов"""
        sitemaps = []
        
        # Проверка стандартного sitemap.xml
        sitemap_urls = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/robots.txt',  # Часто там есть ссылка на sitemap
        ]
        
        for path in sitemap_urls:
            url = urljoin(base_url, path)
            resp = self.requester.get(url)
            
            if resp and resp.status_code == 200:
                if path == '/robots.txt':
                    # Ищем Sitemap: директиву
                    for line in resp.text.split('\n'):
                        if line.lower().startswith('sitemap:'):
                            sitemap_url = line.split(':', 1)[1].strip()
                            sitemaps.append(sitemap_url)
                else:
                    sitemaps.append(urljoin(base_url, path))
                    
                    # Парсим sitemap на наличие других sitemap'ов
                    if 'xml' in resp.headers.get('Content-Type', ''):
                        try:
                            soup = BeautifulSoup(resp.text, 'xml')
                            for loc in soup.find_all('loc'):
                                if loc.string:
                                    sitemaps.append(loc.string)
                        except:
                            pass
        
        # Удаляем дубликаты
        return list(set(sitemaps))
    
    def _detect_technologies(self, base_url: str) -> List[str]:
        """Определение используемых технологий"""
        techs = []
        
        resp = self.requester.get(base_url)
        if not resp:
            return techs
        
        headers = resp.headers
        server = headers.get('Server', '')
        powered = headers.get('X-Powered-By', '')
        
        # Веб-сервер
        if 'nginx' in server.lower():
            techs.append(f"nginx ({server})")
        elif 'apache' in server.lower():
            techs.append(f"Apache ({server})")
        
        # PHP
        if 'php' in powered.lower():
            techs.append(f"PHP ({powered})")
        
        # Кэширование
        if 'x-bitrix-composite' in headers:
            techs.append("Bitrix Composite Cache")
        
        if 'x-bitrix-cdn' in headers:
            techs.append("Bitrix CDN")
        
        # Varnish/Nginx кэш
        if 'x-varnish' in headers or 'x-cache' in headers:
            techs.append("Reverse Proxy Cache")
        
        # Cloudflare
        if 'cf-ray' in headers or 'cloudflare' in headers.get('Server', '').lower():
            techs.append("Cloudflare")
        
        # Проверка на CDN по IP (упрощенно)
        cdn_headers = ['X-Cache', 'X-Edge-Location', 'X-CDN', 'CF-Cache-Status']
        for h in cdn_headers:
            if h in headers:
                techs.append(f"CDN: {h}")
        
        # Проверка базы данных (через ошибки или особенности)
        # Это можно расширить в будущем
        
        return techs
    
    def _aggressive_scan(self, base_url: str, result: ReconResult):
        """Агрессивное сканирование (больше запросов, глубже проверка)"""
        self.logger.info("Starting aggressive scan...")
        
        # Поиск типовых Bitrix-страниц
        common_pages = [
            '/bitrix/rk.php',  # Редиректы
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
        
        # Поиск API endpoints
        api_paths = [
            '/rest/',
            '/api/',
            '/bitrix/services/rest/',
            '/bitrix/tools/sale_order_ajax.php',
            '/bitrix/tools/upload.php',
        ]
        
        for path in api_paths:
            url = urljoin(base_url, path)
            resp = self.requester.options(url)  # OPTIONS запрос
            if resp and resp.status_code != 405:  # 405 = Method Not Allowed
                self.logger.info(f"API endpoint might exist: {path}")
        
        # Проверка файлов конфигурации с разными расширениями
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
                # Проверяем, что это не 404 страница
                if resp.status_code == 200 and '<?php' in resp.text:
                    result.exposed_paths.append(f"{path} (CRITICAL: Config file exposed!)")
                    self.logger.critical(f"Config file exposed: {path}")


# Пример использования и тестирования
if __name__ == "__main__":
    # Заглушки для тестирования
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
    
    # Тест
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        recon = BitrixRecon(MockRequester(), MockLogger())
        result = recon.scan(target, aggressive=False)
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        print("Usage: python recon.py <url>")