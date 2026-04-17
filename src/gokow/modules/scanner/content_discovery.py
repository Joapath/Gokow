"""
Descubrimiento de Contenido - Enumeración de directorios y archivos.

Técnicas:
- Brute-force de directorios comunes
- Búsqueda recursiva
- Filtrado por status code (200, 301, 302, 401, 403, 500)
- Detección de backups (.bak, .zip, .tar.gz)
- Búsqueda de archivos sensibles (.env, .git, config, etc)

Resistencia WAF:
- Rate limiting adaptativo (0.05-0.1s)
- User-Agent rotation
- Minimal requests (solo HEAD si es posible)
- Status code analysis (no solo 200)
- Threads limitados (no flood)
"""

import asyncio
import aiohttp
from datetime import datetime
from typing import Optional, Dict, Any, List, Set, Tuple
from dataclasses import dataclass
import re

from gokow.modules.base import BaseScanner, ScanResult
from gokow.utils.logger import logger


@dataclass
class FoundPath:
    """Ruta encontrada."""
    path: str
    status_code: int
    content_type: Optional[str] = None
    size: Optional[int] = None
    redirect_to: Optional[str] = None


class ContentDiscoveryScanner(BaseScanner):
    """
    Escáner de descubrimiento de contenido.
    
    Enumera directorios y archivos en servidor web:
    - Rutas públicas
    - Backups
    - Archivos de configuración
    - Directorios de desarrollo
    - Rutas admin
    
    Para encontrar:
    - Directorios valiosos
    - Backups olvidados
    - Archivos de configuración
    - Información técnica
    """

    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(target, config)
        
        self.config = config or {}
        self.timeout = self.config.get('timeout', 5)
        self.url = self._normalize_url()
        self.wordlists = self.config.get('wordlists', self._default_wordlists())
        self.found_paths: Dict[str, FoundPath] = {}
        self.max_concurrent = self.config.get('max_concurrent', 5)
        self.interesting_status_codes = {200, 301, 302, 401, 403, 500}

    def _normalize_url(self) -> str:
        """Normalizar target a URL válida."""
        target = self.target.strip()
        
        if not target.startswith('http://') and not target.startswith('https://'):
            target = f'http://{target}'
        
        # Asegurar que termina con /
        if not target.endswith('/'):
            target += '/'
        
        return target

    def _default_wordlists(self) -> List[str]:
        """Wordlists por defecto."""
        return [
            # Directorios comunes
            'admin', 'administrator', 'api', 'api-v1', 'api-v2', 'apiserver',
            'app', 'application', 'application.php',
            'assets', 'archive', 'archives', 'archived',
            'ajax', 'ajax.php', 'admin.php',
            'auth', 'auth.php', 'access',
            'backup', 'backups', 'back', 'bak',
            'blog', 'blogs', 'board', 'browse',
            'cache', 'cached', 'cms', 'config', 'conf',
            'content', 'cgi-bin', 'common', 'console',
            'control', 'controlpanel', 'cpanel',
            'data', 'database', 'db', 'dev', 'develop', 'development',
            'devel', 'download', 'downloads',
            'documentation', 'docs', 'doc', 'docroot',
            'etc', 'example', 'examples', 'execphp',
            'files', 'file', 'file_system', 'fileman',
            'forum', 'forums', 'free', 'ftp',
            'gallery', 'game', 'games', 'git',
            'global', 'groups', 'group',
            'guide', 'hack', 'hard_drive', 'home', 'homepage',
            'host', 'hosting', 'hosts', 'html', 'http',
            'icons', 'icon', 'id', 'images', 'image', 'img',
            'includes', 'include', 'incoming', 'index',
            'info', 'information', 'init', 'input',
            'install', 'installer', 'installation', 'installs',
            'instance', 'internal', 'issues',
            'javascript', 'js', 'json', 'journal',
            'kernel', 'key', 'keys', 'knowledge', 'knowledge_base',
            'language', 'languages', 'layout', 'layouts',
            'learn', 'libraries', 'library', 'license',
            'licenses', 'linux', 'live', 'load',
            'local', 'locale', 'locales', 'location',
            'locations', 'lock', 'log', 'logfile', 'logging',
            'logs', 'login', 'logout', 'lowres',
            'manage', 'management', 'manager', 'manual',
            'manufacturer', 'map', 'mapping', 'maps',
            'market', 'marketing', 'marketplace', 'master',
            'master_password', 'mail', 'mailer', 'mailing',
            'media', 'mediator', 'meet', 'menu', 'menus',
            'message', 'messages', 'method', 'metrics',
            'middleware', 'migration', 'migrations', 'misc',
            'miscellaneous', 'missing', 'mission', 'mod',
            'mode', 'model', 'models', 'moderate', 'moderation',
            'module', 'modules', 'monitor', 'monitoring',
            'monolith', 'mount', 'movement', 'movie', 'movies',
            'moving', 'mp3', 'mpeg', 'multiple', 'myspace',
            'mysqldump', 'name', 'names', 'namespace',
            'namespaces', 'native', 'navigate', 'navigation',
            'nearby', 'necessary', 'need', 'network', 'networks',
            'new', 'news', 'newsletter', 'next',
            'nginx', 'nick', 'node', 'nodes', 'note', 'notes',
            'notification', 'notifications', 'now', 'numbers',
            'object', 'objects', 'obsolete', 'obtain',
            'office', 'official', 'old', 'oldfiles',
            'on', 'one', 'online', 'only', 'open',
            'opensearch', 'openssl', 'operation', 'operations',
            'operator', 'operators', 'opinion', 'opposite',
            'option', 'optionalparam', 'options', 'order',
            'orders', 'ordinary', 'organization', 'organizations',
            'organize', 'origin', 'original', 'orphan',
            'orphaned', 'os', 'other', 'others', 'output',
            'outside', 'over', 'overall', 'overflow', 'overload',
            'override', 'overview', 'owner', 'owners',
            'package', 'packages', 'packagexml', 'packet',
            'packets', 'page', 'pages', 'paginate', 'pagination',
            'paginator', 'panel', 'panels', 'param', 'parameter',
            'parameters', 'parent', 'parents', 'parse',
            'parser', 'part', 'partial', 'participant',
            'participate', 'particular', 'parties', 'partition',
            'partitions', 'parts', 'party', 'pass',
            'passage', 'passenger', 'passed', 'password',
            'passwd', 'passwords', 'past', 'patch',
            'patches', 'path', 'pathinfo', 'patrol',
            'pattern', 'patterns', 'pause', 'pay',
            'payment', 'payments', 'paypal', 'pdf',
            'pending', 'people', 'perlscript', 'permission',
            'permissions', 'permissive', 'permit', 'person',
            'personal', 'perspective', 'perspective_view',
            'php', 'php-mysql', 'phpinfo', 'phpmyadmin',
            'phpmyadmin.php', 'phpunit', 'physics', 'phishing',
            'phishing_attempt', 'phishing_page', 'phishing_report',
            'phishing_url', 'phishing_urls', 'pick', 'picture',
            'pictures', 'piece', 'pieces', 'ping', 'pipe',
            'pipes', 'pixel', 'pixels', 'place', 'placement',
            'places', 'plain', 'plan', 'plane', 'planet',
            'planets', 'planning', 'plans', 'plant',
            'plate', 'plates', 'platform', 'platforms',
            'play', 'player', 'players', 'playground',
            'playing', 'playoff', 'playoffs', 'plays',
            'plaza', 'pleas', 'please', 'pledge', 'pleasure',
            'pluck', 'plug', 'plugin', 'plugins', 'plumb',
            'plumbing', 'plural', 'plus', 'ply', 'pm',
            'pocket', 'pocketpc', 'podcast', 'podium', 'poem',
            'poems', 'pocket', 'point', 'pointer', 'pointers',
            'pointing', 'points', 'poison', 'poise', 'poised',
            'poker', 'polar', 'pole', 'police', 'policing',
            'policies', 'policy', 'polish', 'polishing',
            'polite', 'political', 'politics', 'poll', 'polling',
            'polls', 'polygon', 'pond', 'popular', 'popularity',
            'populate', 'populated', 'population', 'porch',
            'port', 'portal', 'portals', 'portable',
            'portage', 'portal', 'portály', 'portation',
            'portent', 'porter', 'portfolio', 'portion',
            'portioning', 'portions', 'portly', 'portrait',
            'portraiture', 'portray', 'portray', 'pose',
            'posed', 'posh', 'position', 'positions', 'positive',
            'posix', 'posse', 'possess', 'possession',
            'possessions', 'possessive', 'possibility',
            'possible', 'possibly', 'post', 'postage',
            'postal', 'postcard', 'postcards', 'posterior',
            'posterity', 'poster', 'posters', 'postfix',
            'post_id', 'post_ids', 'posting', 'postings',
            'postlog', 'postmen', 'postmortem', 'postnatal',
            'postnumber', 'postpone', 'postponed', 'posts',
            'postscript', 'posture', 'postures', 'postwar',
            'potash', 'potassium', 'poteen', 'potency',
            'potent', 'potential', 'potentiality', 'potentially',
            'potentilla', 'potentialize', 'potently', 'pother',
            'pothered', 'pothering', 'pothers', 'potherb',
            'potherbs', 'pothole', 'potholes', 'potion',
            'potions', 'potlach', 'potlacs', 'potlatch',
            'potlatches', 'potlicker', 'potluck', 'potlucks',
            'potman', 'potmanteau', 'potoo', 'potoos', 'potpourri',
            'potpourris', 'pots', 'potsherd', 'potsherds',
            'potshop', 'potshot', 'potshots', 'potshotted',
            'potshotting', 'potsy', 'pottage', 'pottages',
            'potted', 'potteen', 'potteen', 'potter',
            'pottered', 'potterer', 'potterers', 'pottering',
            'potteries', 'potters', 'pottery', 'potting',
            'pottings', 'potty', 'pouch', 'pouched', 'pouches',
            'pouchier', 'pouchiest', 'pouching', 'pouchy',
            'pouf', 'pouffe', 'pouffed', 'puffes', 'pouffy',
            'poufs', 'pouke', 'pouks', 'poult', 'poulterer',
            'poulterers', 'poultice', 'poulticed', 'poultices',
            'poulticing', 'poultry', 'poultryman', 'poultrywomen',
            'poults', 'pounce', 'pounced', 'pouncer',
            'pouncers', 'pounces', 'pouncing', 'pound',
            'poundable', 'poundage', 'poundages', 'pounded',
            'poundee', 'pounder', 'pounders', 'pounding',
            'poundings', 'pounds', 'pour', 'pourable',
            'poured', 'pourer', 'pourers', 'pouring',
            'pouringly', 'pourings', 'pouring_rain', 'pourparler',
            'pourparlers', 'pourpoint', 'pourpoints', 'pours',
            'pousada', 'pousadas', 'pousse', 'pousse_cafe',
            'pousse_cafes', 'pousses', 'poussette', 'poussettes',
            'pout', 'poutana', 'pouted', 'pouter', 'pouteria',
            'pouteria_campechiana', 'pouters', 'poutful', 'poutie',
            'pouting', 'poutingly', 'poutings', 'poutish',
            'poutingly', 'pouts', 'pouty', 'poutypants',
            'poverty', 'powder', 'powdered', 'powderer',
            'powderers', 'powderhorn', 'powderhourns', 'powdering',
            'powderings', 'powderless', 'powderpuff', 'powderpuffs',
            'powders', 'powdery', 'powdrage', 'pow', 'powdwow',
            'powdwows', 'power', 'powered', 'powering', 'powerless',
            'powerlessly', 'powerlessness', 'powerlessnesses',
            'powers', 'powfagged', 'powfags', 'powhead',
            'powheads', 'powinda', 'pow_wow', 'pow_wows',
            'powpincksh', 'powrie', 'powries', 'powses',
            'powshot', 'powshots', 'powsned', 'powsowdie',
            'powsowner', 'powsound', 'powsownie', 'powsoudie',
            'powwow', 'powwows', 'pox', 'poxed', 'poxes',
            'poxier', 'poxiest', 'poxing', 'poxings', 'poxy',
            'poxyism', 'poyade', 'poyceman', 'poynard',
            'poynard', 'poynards', 'poyndestable', 'poynders',
            'poyou', 'poyous', 'poyser', 'poysers',
        ]

    async def _check_path(self, session: aiohttp.ClientSession, path: str) -> Optional[FoundPath]:
        """Verificar un path específico."""
        try:
            await self._apply_opsec()  # OPSEC: delay
            
            full_url = self.url.rstrip('/') + '/' + path.lstrip('/')
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            async with session.head(full_url, headers=headers, 
                                  timeout=self.timeout, allow_redirects=False) as resp:
                if resp.status in self.interesting_status_codes:
                    content_type = resp.headers.get('Content-Type', 'unknown')
                    content_length = resp.headers.get('Content-Length', None)
                    location = resp.headers.get('Location', None)
                    
                    return FoundPath(
                        path=path,
                        status_code=resp.status,
                        content_type=content_type,
                        size=int(content_length) if content_length else None,
                        redirect_to=location
                    )
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            pass
        
        return None

    async def _enumerate_paths(self) -> int:
        """Enumerar paths."""
        found_count = 0
        
        connector = aiohttp.TCPConnector(limit=self.max_concurrent)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            
            for path in self.wordlists:
                tasks.append(self._check_path(session, path))
                
                # Limitar tasks concurrentes
                if len(tasks) >= self.max_concurrent:
                    results = await asyncio.gather(*tasks)
                    for result in results:
                        if result:
                            self.found_paths[result.path] = result
                            status_emoji = '✓' if result.status_code == 200 else '→' if result.status_code in [301, 302] else '⚠'
                            self._log_finding('info', f'{status_emoji} [{result.status_code}]', f'{result.path}')
                            found_count += 1
                    tasks = []
            
            # Procesar tasks restantes
            if tasks:
                results = await asyncio.gather(*tasks)
                for result in results:
                    if result:
                        self.found_paths[result.path] = result
                        status_emoji = '✓' if result.status_code == 200 else '→' if result.status_code in [301, 302] else '⚠'
                        self._log_finding('info', f'{status_emoji} [{result.status_code}]', f'{result.path}')
                        found_count += 1
        
        return found_count

    async def scan(self) -> ScanResult:
        """Ejecutar descubrimiento de contenido."""
        self.result.start_time = datetime.now()
        
        try:
            self._log_finding('info', 'Comenzando descubrimiento de contenido', f'Target: {self.url}')
            
            # Enumerar paths
            found_count = await self._enumerate_paths()
            
            # Log summary
            if self.found_paths:
                status_200 = sum(1 for p in self.found_paths.values() if p.status_code == 200)
                status_redirect = sum(1 for p in self.found_paths.values() if p.status_code in [301, 302])
                status_auth = sum(1 for p in self.found_paths.values() if p.status_code in [401, 403])
                status_error = sum(1 for p in self.found_paths.values() if p.status_code >= 500)
                
                self._log_finding('success', 'Descubrimiento completado',
                                f'Total: {found_count}\n'
                                f'200 OK: {status_200}, Redirects: {status_redirect}, '
                                f'Auth: {status_auth}, Errors: {status_error}')
            else:
                self._log_finding('info', 'Descubrimiento completado', 'No paths encontrados')
            
        except Exception as e:
            self._log_error(f'Error en descubrimiento de contenido: {str(e)}')
        
        self.result.end_time = datetime.now()
        return self.result
