"""
Fingerprinting Web - Detección de tecnologías y servidores.

Detecta:
- Servidor web (Apache, Nginx, IIS, etc)
- CMS (WordPress, Drupal, Joomla, etc)
- Frameworks (Laravel, Django, Flask, etc)
- Versiones de software
- Etiquetas meta
- Headers de seguridad

Técnicas de evasión:
- Múltiples User-Agents
- Headers normalizados
- Delays entre requests
- Análisis profundo (no solo headers)
"""

import asyncio
import aiohttp
from datetime import datetime
from typing import Optional, Dict, Any, List, Set, Tuple
from dataclasses import dataclass
import re
import socket

from gokow.modules.base import BaseScanner, ScanResult
from gokow.utils.logger import logger


@dataclass
class TechnologyDetected:
    """Tecnología detectada."""
    name: str
    version: Optional[str] = None
    type: str = 'unknown'  # server, cms, framework, language, etc
    confidence: float = 0.7


class WebFingerprintingScanner(BaseScanner):
    """
    Escáner de fingerprinting web.
    
    Detecta tecnologías en un servidor web:
    - Servidor web
    - CMS/Plataformas
    - Lenguajes de programación
    - Frameworks
    - Versions
    
    Muy útil para identificar aplicaciones vulnerables.
    """

    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(target, config)
        
        self.config = config or {}
        self.timeout = self.config.get('timeout', 5)
        self.url = self._normalize_url()
        self.technologies: Dict[str, TechnologyDetected] = {}
        self.headers: Dict[str, str] = {}
        self.status_code: Optional[int] = None

    def _normalize_url(self) -> str:
        """Normalizar target a URL válida."""
        target = self.target.strip()
        
        # Si no tiene protocolo, agregar http://
        if not target.startswith('http://') and not target.startswith('https://'):
            target = f'http://{target}'
        
        # Si es solo dominio, agregar /
        if target.count('/') == 2:  # solo http://domain.com
            target += '/'
        
        return target

    async def _fetch_page(self) -> Tuple[Optional[str], Optional[Dict[str, str]], Optional[int]]:
        """Obtener página y headers."""
        try:
            async with aiohttp.ClientSession() as session:
                await self._apply_opsec()  # OPSEC: delay
                
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                
                async with session.get(self.url, headers=headers, 
                                     timeout=self.timeout, allow_redirects=True) as resp:
                    content = await resp.text()
                    return content, dict(resp.headers), resp.status
                    
        except Exception as e:
            self._log_error(f'Error fetching page: {str(e)}')
            return None, None, None

    def _detect_from_headers(self, headers: Dict[str, str]) -> None:
        """Detectar tecnologías desde headers HTTP."""
        header_map = {
            'server': ('Server', 'server'),
            'x-powered-by': ('X-Powered-By', 'x-powered-by'),
            'x-aspnet-version': ('X-AspNet-Version', 'x-aspnet-version'),
            'x-runtime': ('X-Runtime', 'x-runtime'),
            'x-ua-compatible': ('X-UA-Compatible', 'x-ua-compatible'),
        }
        
        for key, header_keys in header_map.items():
            for header_key in header_keys:
                if header_key in headers:
                    value = headers[header_key]
                    self.headers[header_key] = value
                    
                    # Parse servidores comunes
                    if 'server' in key.lower():
                        tech = self._parse_server_header(value)
                        if tech:
                            self.technologies[tech.name] = tech
                    else:
                        # Otros headers
                        tech = TechnologyDetected(name=value, type='framework', confidence=0.8)
                        self.technologies[value] = tech

    def _parse_server_header(self, server_header: str) -> Optional[TechnologyDetected]:
        """Parse el header Server."""
        server_header = server_header.strip()
        
        # Apache
        if 'Apache' in server_header:
            match = re.search(r'Apache/([0-9.]+)', server_header)
            return TechnologyDetected(
                name='Apache',
                version=match.group(1) if match else None,
                type='server',
                confidence=0.95
            )
        
        # Nginx
        elif 'nginx' in server_header.lower():
            match = re.search(r'nginx/([0-9.]+)', server_header)
            return TechnologyDetected(
                name='Nginx',
                version=match.group(1) if match else None,
                type='server',
                confidence=0.95
            )
        
        # IIS
        elif 'IIS' in server_header or 'Microsoft' in server_header:
            match = re.search(r'IIS/([0-9.]+)', server_header)
            return TechnologyDetected(
                name='IIS',
                version=match.group(1) if match else None,
                type='server',
                confidence=0.95
            )
        
        # LiteSpeed
        elif 'LiteSpeed' in server_header:
            match = re.search(r'LiteSpeed/([0-9.]+)', server_header)
            return TechnologyDetected(
                name='LiteSpeed',
                version=match.group(1) if match else None,
                type='server',
                confidence=0.95
            )
        
        # Otros
        else:
            return TechnologyDetected(
                name=server_header.split('/')[0],
                version=server_header.split('/')[-1] if '/' in server_header else None,
                type='server',
                confidence=0.7
            )

    def _detect_from_html(self, html: str) -> None:
        """Detectar tecnologías desde HTML."""
        if not html:
            return
        
        # WordPress
        if 'wp-content' in html or 'wp-includes' in html:
            match = re.search(r'wp_version\.version = "([^"]+)"', html)
            self.technologies['WordPress'] = TechnologyDetected(
                name='WordPress',
                version=match.group(1) if match else None,
                type='cms',
                confidence=0.95
            )
        
        # Drupal
        if 'drupal' in html.lower():
            self.technologies['Drupal'] = TechnologyDetected(
                name='Drupal',
                type='cms',
                confidence=0.8
            )
        
        # Joomla
        if 'joomla' in html.lower() or 'com_' in html.lower():
            self.technologies['Joomla'] = TechnologyDetected(
                name='Joomla',
                type='cms',
                confidence=0.8
            )
        
        # META tags
        meta_tags = re.findall(r'<meta name="([^"]+)" content="([^"]+)"', html, re.IGNORECASE)
        for name, content in meta_tags:
            if 'generator' in name.lower():
                self.technologies[content] = TechnologyDetected(
                    name=content,
                    type='generator',
                    confidence=0.9
                )
        
        # Form action patterns
        if '<form' in html:
            if '/wp-login' in html or 'wp-submit' in html:
                self.technologies['WordPress'] = TechnologyDetected(
                    name='WordPress',
                    type='cms',
                    confidence=0.9
                )

    def _detect_common_paths(self, html: str) -> None:
        """Detectar tecnologías desde paths comunes."""
        paths = [
            ('WordPress', '/wp-admin/', '/wp-includes/'),
            ('Drupal', '/sites/all/', '/modules/'),
            ('Joomla', 'com_', 'administrator/'),
            ('Magento', '/skin/frontend/', '/media/catalog/'),
            ('Prestashop', '/prestashop/', '/modules/'),
            ('OpenCart', '/catalog/view/', '/admin/'),
        ]
        
        for cms, *patterns in paths:
            for pattern in patterns:
                if pattern in html:
                    if cms not in self.technologies:
                        self.technologies[cms] = TechnologyDetected(
                            name=cms,
                            type='cms',
                            confidence=0.8
                        )

    async def scan(self) -> ScanResult:
        """Ejecutar fingerprinting web."""
        self.result.start_time = datetime.now()
        
        try:
            self._log_finding('info', 'Começando fingerprinting web', f'Target: {self.url}')
            
            # Obtener página
            html, headers, status = await self._fetch_page()
            
            if not html or not headers:
                self._log_error('No se pudo acceder a la página')
                self.result.end_time = datetime.now()
                return self.result
            
            self.status_code = status
            
            # Detectar desde headers
            self._detect_from_headers(headers)
            
            # Detectar desde HTML
            self._detect_from_html(html)
            
            # Detectar desde paths comunes
            self._detect_common_paths(html)
            
            # Log results
            if self.technologies:
                for tech_name, tech in self.technologies.items():
                    version_str = f" v{tech.version}" if tech.version else ""
                    confidence_str = f" (confianza: {tech.confidence*100:.0f}%)"
                    self._log_finding('success', f'Tecnología detectada: {tech.name}', 
                                    f'{tech.type}{version_str}{confidence_str}')
            
            # Summary
            self._log_finding('info', 'Fingerprinting completado', 
                            f'Total: {len(self.technologies)} tecnologías detectadas')
            
        except Exception as e:
            self._log_error(f'Error en fingerprinting: {str(e)}')
        
        self.result.end_time = datetime.now()
        return self.result
