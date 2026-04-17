"""
Enumeración de Subdominios.

Implementa múltiples técnicas para descubrir subdominios:
- DNS brute-force con wordlist
- Certificate Transparency (CT logs)
- Passive DNS queries
- CNAME detection

Resistencia WAF:
- Rate limiting 0.1-0.2s entre requests
- User-Agent rotation
- Múltiples sources DNS
- Minimal footprint en logs
"""

import asyncio
import dns.resolver
import dns.exception
import aiohttp
from datetime import datetime
from typing import Optional, Dict, Any, List, Set, Tuple
from dataclasses import dataclass
import socket

from gokow.modules.base import BaseScanner, ScanResult
from gokow.utils.logger import logger


@dataclass
class SubdomainFound:
    """Subdominio descubierto."""
    name: str
    source: str  # dns-brute, ct-logs, passive, cname
    ip: Optional[str] = None
    cname: Optional[str] = None
    confidence: float = 0.8


class SubdomainEnumerationScanner(BaseScanner):
    """
    Escáner de enumeración de subdominios.
    
    Descubre subdominios usando múltiples técnicas:
    - Brute-force contra wordlist
    - Certificate Transparency logs
    - CNAME enumeration
    - DNS queries pasivas
    
    Ventaja de multicanal: Si un método es bloqueado, otros aún funcionan.
    """

    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(target, config)
        
        self.config = config or {}
        self.timeout = self.config.get('timeout', 10)
        self.wordlist = self.config.get('wordlist', self._default_wordlist())
        self.found_subdomains: Set[str] = set()
        self.subdomain_data: Dict[str, SubdomainFound] = {}
        
        # Extraer dominio del target
        self.domain = self._extract_domain()
        if not self.domain:
            raise ValueError(f"No se pudo extraer dominio de {self.target}")

    def _extract_domain(self) -> Optional[str]:
        """Extraer dominio del target."""
        target = self.target.lower().strip()
        
        # Si es URL, extraer dominio
        if '://' in target:
            target = target.split('://')[1]
        
        # Remover puerto
        if ':' in target:
            target = target.split(':')[0]
        
        # Remover path
        if '/' in target:
            target = target.split('/')[0]
        
        # Validar que es un dominio (no IP)
        try:
            socket.inet_aton(target)
            return None
        except socket.error:
            return target

    def _default_wordlist(self) -> List[str]:
        """Wordlist por defecto para brute-force."""
        return [
            'www', 'mail', 'ftp', 'api', 'admin', 'app', 'blog',
            'dev', 'test', 'staging', 'prod', 'production',
            'backend', 'frontend', 'db', 'database', 'cdn',
            'assets', 'static', 'media', 'mobile', 'desktop',
            'internal', 'private', 'secure', 'vpn', 'ssh',
            'config', 'backup', 'archive', 'old', 'new',
            'v1', 'v2', 'api-v1', 'api-v2', 'beta', 'alpha',
            'mail', 'smtp', 'imap', 'ns1', 'ns2', 'mx1', 'mx2',
            'ns', 'mx', 'pop', 'smtp', 'mail1', 'mail2',
            'webmail', 'cpanel', 'plesk', 'whm', 'autodiscover',
            'autoconfig', 'xmpp', 'sip', 'jabber',
            'search', 'help', 'status', 'support', 'login',
            'accounts', 'auth', 'oauth', 'oidc', 'sso',
            'git', 'gitlab', 'github', 'bitbucket', 'jenkins',
            'sonarqube', 'grafana', 'prometheus', 'kibana', 'elastic',
            'redis', 'memcache', 'mongo', 'postgres', 'mysql',
        ]

    async def _dns_brute_force(self) -> int:
        """Brute-force de subdominios contra wordlist."""
        found_count = 0
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        
        for subdomain in self.wordlist:
            await self._apply_opsec()  # OPSEC: delay entre requests
            
            full_name = f"{subdomain}.{self.domain}"
            
            try:
                # Intenta resolver A record
                answers = resolver.resolve(full_name, 'A', tcp=False)
                
                for rdata in answers:
                    ip = str(rdata)
                    self.found_subdomains.add(full_name)
                    self.subdomain_data[full_name] = SubdomainFound(
                        name=full_name,
                        source='dns-brute',
                        ip=ip,
                        confidence=0.95
                    )
                    self._log_finding('info', f'Subdominio encontrado', f'{full_name} → {ip}')
                    found_count += 1
                    
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
            except Exception as e:
                self._log_error(f'Error en brute-force: {str(e)}')
        
        return found_count

    async def _cname_enumeration(self) -> int:
        """Enumera CNAMEs para encontrar subdominios ocultos."""
        found_count = 0
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        
        # Intenta encontrar wildcard y luego CNAMEs
        for subdomain in ['random-test-' + str(asyncio.get_event_loop().time())[:10], 'test']:
            await self._apply_opsec()
            full_name = f"{subdomain}.{self.domain}"
            
            try:
                answers = resolver.resolve(full_name, 'CNAME', tcp=False)
                for rdata in answers:
                    cname = str(rdata)
                    self.subdomain_data[cname] = SubdomainFound(
                        name=full_name,
                        source='cname',
                        cname=cname,
                        confidence=0.8
                    )
                    self._log_finding('info', f'CNAME descubierto', f'{full_name} → {cname}')
                    found_count += 1
                    
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
            except Exception:
                pass
        
        return found_count

    async def _certificate_transparency(self) -> int:
        """Busca en Certificate Transparency logs (pasivo, sin WAF)."""
        found_count = 0
        
        # Usando crt.sh (Certificate Transparency search)
        url = f"https://crt.sh/?q={self.domain}&output=json"
        
        try:
            async with aiohttp.ClientSession() as session:
                await self._apply_opsec()
                
                as_headers = {
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
                }
                
                async with session.get(url, headers=as_headers, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            
                            # Parsear name_value (puede tener múltiples nombres)
                            for name in name_value.split('\n'):
                                name = name.strip()
                                if name and self.domain in name and name not in self.found_subdomains:
                                    # Validar que es un subdominio (no IP)
                                    if not name.replace('.', '').isdigit():
                                        self.found_subdomains.add(name)
                                        self.subdomain_data[name] = SubdomainFound(
                                            name=name,
                                            source='ct-logs',
                                            confidence=0.9
                                        )
                                        self._log_finding('info', f'CT Log descubierto', f'{name}')
                                        found_count += 1
        except Exception as e:
            self._log_error(f'Error en CT logs: {str(e)}')
        
        return found_count

    async def scan(self) -> ScanResult:
        """Ejecutar escaneo de subdominios."""
        self.result.start_time = datetime.now()
        
        try:
            self._log_finding('info', 'Comenzando enumeración de subdominios', f'Target: {self.domain}')
            
            # Técnica 1: DNS brute-force
            count1 = await self._dns_brute_force()
            
            # Técnica 2: CNAME enumeration
            count2 = await self._cname_enumeration()
            
            # Técnica 3: Certificate Transparency
            count3 = await self._certificate_transparency()
            
            total_found = count1 + count2 + count3
            
            # Log summary
            self._log_finding('success', 'Enumeración completada', 
                            f'Total: {len(self.found_subdomains)} subdominios únicos\n'
                            f'DNS Brute-force: {count1}, CNAME: {count2}, CT: {count3}')
            
            # Agregar lista completa
            if self.found_subdomains:
                subdomain_list = '\n'.join(sorted(self.found_subdomains))
                self._log_finding('info', 'Subdominios descubiertos', subdomain_list)
            
        except Exception as e:
            self._log_error(f'Error en enumeración de subdominios: {str(e)}')
        
        self.result.end_time = datetime.now()
        return self.result
