"""
Detección de servicios y fingerprinting.

Identifica servicios y versiones que corren en puertos abiertos.
Diseñado para evitar detección por WAF/IDS.

Técnicas:
1. Banner grabbing pasivo
2. HTTP header analysis
3. Respuesta a requests específicas
4. Timing analysis (timing da pistas)
"""

import asyncio
import socket
import re
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
import random

import aiohttp
from gokow.modules.base import BaseScanner, ScanResult
from gokow.utils.logger import logger
from gokow.utils.opsec import OPSECManager


@dataclass
class ServiceInfo:
    """Información de servicio detectado."""
    port: int
    protocol: str  # HTTP, SSH, FTP, etc.
    name: str
    version: Optional[str] = None
    product: Optional[str] = None
    confidence: int = 0  # 0-100


class ServiceDetectionScanner(BaseScanner):
    """
    Escáner de detección de servicios.
    
    Detecta qué servicios corren en puertos y sus versiones.
    Diseñado para ser sigiloso con WAF/IDS:
    - Minimal requests
    - Headers variados
    - Delays aleatorios
    - User-Agent rotation
    """

    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(target, config)
        
        self.config = config or {}
        self.ports = self._parse_ports(self.config.get('ports', '80,443,22,21,3306'))
        self.deep_scan = self.config.get('deep_scan', False)
        self.timeout = self.config.get('timeout', 5)
        self.services: Dict[int, ServiceInfo] = {}

    def _parse_ports(self, ports: str) -> List[int]:
        """Parsear puertos."""
        result = []
        for part in ports.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                result.extend(range(int(start), int(end) + 1))
            else:
                try:
                    result.append(int(part))
                except ValueError:
                    pass
        return sorted(list(set(result)))

    async def scan(self) -> ScanResult:
        """
        Ejecutar detección de servicios.
        
        Returns:
            ScanResult con servicios identificados
        """
        self.result.start_time = datetime.now()
        
        try:
            # Validar target
            if not self._validate_target():
                self._log_error("Target no válido para service detection")
                return self.result

            self._log_finding(
                "info",
                "Iniciando detección de servicios",
                f"Target: {self.target} | Puertos: {len(self.ports)} | Deep scan: {self.deep_scan}"
            )

            # Aplicar OPSEC
            await self._apply_opsec()

            # Detectar servicios
            await self._detect_services()

            # Log resultados
            self._log_results()

            self.result.end_time = datetime.now()
            return self.result

        except Exception as e:
            self._log_error(f"Error en service detection: {str(e)}")
            self.result.end_time = datetime.now()
            return self.result

    def _validate_target(self) -> bool:
        """Validar target."""
        try:
            import ipaddress
            ipaddress.IPv4Address(self.target)
            return True
        except ValueError:
            return False

    async def _detect_services(self):
        """Detectar servicios en puertos."""
        for port in self.ports:
            try:
                # Intentar HTTP primero (más probable)
                if await self._try_http(port):
                    continue
                
                # Luego otros protocolos
                await self._try_ssh(port)
                await self._try_ftp(port)
                await self._try_generic(port)
                
                # Delay para evitar WAF
                await asyncio.sleep(random.uniform(0.3, 0.8))
            
            except Exception as e:
                logger.debug(f"Error detecting service on {port}: {e}")

    async def _try_http(self, port: int) -> bool:
        """Detectar si es HTTP/HTTPS."""
        try:
            url = f"http://{self.target}:{port}/"
            
            # Headers realistas
            headers = {
                'User-Agent': self._get_user_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close',
            }
            
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(
                        url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False
                    ) as response:
                        # Análisis de headers
                        server_header = response.headers.get('Server', '')
                        power_by = response.headers.get('X-Powered-By', '')
                        
                        service_name = "HTTP"
                        version = None
                        product = server_header
                        
                        # Parsear Server header
                        if server_header:
                            service_name = f"HTTP ({server_header.split('/')[0]})"
                            if '/' in server_header:
                                version = server_header.split('/')[1].split()[0]
                        
                        if power_by:
                            service_name += f" [{power_by}]"
                        
                        self.services[port] = ServiceInfo(
                            port=port,
                            protocol='HTTP',
                            name=service_name,
                            version=version,
                            product=product,
                            confidence=90 if server_header else 70
                        )
                        
                        logger.debug(f"HTTP detected on {port}: {server_header}")
                        return True
                
                except asyncio.TimeoutError:
                    pass
                except Exception as e:
                    logger.debug(f"HTTP detection error on {port}: {e}")
        
        except Exception as e:
            logger.debug(f"HTTP attempt failed on {port}")
        
        return False

    async def _try_ssh(self, port: int) -> bool:
        """Detectar SSH."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, port),
                timeout=self.timeout
            )
            
            # Leer banner
            banner = await asyncio.wait_for(reader.read(1024), timeout=1)
            writer.close()
            await writer.wait_closed()
            
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            
            if 'SSH' in banner_str:
                # Parsear versión
                version = None
                match = re.search(r'SSH-(\d+\.\d+)', banner_str)
                if match:
                    version = match.group(1)
                
                self.services[port] = ServiceInfo(
                    port=port,
                    protocol='SSH',
                    name=banner_str.split('-')[0] if '-' in banner_str else 'SSH',
                    version=version,
                    product=banner_str,
                    confidence=95
                )
                
                logger.debug(f"SSH detected on {port}: {banner_str}")
                return True
        
        except (asyncio.TimeoutError, ConnectionRefusedError, Exception):
            pass
        
        return False

    async def _try_ftp(self, port: int) -> bool:
        """Detectar FTP."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, port),
                timeout=self.timeout
            )
            
            # Leer banner
            banner = await asyncio.wait_for(reader.read(1024), timeout=1)
            writer.close()
            await writer.wait_closed()
            
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            
            if '220' in banner_str:  # FTP response code
                version = None
                if 'vsftpd' in banner_str.lower():
                    version = re.search(r'vsftpd\s+([\d.]+)', banner_str, re.I)
                    if version:
                        version = version.group(1)
                
                self.services[port] = ServiceInfo(
                    port=port,
                    protocol='FTP',
                    name='FTP',
                    version=version,
                    product=banner_str,
                    confidence=95
                )
                
                logger.debug(f"FTP detected on {port}")
                return True
        
        except (asyncio.TimeoutError, ConnectionRefusedError, Exception):
            pass
        
        return False

    async def _try_generic(self, port: int):
        """Intentar detección genérica."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, port),
                timeout=self.timeout
            )
            
            banner = await asyncio.wait_for(reader.read(1024), timeout=1)
            writer.close()
            await writer.wait_closed()
            
            if banner and port not in self.services:
                banner_str = banner.decode('utf-8', errors='ignore').strip()
                
                self.services[port] = ServiceInfo(
                    port=port,
                    protocol='Unknown',
                    name='Unknown service',
                    product=banner_str[:100] if banner_str else None,
                    confidence=40
                )
                
                logger.debug(f"Generic service on {port}: {banner_str[:50]}")
        
        except (asyncio.TimeoutError, ConnectionRefusedError, Exception):
            pass

    def _get_user_agent(self) -> str:
        """Obtener User-Agent random."""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36',
        ]
        return random.choice(user_agents)

    def _log_results(self):
        """Log de resultados."""
        if not self.services:
            self._log_finding("warning", "Sin servicios detectados", "Verifica conectividad")
            return
        
        self._log_finding(
            "success",
            f"Servicios detectados: {len(self.services)}",
            " | ".join([f"{s.port}: {s.protocol}" for s in self.services.values()])
        )
        
        # Detalles
        for service in sorted(self.services.values(), key=lambda s: s.port):
            details = f"Protocolo: {service.protocol}"
            if service.version:
                details += f" | Versión: {service.version}"
            if service.product:
                details += f" | Producto: {service.product[:80]}"
            details += f" | Confianza: {service.confidence}%"
            
            self._log_finding("info", f"Puerto {service.port}: {service.name}", details)
