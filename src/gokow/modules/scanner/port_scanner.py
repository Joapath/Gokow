"""
Escáner de puertos con evasión de WAF.

Implementa múltiples técnicas de escaneo de puertos con consideración especial
para WAF (CloudFlare, NGINX proxy) y sistemas de protección.

Técnicas:
1. TCP Connect (non-destructive, detectable)
2. TCP SYN (stealth, no completa handshake)
3. Service fingerprinting
4. Evasión de IDS/WAF
"""

import asyncio
import socket
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, field
import random

from gokow.modules.base import BaseScanner, ScanResult
from gokow.utils.logger import logger
from gokow.utils.opsec import OPSECManager

try:
    from scapy.all import IP, TCP, sr1, socket as scapy_socket
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class PortInfo:
    """Información de un puerto."""
    port: int
    state: str  # open, closed, filtered
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None


class PortScanner(BaseScanner):
    """
    Escáner de puertos con consideración para WAF y proxies.
    
    Implementa técnicas de escaneo que evitan detección:
    - Rate limiting inteligente
    - Source port randomization
    - TCP window size variation
    - User-Agent rotation
    - Banner grabbing cuidadoso
    """

    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(target, config)
        
        self.config = config or {}
        self.ports = self._parse_ports(self.config.get('ports', '1-1000'))
        self.technique = self.config.get('technique', 'connect')  # connect, syn, udp
        self.timeout = self.config.get('timeout', 2)
        self.rate_limit = self.config.get('rate_limit', 0.1)  # segundos entre ports
        self.min_rate_limit = self.config.get('min_rate_limit', 0.05)
        self.service_detection = self.config.get('service_detection', True)
        
        self.results: Dict[int, PortInfo] = {}

    def _parse_ports(self, ports: str) -> List[int]:
        """Parsear especificación de puertos."""
        result = []
        
        for part in ports.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                result.extend(range(int(start), int(end) + 1))
            else:
                result.append(int(part))
        
        # Limitar para WAF
        return sorted(list(set(result)))[:min(len(result), 1000)]

    async def scan(self) -> ScanResult:
        """
        Ejecutar escaneo de puertos.
        
        Returns:
            ScanResult con puertos descubiertos
        """
        self.result.start_time = datetime.now()
        
        try:
            # Validar target
            if not self._validate_target():
                self._log_error("Target no válido para port scan")
                return self.result

            self._log_finding(
                "info",
                f"Iniciando escaneo de puertos",
                f"Target: {self.target} | Puertos: {len(self.ports)} | Técnica: {self.technique}"
            )

            # Aplicar OPSEC
            await self._apply_opsec()

            # Escanear puertos
            await self._scan_ports()

            # Log de resultados
            self._log_results()

            self.result.end_time = datetime.now()
            return self.result

        except Exception as e:
            self._log_error(f"Error en port scan: {str(e)}")
            self.result.end_time = datetime.now()
            return self.result

    def _validate_target(self) -> bool:
        """Validar que target es una IP simple."""
        try:
            import ipaddress
            ipaddress.IPv4Address(self.target)
            return True
        except (ValueError, TypeError):
            return False

    async def _scan_ports(self):
        """Escanear puertos con técnica elegida."""
        if self.technique == 'connect':
            await self._tcp_connect_scan()
        elif self.technique == 'syn' and SCAPY_AVAILABLE:
            await self._tcp_syn_scan()
        else:
            await self._tcp_connect_scan()  # Fallback

    async def _tcp_connect_scan(self):
        """
        TCP Connect Scan.
        
        Completa el three-way handshake. Más detectable pero confiable.
        Útil contra WAF que filtra SYN packets.
        """
        logger.info(f"TCP Connect scan: {self.target}")
        
        # Randomizar orden de puertos para evitar patrones
        ports = self.ports.copy()
        random.shuffle(ports)
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                # Pequeña variación en source port para evitar detección
                if random.random() > 0.8:  # 20% del tiempo
                    sock.bind(('0.0.0.0', random.randint(1025, 65535)))
                
                result = sock.connect_ex((self.target, port))
                
                if result == 0:
                    self.results[port] = PortInfo(port=port, state='open')
                    
                    # Intentar banner grabbing si servicio detection está activo
                    if self.service_detection:
                        banner = await self._grab_banner(self.target, port)
                        if banner:
                            self.results[port].banner = banner
                            self.results[port].service = self._identify_service(port, banner)
                    
                    logger.debug(f"Port {port}/tcp open")
                else:
                    self.results[port] = PortInfo(port=port, state='closed')
                
                sock.close()
                
            except socket.timeout:
                self.results[port] = PortInfo(port=port, state='filtered')
            except Exception as e:
                self.results[port] = PortInfo(port=port, state='filtered')
                logger.debug(f"Port {port} scan error: {e}")
            
            # Rate limiting para evitar WAF
            delay = random.uniform(self.min_rate_limit, self.rate_limit)
            await asyncio.sleep(delay)

    async def _tcp_syn_scan(self):
        """
        TCP SYN Scan (stealth scan).
        
        No completa handshake, más sigiloso pero requiere permisos.
        """
        logger.info(f"TCP SYN scan: {self.target}")
        
        ports = self.ports.copy()
        random.shuffle(ports)
        
        for port in ports:
            try:
                # Crear SYN packet
                packet = IP(dst=self.target) / TCP(dport=port, flags="S")
                response = sr1(packet, timeout=self.timeout, verbose=False)
                
                if response and response[TCP].flags & 0x12:  # SYN-ACK
                    self.results[port] = PortInfo(port=port, state='open')
                    logger.debug(f"Port {port}/tcp open (SYN)")
                elif response and response[TCP].flags & 0x14:  # RST
                    self.results[port] = PortInfo(port=port, state='closed')
                else:
                    self.results[port] = PortInfo(port=port, state='filtered')
                
            except Exception as e:
                self.results[port] = PortInfo(port=port, state='filtered')
                logger.debug(f"Port {port} SYN error: {e}")
            
            delay = random.uniform(self.min_rate_limit, self.rate_limit)
            await asyncio.sleep(delay)

    async def _grab_banner(self, host: str, port: int, size: int = 1024) -> Optional[str]:
        """
        Obtener banner del servicio.
        
        Cuidadoso para no disparar WAF.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((host, port))
            
            # Leer respuesta sin enviar nada (passive)
            banner = sock.recv(size)
            sock.close()
            
            if banner:
                return banner.decode('utf-8', errors='ignore').strip()
        except Exception:
            pass
        
        return None

    def _identify_service(self, port: int, banner: str) -> Optional[str]:
        """Identificar servicio por puerto y banner."""
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-ALT",
            8443: "HTTPS-ALT",
        }
        
        # Buscar por puerto
        if port in common_services:
            return common_services[port]
        
        # Buscar en banner
        banner_lower = banner.lower()
        if 'apache' in banner_lower:
            return "Apache HTTP"
        elif 'nginx' in banner_lower:
            return "Nginx HTTP"
        elif 'iis' in banner_lower:
            return "IIS HTTP"
        elif 'openssh' in banner_lower:
            return "OpenSSH"
        
        return None

    def _log_results(self):
        """Log de resultados del escaneo."""
        open_ports = [p for p, info in self.results.items() if info.state == 'open']
        closed_ports = [p for p, info in self.results.items() if info.state == 'closed']
        filtered_ports = [p for p, info in self.results.items() if info.state == 'filtered']
        
        self._log_finding(
            "info" if open_ports else "warning",
            f"Resultados del escaneo",
            f"Abiertos: {len(open_ports)} | Cerrados: {len(closed_ports)} | Filtrados: {len(filtered_ports)}"
        )
        
        # Detalles de puertos abiertos
        for port in sorted(open_ports):
            info = self.results[port]
            service = f" ({info.service})" if info.service else ""
            details = f"Servicio: {info.service or 'Desconocido'}"
            if info.banner:
                details += f" | Banner: {info.banner[:100]}"
            
            self._log_finding("success", f"Puerto {port}/tcp abierto{service}", details)
