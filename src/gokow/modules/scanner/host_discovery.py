"""
Discovery pasivo de hosts en una red.

Implementa múltiples técnicas para detectar hosts activos con consideración
para WAF y proxies. Prioriza métodos pasivos y evasión de detección.

Técnicas:
1. ICMP Echo (ping) - Si se permite
2. ARP scan (local network)
3. TCP connect scan (puertos comunes)
4. Análisis de respuestas pasivas
"""

import asyncio
import ipaddress
from datetime import datetime
from typing import List, Set, Optional, Dict, Any
from dataclasses import dataclass, field
import socket

from gokow.modules.base import BaseScanner, ScanResult
from gokow.utils.opsec import OPSECManager
from gokow.utils.logger import logger

try:
    from scapy.all import ARP, Ether, srp, ICMP, IP, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    

@dataclass
class HostInfo:
    """Información de un host descubierto."""
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    detected_by: List[str] = field(default_factory=list)
    ports_open: List[int] = field(default_factory=list)
    os_hint: Optional[str] = None


class HostDiscoveryScanner(BaseScanner):
    """
    Escáner pasivo de descubrimiento de hosts.
    
    Detecta hosts activos en una red usando múltiples técnicas:
    - ICMP (ping)
    - ARP (broadcast local)
    - TCP SYN (puertos comunes)
    - Resolución de DNS
    """

    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(target, config)
        self.hosts: Dict[str, HostInfo] = {}
        self.techniques = config.get('techniques', ['icmp', 'arp', 'tcp']) if config else ['icmp', 'arp', 'tcp']
        self.timeout = config.get('timeout', 2) if config else 2
        self.common_ports = config.get('ports', [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080]) if config else [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080]

    async def scan(self) -> ScanResult:
        """
        Ejecutar discovery de hosts.
        
        Returns:
            ScanResult con hosts descubiertos
        """
        self.result.start_time = datetime.now()
        
        try:
            # Validar target
            network = self._parse_target()
            if not network:
                self._log_error("Target no es válida para host discovery")
                return self.result

            self._log_finding(
                "info",
                f"Iniciando descubrimiento en {network}",
                f"Técnicas: {', '.join(self.techniques)}"
            )

            # Aplicar OPSEC antes de escanear
            await self._apply_opsec()

            # Ejecutar técnicas de descubrimiento
            await self._run_discovery(network)

            # Log de resultados
            if self.hosts:
                self._log_finding(
                    "success",
                    f"Hosts descubiertos: {len(self.hosts)}",
                    self._format_hosts_summary()
                )

                # Detalles de cada host
                for ip, info in self.hosts.items():
                    self._log_finding(
                        "info",
                        f"Host: {ip}",
                        f"MAC: {info.mac or 'N/A'} | Detectado por: {', '.join(info.detected_by)} | Puertos: {', '.join(map(str, info.ports_open)) or 'N/A'}"
                    )
            else:
                self._log_finding(
                    "warning",
                    "Sin hosts descubiertos",
                    "Verifica conectividad o permisos de red"
                )

            self.result.end_time = datetime.now()
            return self.result

        except Exception as e:
            self._log_error(f"Error en host discovery: {str(e)}")
            self.result.end_time = datetime.now()
            return self.result

    def _parse_target(self) -> Optional[ipaddress.IPv4Network]:
        """Parsear target como red IP."""
        try:
            # Intentar CIDR
            if '/' in self.target:
                return ipaddress.IPv4Network(self.target, strict=False)
            
            # Intentar rango
            if '-' in self.target:
                parts = self.target.split('-')
                return ipaddress.IPv4Network(f"{parts[0]}/32")
            
            # IP simple
            ip = ipaddress.IPv4Address(self.target)
            return ipaddress.IPv4Network(f"{ip}/32")
        except ValueError:
            return None

    async def _run_discovery(self, network: ipaddress.IPv4Network):
        """Ejecutar técnicas de descubrimiento."""
        # ICMP (si está en config)
        if 'icmp' in self.techniques and SCAPY_AVAILABLE:
            await self._icmp_discovery(network)
            await self._apply_opsec()  # Delay entre técnicas

        # ARP (solo para local network)
        if 'arp' in self.techniques and network.prefixlen >= 24 and SCAPY_AVAILABLE:
            await self._arp_discovery(network)
            await self._apply_opsec()

        # TCP Connect (puertos comunes)
        if 'tcp' in self.techniques:
            await self._tcp_discovery(network)

    async def _icmp_discovery(self, network: ipaddress.IPv4Network):
        """Descubrimiento por ICMP (ping)."""
        logger.info(f"ICMP scan: {network}")
        
        try:
            for ip in list(network.hosts())[:network.num_addresses]:  # Limitar para WAF
                if ip == network.network_address or ip == network.broadcast_address:
                    continue

                try:
                    # Crear paquete ICMP
                    packet = IP(dst=str(ip)) / ICMP()
                    response = sr1(packet, timeout=self.timeout, verbose=False)
                    
                    if response:
                        self._register_host(str(ip), "ICMP")
                        
                except Exception:
                    pass

                # Pequeño delay para evitar rate limiting
                await asyncio.sleep(0.1)

        except Exception as e:
            logger.warning(f"ICMP discovery error: {e}")

    async def _arp_discovery(self, network: ipaddress.IPv4Network):
        """Descubrimiento por ARP (solo local)."""
        logger.info(f"ARP scan: {network}")
        
        try:
            answered, unanswered = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
                timeout=self.timeout,
                verbose=False
            )

            for send, recv in answered:
                ip = recv[ARP].psrc
                mac = recv[ARP].hwsrc
                self._register_host(ip, "ARP", mac)
                await asyncio.sleep(0.05)

        except Exception as e:
            logger.warning(f"ARP discovery error: {e}")

    async def _tcp_discovery(self, network: ipaddress.IPv4Network):
        """Descubrimiento por TCP connect (con considración para WAF)."""
        logger.info(f"TCP scan: {network}")
        
        ips = list(network.hosts())[:min(256, network.num_addresses)]
        
        for ip in ips:
            for port in self.common_ports:
                try:
                    # Socket timeout corto
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((str(ip), port))
                    sock.close()
                    
                    if result == 0:
                        self._register_host(str(ip), "TCP", port=port)
                        logger.debug(f"Port {port} open on {ip}")
                    
                    await asyncio.sleep(0.05)  # Rate limiting
                    
                except Exception:
                    pass

    def _register_host(self, ip: str, method: str, mac: Optional[str] = None, port: Optional[int] = None):
        """Registrar un host descubierto."""
        if ip not in self.hosts:
            self.hosts[ip] = HostInfo(ip=ip, mac=mac)
        
        if method not in self.hosts[ip].detected_by:
            self.hosts[ip].detected_by.append(method)
        
        if port and port not in self.hosts[ip].ports_open:
            self.hosts[ip].ports_open.append(port)
            self.hosts[ip].ports_open.sort()

    def _format_hosts_summary(self) -> str:
        """Formatear resumen de hosts."""
        by_method = {}
        for host in self.hosts.values():
            for method in host.detected_by:
                by_method[method] = by_method.get(method, 0) + 1
        
        return " | ".join([f"{m}: {c}" for m, c in by_method.items()])
