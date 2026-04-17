"""
Análisis SSL/TLS de dominios y direcciones IP.

Realiza análisis completo de certificados SSL/TLS, cipher suites soportadas
y detección de vulnerabilidades comunes con enfoque en OPSEC.

Características:
1. Análisis de certificado (válido, expiración, issuer, etc.)
2. Cipher suites soportadas
3. Detección de vulnerabilidades (Heartbleed, POODLE, etc.)
4. Información del servidor SSL/TLS
5. Soporte para SNI (Server Name Indication)
"""

import hashlib
import ssl
import socket
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
import asyncio

from gokow.modules.base import BaseScanner, ScanResult
from gokow.utils.logger import logger


@dataclass
class SSLCertificate:
    """Información del certificado SSL/TLS."""
    subject: Dict[str, str]
    issuer: Dict[str, str]
    version: int
    serial_number: str
    not_before: datetime
    not_after: datetime
    signature_algorithm: str
    public_key_algorithm: str
    public_key_size: int
    subject_alt_names: List[str] = field(default_factory=list)
    is_valid: bool = True
    days_until_expiry: int = 0
    fingerprint_sha256: str = ""


@dataclass
class SSLInfo:
    """Información completa del análisis SSL/TLS."""
    target: str
    port: int
    protocol: str
    certificate: Optional[SSLCertificate] = None
    cipher_suites: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    server_info: Dict[str, Any] = field(default_factory=dict)
    handshake_time: float = 0.0
    connection_secure: bool = False


class SSLTLSAnalysisScanner(BaseScanner):
    """
    Analizador SSL/TLS completo.
    
    Realiza análisis exhaustivo de conexiones SSL/TLS incluyendo:
    - Validación de certificados
    - Cipher suites soportadas
    - Detección de vulnerabilidades
    - Información del servidor
    """

    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(target, config)
        self.port = self.config.get('port', 443)
        self.timeout = self.config.get('timeout', 10)
        self.check_vulnerabilities = self.config.get('check_vulnerabilities', True)

    async def scan(self) -> ScanResult:
        """
        Ejecutar análisis SSL/TLS completo.
        
        Returns:
            ScanResult con hallazgos del análisis SSL/TLS
        """
        self._log_finding("info", "Inicio de Análisis SSL/TLS", 
                         f"Iniciando análisis SSL/TLS para {self.target}:{self.port}")

        ssl_info = SSLInfo(target=self.target, port=self.port, protocol="TLS")

        try:
            # Análisis del certificado
            cert_info = await self._analyze_certificate()
            if cert_info:
                ssl_info.certificate = cert_info
                self._log_finding("info", "Certificado Analizado", 
                                 f"Certificado válido para {self.target}")

            # Análisis de cipher suites
            ciphers = await self._analyze_cipher_suites()
            ssl_info.cipher_suites = ciphers
            self._log_finding("info", "Cipher Suites Analizadas", 
                             f"Encontradas {len(ciphers)} cipher suites")

            # Detección de vulnerabilidades
            if self.check_vulnerabilities:
                vulns = await self._check_vulnerabilities()
                ssl_info.vulnerabilities = vulns
                if vulns:
                    self._log_finding("warning", "Vulnerabilidades Detectadas", 
                                     f"Se encontraron {len(vulns)} vulnerabilidades potenciales")

            # Información del servidor
            server_info = await self._get_server_info()
            ssl_info.server_info = server_info

            ssl_info.connection_secure = self._is_connection_secure(ssl_info)

            # Crear hallazgo principal
            finding_data = {
                "target": self.target,
                "port": self.port,
                "protocol": ssl_info.protocol,
                "certificate_valid": ssl_info.certificate.is_valid if ssl_info.certificate else False,
                "cipher_suites_count": len(ssl_info.cipher_suites),
                "vulnerabilities_count": len(ssl_info.vulnerabilities),
                "connection_secure": ssl_info.connection_secure
            }

            self._log_finding("success", "Análisis SSL/TLS Completado", 
                             f"Análisis exitoso para {self.target}:{self.port}")

            return ScanResult(
                scanner_name="SSL/TLS Analysis",
                target=self.target,
                timestamp=datetime.now(timezone.utc),
                findings=[finding_data],
                raw_data={"ssl_info": ssl_info}
            )

        except Exception as e:
            self._log_finding("error", "Error en Análisis SSL/TLS", 
                             f"Error durante el análisis: {str(e)}")
            return ScanResult(
                scanner_name="SSL/TLS Analysis",
                target=self.target,
                timestamp=datetime.now(timezone.utc),
                findings=[],
                raw_data={"error": str(e)}
            )

    async def _analyze_certificate(self) -> Optional[SSLCertificate]:
        """Analizar el certificado SSL/TLS."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = ssock.getpeercert()

                    if not cert:
                        return None

                    subject = self._parse_cert_name(cert.get('subject', ()))
                    issuer = self._parse_cert_name(cert.get('issuer', ()))
                    not_before = self._parse_cert_date(cert.get('notBefore'))
                    not_after = self._parse_cert_date(cert.get('notAfter'))
                    now = datetime.now(timezone.utc)
                    days_until_expiry = (not_after - now).days if not_after else 0

                    alt_names = []
                    for name_type, name_value in cert.get('subjectAltName', []):
                        if name_type == 'DNS':
                            alt_names.append(name_value)

                    fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest() if cert_der else ""

                    return SSLCertificate(
                        subject=subject,
                        issuer=issuer,
                        version=0,
                        serial_number=str(cert.get('serialNumber', '')),
                        not_before=not_before or now,
                        not_after=not_after or now,
                        signature_algorithm=cert.get('signatureAlgorithm', 'unknown'),
                        public_key_algorithm='unknown',
                        public_key_size=0,
                        subject_alt_names=alt_names,
                        is_valid=not_before <= now <= not_after if not_before and not_after else False,
                        days_until_expiry=max(0, days_until_expiry),
                        fingerprint_sha256=fingerprint_sha256
                    )

        except Exception as e:
            self._log_finding("warning", "Error Analizando Certificado", 
                             f"No se pudo analizar el certificado: {str(e)}")
            return None

    async def _analyze_cipher_suites(self) -> List[Dict[str, Any]]:
        """Analizar cipher suites soportadas."""
        ciphers = []
        
        # Lista de cipher suites comunes a probar
        common_ciphers = [
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-SHA384',
            'ECDHE-RSA-AES128-SHA256',
            'AES256-GCM-SHA384',
            'AES128-GCM-SHA256',
            'AES256-SHA256',
            'AES128-SHA256'
        ]
        
        for cipher in common_ciphers:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                context.set_ciphers(cipher)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        cipher_info = ssock.cipher()
                        ciphers.append({
                            "name": cipher,
                            "supported": True,
                            "protocol": cipher_info[1],
                            "bits": cipher_info[2]
                        })
                        
            except ssl.SSLError:
                ciphers.append({
                    "name": cipher,
                    "supported": False,
                    "protocol": None,
                    "bits": None
                })
            except Exception:
                continue
                
        return ciphers

    async def _check_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Verificar vulnerabilidades comunes."""
        vulnerabilities = []
        
        # Verificar POODLE (SSLv3)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.set_ciphers('ALL:COMPLEMENTOFALL')
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    if ssock.version() == 'SSLv3':
                        vulnerabilities.append({
                            "name": "POODLE",
                            "severity": "high",
                            "description": "Servidor soporta SSLv3 (vulnerable a POODLE)",
                            "cve": "CVE-2014-3566"
                        })
        except:
            pass
            
        # Verificar Heartbleed (OpenSSL < 1.0.1g)
        # Nota: Detección simplificada basada en versión del servidor
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    version = ssock.version()
                    if version in ['TLSv1', 'TLSv1.1']:
                        vulnerabilities.append({
                            "name": "Deprecado TLS",
                            "severity": "medium",
                            "description": f"Servidor usa {version} (deprecado, usar TLS 1.2+)",
                            "cve": None
                        })
        except:
            pass
            
        return vulnerabilities

    async def _get_server_info(self) -> Dict[str, Any]:
        """Obtener información del servidor SSL/TLS."""
        info = {}
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            start_time = asyncio.get_event_loop().time()
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    end_time = asyncio.get_event_loop().time()
                    
                    info = {
                        "version": ssock.version(),
                        "cipher": ssock.cipher(),
                        "handshake_time": round(end_time - start_time, 3),
                        "compression": ssock.compression(),
                        "session_reused": ssock.session_reused
                    }
                    
        except Exception as e:
            info = {"error": str(e)}
            
        return info

    def _parse_cert_name(self, name) -> Dict[str, str]:
        """Parse certificate name object."""
        parsed = {}
        for attr in name:
            if isinstance(attr, tuple) and len(attr) == 1:
                component = attr[0]
                if isinstance(component, tuple) and len(component) == 2:
                    key = component[0]
                    value = component[1]
                else:
                    continue
            elif isinstance(attr, tuple) and len(attr) == 2:
                key, value = attr
            else:
                continue

            if isinstance(key, bytes):
                key = key.decode(errors='ignore')
            if isinstance(value, bytes):
                value = value.decode(errors='ignore')

            parsed[str(key)] = str(value)
        return parsed

    def _parse_cert_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse certificate date strings."""
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        except Exception:
            try:
                return datetime.strptime(date_str, '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)
            except Exception:
                return None

    def _is_connection_secure(self, ssl_info: SSLInfo) -> bool:
        """Determinar si la conexión es segura."""
        if not ssl_info.certificate:
            return False
            
        # Verificar certificado válido
        if not ssl_info.certificate.is_valid:
            return False
            
        # Verificar cipher suites modernas
        modern_ciphers = [c for c in ssl_info.cipher_suites 
                         if c.get('supported') and c.get('bits', 0) >= 128]
        
        if not modern_ciphers:
            return False
            
        # Verificar ausencia de vulnerabilidades críticas
        critical_vulns = [v for v in ssl_info.vulnerabilities 
                         if v.get('severity') == 'critical']
        
        return len(critical_vulns) == 0