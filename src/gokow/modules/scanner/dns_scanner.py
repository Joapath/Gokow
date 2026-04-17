"""
Enumeración de registros DNS.

Implementa consultas DNS para enumerar registros de un dominio.
Resistente a WAF porque usa canales DNS que generalmente no tienen filtrado.

Registros soportados:
- A (IPv4)
- AAAA (IPv6)
- CNAME
- MX (Mail exchange)
- NS (Nameservers)
- TXT (Text records)
- SOA (Start of authority)
- SRV (Service records)
"""

import asyncio
import dns.resolver
import dns.exception
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
import socket

from gokow.modules.base import BaseScanner, ScanResult
from gokow.utils.logger import logger


@dataclass
class DNSRecord:
    """Registro DNS encontrado."""
    type: str
    name: str
    value: str
    ttl: Optional[int] = None


class DNSEnumerationScanner(BaseScanner):
    """
    Escáner de enumeración DNS.
    
    Enumera registros DNS de un dominio para:
    - Descubrir infraestructura
    - Identificar nameservers
    - Encontrar mail servers
    - Detectar cambios en DNS
    
    Ventajas:
    - No es bloqueado por WAF
    - Uso legítimo de DNS
    - Rápido y confiable
    """

    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(target, config)
        
        self.config = config or {}
        self.record_types = self.config.get('record_types', ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA'])
        self.timeout = self.config.get('timeout', 5)
        self.nameservers = self.config.get('nameservers', None)  # Usar custom nameservers si se proporciona
        self.records: Dict[str, List[DNSRecord]] = {rt: [] for rt in self.record_types}
        
        # Validar que el target es un dominio
        self.domain = self._extract_domain()

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
        
        return target if target else None

    async def scan(self) -> ScanResult:
        """
        Ejecutar enumeración DNS.
        
        Returns:
            ScanResult con registros encontrados
        """
        self.result.start_time = datetime.now()
        
        try:
            if not self.domain:
                self._log_error("No se pudo extraer dominio del target")
                return self.result

            self._log_finding(
                "info",
                f"Enumeración DNS",
                f"Dominio: {self.domain} | Registros: {', '.join(self.record_types)}"
            )

            # Aplicar OPSEC
            await self._apply_opsec()

            # Configurar resolver
            resolver = self._setup_resolver()

            # Enumerar cada tipo de registro
            for record_type in self.record_types:
                try:
                    await self._query_record(resolver, record_type)
                    await asyncio.sleep(0.2)  # Delay entre queries
                except Exception as e:
                    logger.debug(f"Error querying {record_type}: {e}")

            # Log de resultados
            self._log_results()

            self.result.end_time = datetime.now()
            return self.result

        except Exception as e:
            self._log_error(f"Error en DNS enumeration: {str(e)}")
            self.result.end_time = datetime.now()
            return self.result

    def _setup_resolver(self) -> dns.resolver.Resolver:
        """Crear resolver DNS configurado."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        
        # Usar nameservers custom si se proporciona
        if self.nameservers:
            resolver.nameservers = self.nameservers
        
        return resolver

    async def _query_record(self, resolver: dns.resolver.Resolver, record_type: str):
        """Consultar un tipo de registro DNS."""
        try:
            logger.debug(f"Querying {record_type} for {self.domain}")
            
            # Ejecutar query en thread para no bloquear
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                self._blocking_query,
                resolver,
                self.domain,
                record_type
            )
            
            if answers:
                self.records[record_type] = self._parse_answers(record_type, answers)
                logger.debug(f"Found {len(self.records[record_type])} {record_type} records")
        
        except dns.exception.DNSException as e:
            logger.debug(f"DNS query failed for {record_type}: {e}")
        except Exception as e:
            logger.debug(f"Error querying {record_type}: {e}")

    def _blocking_query(self, resolver: dns.resolver.Resolver, domain: str, record_type: str):
        """Ejecutar query (blocking)."""
        try:
            return resolver.resolve(domain, record_type)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            return None

    def _parse_answers(self, record_type: str, answers) -> List[DNSRecord]:
        """Parsear respuestas DNS."""
        records = []
        
        try:
            for rdata in answers:
                if record_type == 'A':
                    records.append(DNSRecord(
                        type='A',
                        name=self.domain,
                        value=str(rdata),
                        ttl=answers.rrset.ttl
                    ))
                
                elif record_type == 'AAAA':
                    records.append(DNSRecord(
                        type='AAAA',
                        name=self.domain,
                        value=str(rdata),
                        ttl=answers.rrset.ttl
                    ))
                
                elif record_type == 'CNAME':
                    records.append(DNSRecord(
                        type='CNAME',
                        name=self.domain,
                        value=str(rdata).rstrip('.'),
                        ttl=answers.rrset.ttl
                    ))
                
                elif record_type == 'MX':
                    records.append(DNSRecord(
                        type='MX',
                        name=self.domain,
                        value=f"{rdata.preference} {str(rdata.exchange).rstrip('.')}",
                        ttl=answers.rrset.ttl
                    ))
                
                elif record_type == 'NS':
                    records.append(DNSRecord(
                        type='NS',
                        name=self.domain,
                        value=str(rdata).rstrip('.'),
                        ttl=answers.rrset.ttl
                    ))
                
                elif record_type == 'TXT':
                    value = b''.join(rdata.strings).decode('utf-8', errors='ignore')
                    records.append(DNSRecord(
                        type='TXT',
                        name=self.domain,
                        value=value,
                        ttl=answers.rrset.ttl
                    ))
                
                elif record_type == 'SOA':
                    records.append(DNSRecord(
                        type='SOA',
                        name=self.domain,
                        value=f"{rdata.mname} {rdata.rname}",
                        ttl=answers.rrset.ttl
                    ))
                
                elif record_type == 'SRV':
                    records.append(DNSRecord(
                        type='SRV',
                        name=self.domain,
                        value=f"{rdata.priority} {rdata.weight} {rdata.port} {str(rdata.target).rstrip('.')}",
                        ttl=answers.rrset.ttl
                    ))
        
        except Exception as e:
            logger.debug(f"Error parsing {record_type} answers: {e}")
        
        return records

    def _log_results(self):
        """Log de resultados."""
        total_records = sum(len(recs) for recs in self.records.values())
        
        if total_records == 0:
            self._log_finding("warning", "Sin registros DNS encontrados", "El dominio podría no existir")
            return
        
        self._log_finding(
            "success",
            f"Registros DNS encontrados: {total_records}",
            " | ".join([f"{rt}: {len(recs)}" for rt, recs in self.records.items() if recs])
        )
        
        # Log detallado de cada registro
        for record_type, records in self.records.items():
            if not records:
                continue
            
            for record in records:
                message = f"{record.type} record"
                details = f"Valor: {record.value}"
                if record.ttl:
                    details += f" | TTL: {record.ttl}"
                
                self._log_finding("info", message, details)
