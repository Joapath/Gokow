"""Base classes and models for Gokow scanners."""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any, Optional
from rich.console import Console

from gokow.utils.opsec import OPSECManager


@dataclass
class ScanResult:
    """Result model for scan operations."""
    target: str
    scan_type: str
    start_time: datetime
    end_time: Optional[datetime] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    opsec_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for reporting."""
        return {
            'target': self.target,
            'scan_type': self.scan_type,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'findings': self.findings,
            'errors': self.errors,
            'opsec_metadata': self.opsec_metadata,
        }


class BaseScanner(ABC):
    """Base class for all scanners with OPSEC integration."""

    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        self.target = target
        self.config = config or {}
        self.console = Console()
        self.opsec = OPSECManager(self.config.get('opsec', {}))
        self.result = ScanResult(
            target=target,
            scan_type=self.__class__.__name__,
            start_time=datetime.now()
        )

    @abstractmethod
    async def scan(self) -> ScanResult:
        """Execute scan - must be implemented by subclasses."""
        pass

    def _validate_target(self) -> bool:
        """Validate target format - override in subclasses."""
        return True

    def _log_finding(self, severity: str, title: str, details: Optional[str] = None):
        """
        Log a finding with severity level.
        
        Args:
            severity: 'info', 'warning', 'success', 'error'
            title: Título del hallazgo
            details: Detalles adicionales
        """
        # Formatear detalles
        if details:
            details_str = str(details) if not isinstance(details, dict) else details
        else:
            details_str = ""
        
        finding = {
            'severity': severity,
            'title': title,
            'details': details_str,
            'timestamp': datetime.now().isoformat()
        }
        self.result.findings.append(finding)

    def _log_error(self, error: str):
        """Log an error."""
        self.result.errors.append(error)

    async def _apply_opsec(self, request_kwargs: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Apply OPSEC measures.
        
        Async version that applies delays and other OPSEC techniques.
        """
        kwargs = request_kwargs or {}
        
        # Aplicar delay OPSEC
        await self.opsec.apply_delay()
        
        # Aplicar headers y otras medidas
        return self.opsec.apply_to_request(kwargs)

    def apply_opsec_to_request(self, request_kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synchronous version: Apply OPSEC measures to request.
        
        Use for sync contexts.
        """
        return self.opsec.apply_to_request(request_kwargs)