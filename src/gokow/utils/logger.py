"""
Sistema de logging centralizado para Gokow.

Proporciona una interfaz limpia para logging en toda la aplicación.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
from logging.handlers import RotatingFileHandler

from rich.logging import RichHandler
from rich.console import Console

# Console directa para crear el logger
_console = Console()


class GokowLogger:
    """Logger centralizado para Gokow."""

    _instance: Optional['GokowLogger'] = None
    _logger: Optional[logging.Logger] = None

    def __new__(cls):
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Inicializar el logger."""
        self._logger = logging.getLogger("gokow")
        self._logger.setLevel(logging.DEBUG)

        # Evitar handlers duplicados
        if self._logger.handlers:
            return

        # Handler para console con Rich
        console_handler = RichHandler(
            console=_console,
            show_time=True,
            show_path=True,
            show_level=True,
        )
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            "%(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        console_handler.setFormatter(console_formatter)
        self._logger.addHandler(console_handler)

        # Handler para archivo
        log_dir = Path.home() / ".gokow" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        log_file = log_dir / f"gokow_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_formatter)
        self._logger.addHandler(file_handler)

    @property
    def logger(self) -> logging.Logger:
        """Obtener el logger."""
        return self._logger

    def debug(self, message: str):
        """Log de debug."""
        self._logger.debug(message)

    def info(self, message: str):
        """Log de información."""
        self._logger.info(message)

    def warning(self, message: str):
        """Log de advertencia."""
        self._logger.warning(message)

    def error(self, message: str):
        """Log de error."""
        self._logger.error(message)

    def critical(self, message: str):
        """Log crítico."""
        self._logger.critical(message)


# Instancia global
logger = GokowLogger()


# Funciones de conveniencia
def log_debug(message: str):
    """Log debug rápido."""
    logger.debug(message)


def log_info(message: str):
    """Log info rápido."""
    logger.info(message)


def log_warning(message: str):
    """Log warning rápido."""
    logger.warning(message)


def log_error(message: str):
    """Log error rápido."""
    logger.error(message)


def log_critical(message: str):
    """Log crítico rápido."""
    logger.critical(message)
