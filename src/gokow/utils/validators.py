"""
Utilidades de validación para escaneos y configuración.

Centraliza toda la lógica de validación para mantener código limpio y reutilizable.
"""

import re
import ipaddress
from typing import Tuple, Optional
from enum import Enum


class TargetType(Enum):
    """Tipos de target soportados."""
    IP_SINGLE = "ip_single"
    IP_RANGE = "ip_range"
    CIDR = "cidr"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    URL = "url"
    INVALID = "invalid"


class TargetValidator:
    """Validator para diferentes tipos de targets."""

    @staticmethod
    def validar_ip_simple(target: str) -> bool:
        """
        Validar si es una dirección IP simple.

        Args:
            target: Dirección a validar

        Returns:
            True si es una IP válida
        """
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    @staticmethod
    def validar_rango_ip(target: str) -> bool:
        """
        Validar si es un rango de IPs (ej: 192.168.1.1-192.168.1.10).

        Args:
            target: Rango a validar

        Returns:
            True si es un rango válido
        """
        if "-" not in target:
            return False

        parts = target.split("-")
        if len(parts) != 2:
            return False

        try:
            ip1 = ipaddress.ip_address(parts[0].strip())
            ip2 = ipaddress.ip_address(parts[1].strip())
            return ip1 < ip2  # El primero debe ser menor que el segundo
        except ValueError:
            return False

    @staticmethod
    def validar_cidr(target: str) -> bool:
        """
        Validar si es una notación CIDR (ej: 192.168.1.0/24).

        Args:
            target: Notación a validar

        Returns:
            True si es CIDR válido
        """
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            return False

    @staticmethod
    def validar_dominio(target: str) -> bool:
        """
        Validar si es un dominio válido.

        Args:
            target: Dominio a validar

        Returns:
            True si es un dominio válido
        """
        # Expresión regular para validar dominios
        patron = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
        return bool(re.match(patron, target.lower()))

    @staticmethod
    def validar_url(target: str) -> bool:
        """
        Validar si es una URL válida.

        Args:
            target: URL a validar

        Returns:
            True si es una URL válida
        """
        patron = r'^https?://[a-z0-9-._~:/?#\[\]@!$&\'()*+,;=]+$'
        return bool(re.match(patron, target.lower()))

    @staticmethod
    def detectar_tipo(target: str) -> TargetType:
        """
        Detectar automáticamente el tipo de target.

        Args:
            target: Target a analizar

        Returns:
            TargetType identificado
        """
        if TargetValidator.validar_ip_simple(target):
            return TargetType.IP_SINGLE

        if TargetValidator.validar_rango_ip(target):
            return TargetType.IP_RANGE

        if TargetValidator.validar_cidr(target):
            return TargetType.CIDR

        if TargetValidator.validar_url(target):
            return TargetType.URL

        if TargetValidator.validar_dominio(target):
            if target.count(".") > 1:
                return TargetType.SUBDOMAIN
            return TargetType.DOMAIN

        return TargetType.INVALID

    @staticmethod
    def validar(target: str) -> Tuple[bool, str, TargetType]:
        """
        Validar un target y retornar información detallada.

        Args:
            target: Target a validar

        Returns:
            Tupla (es_valido, mensaje, tipo)
        """
        if not target or len(target) < 3:
            return False, "Target demasiado corto", TargetType.INVALID

        target = target.strip()
        tipo = TargetValidator.detectar_tipo(target)

        if tipo == TargetType.INVALID:
            return False, "Formato de target no válido", tipo

        mensajes = {
            TargetType.IP_SINGLE: "IP simple",
            TargetType.IP_RANGE: "Rango de IPs",
            TargetType.CIDR: "Notación CIDR",
            TargetType.DOMAIN: "Dominio",
            TargetType.SUBDOMAIN: "Subdominio",
            TargetType.URL: "URL",
        }

        mensaje = f"Target válido: {mensajes.get(tipo, 'Desconocido')}"
        return True, mensaje, tipo


class ConfigValidator:
    """Validator para configuraciones."""

    @staticmethod
    def validar_puerto(puerto: int) -> bool:
        """
        Validar número de puerto.

        Args:
            puerto: Número de puerto

        Returns:
            True si es válido
        """
        return 1 <= puerto <= 65535

    @staticmethod
    def validar_rango_puertos(rango: str) -> Tuple[bool, str]:
        """
        Validar rango de puertos (ej: 1-65535, 80,443,8080).

        Args:
            rango: Rango a validar

        Returns:
            Tupla (es_valido, mensaje_error)
        """
        if not rango:
            return False, "Rango no puede estar vacío"

        # Rango simple (e.g., 1-1000)
        if "-" in rango:
            try:
                start, end = rango.split("-")
                start, end = int(start.strip()), int(end.strip())

                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    return False, "Puertos fuera de rango válido"

                if start > end:
                    return False, "Puerto inicial es mayor que el final"

                return True, ""
            except ValueError:
                return False, "Formato de rango inválido"

        # Puertos individuales (e.g., 80,443,8080)
        if "," in rango:
            try:
                for puerto_str in rango.split(","):
                    puerto = int(puerto_str.strip())
                    if not ConfigValidator.validar_puerto(puerto):
                        return False, f"Puerto inválido: {puerto}"
                return True, ""
            except ValueError:
                return False, "Formato de puertos inválido"

        # Puerto individual
        try:
            puerto = int(rango)
            if ConfigValidator.validar_puerto(puerto):
                return True, ""
            return False, "Puerto fuera de rango"
        except ValueError:
            return False, "Formato no válido"
