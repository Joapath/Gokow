"""
Gestor de estado para el menú interactivo.

Mantiene la lógica de selección y validación separada de la interfaz.
"""

from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from gokow.cli.menu_config import SCAN_CATEGORIES, OPSEC_MODES


@dataclass
class ScanConfiguration:
    """Configuración de escaneo seleccionada por el usuario."""

    categoria: Optional[str] = None
    opsec_mode: str = "normal"
    target: Optional[str] = None
    scanner_type: Optional[str] = None
    opciones_avanzadas: Dict[str, Any] = field(default_factory=dict)

    def es_valida(self) -> bool:
        """Validar que la configuración es completa."""
        return self.categoria is not None and self.opsec_mode in OPSEC_MODES

    def obtener_resumen(self) -> str:
        """Obtener resumen legible de la configuración."""
        lineas = [
            f"Categoría: {SCAN_CATEGORIES.get(self.categoria, {}).get('nombre', 'Desconocida')}",
            f"Modo OPSEC: {OPSEC_MODES.get(self.opsec_mode, {}).get('nombre', 'Normal')}",
        ]
        if self.target:
            lineas.append(f"Target: {self.target}")
        return "\n".join(lineas)


class MenuState:
    """Gestor del estado del menú interactivo."""

    def __init__(self):
        """Inicializar el estado."""
        self.config = ScanConfiguration()
        self.historial_escaneos: List[ScanConfiguration] = []
        self.mostrar_opciones_avanzadas = False

    def seleccionar_categoria(self, categoria: str) -> bool:
        """
        Seleccionar una categoría de escaneo.

        Args:
            categoria: Identificador de la categoría

        Returns:
            True si la selección es válida, False en caso contrario
        """
        if categoria not in SCAN_CATEGORIES:
            return False

        self.config.categoria = categoria
        return True

    def seleccionar_opsec(self, modo: str) -> bool:
        """
        Seleccionar modo OPSEC.

        Args:
            modo: Identificador del modo OPSEC

        Returns:
            True si la selección es válida, False en caso contrario
        """
        if modo not in OPSEC_MODES:
            return False

        self.config.opsec_mode = modo
        return True

    def establecer_target(self, target: str) -> bool:
        """
        Establecer el target del escaneo.

        Args:
            target: Dirección IP, dominio o rango

        Returns:
            True si es válido, False en caso contrario
        """
        if not target or len(target) < 3:
            return False

        self.config.target = target
        return True

    def seleccionar_scanner(self, scanner_type: str) -> bool:
        """
        Seleccionar tipo de scanner específico.

        Args:
            scanner_type: Identificador del tipo de scanner

        Returns:
            True si la selección es válida
        """
        categoria = self.config.categoria
        if not categoria or categoria not in SCAN_CATEGORIES:
            return False

        modulos = SCAN_CATEGORIES[categoria].get('modulos', [])
        if scanner_type not in modulos:
            return False

        self.config.scanner_type = scanner_type
        return True

    def guardar_configuracion(self) -> bool:
        """
        Guardar la configuración actual en el historial.

        Returns:
            True si se guardó exitosamente
        """
        if not self.config.es_valida():
            return False

        # Guardar copia de la configuración actual
        self.historial_escaneos.append(
            ScanConfiguration(
                categoria=self.config.categoria,
                opsec_mode=self.config.opsec_mode,
                target=self.config.target,
                opciones_avanzadas=self.config.opciones_avanzadas.copy(),
            )
        )
        return True

    def resetear_configuracion(self):
        """Resetear la configuración a valores por defecto."""
        self.config = ScanConfiguration()

    def obtener_categorias(self) -> List[tuple]:
        """
        Obtener lista de categorías para Select widget.

        Returns:
            Lista de tuplas (nombre, identificador)
        """
        return [
            (f"{cat['icon']} {cat['nombre']}", cat_id)
            for cat_id, cat in SCAN_CATEGORIES.items()
        ]

    def obtener_modos_opsec(self) -> List[tuple]:
        """
        Obtener lista de modos OPSEC para Select widget.

        Returns:
            Lista de tuplas (nombre, identificador)
        """
        return [
            (f"🔐 {modo['nombre']} - {modo['descripcion']}", modo_id)
            for modo_id, modo in OPSEC_MODES.items()
        ]

    def obtener_modulos_categoria(self, categoria: Optional[str] = None) -> List[str]:
        """
        Obtener módulos disponibles para una categoría.

        Args:
            categoria: Identificador de categoría (usa la actual si es None)

        Returns:
            Lista de módulos
        """
        cat_id = categoria or self.config.categoria
        if not cat_id or cat_id not in SCAN_CATEGORIES:
            return []

        return SCAN_CATEGORIES[cat_id]["modulos"]

    def obtener_informacion_categoria(self, categoria: Optional[str] = None) -> Dict[str, Any]:
        """
        Obtener información completa de una categoría.

        Args:
            categoria: Identificador de categoría (usa la actual si es None)

        Returns:
            Diccionario con información de la categoría
        """
        cat_id = categoria or self.config.categoria
        if not cat_id or cat_id not in SCAN_CATEGORIES:
            return {}

        return SCAN_CATEGORIES[cat_id]

    def obtener_informacion_opsec(self, modo: Optional[str] = None) -> Dict[str, Any]:
        """
        Obtener información completa de un modo OPSEC.

        Args:
            modo: Identificador del modo (usa el actual si es None)

        Returns:
            Diccionario con información del modo
        """
        modo_id = modo or self.config.opsec_mode
        if modo_id not in OPSEC_MODES:
            return {}

        return OPSEC_MODES[modo_id]

    def validar_configuration(self) -> tuple[bool, str]:
        """
        Validar la configuración completa.

        Returns:
            Tupla (es_valida, mensaje_error)
        """
        if not self.config.categoria:
            return False, "Debe seleccionar una categoría"

        if not self.config.opsec_mode:
            return False, "Debe seleccionar un modo OPSEC"

        return True, "Configuración válida"
