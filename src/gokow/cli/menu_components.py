"""
Componentes reutilizables para la interfaz Textual.

Incluye widgets personalizados para mejorar la experiencia del menú.
"""

from textual.widgets import Static, Label
from textual.containers import Container, Vertical, Horizontal
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing import Optional

console = Console()


class InfoPanel(Static):
    """Panel para mostrar información descriptiva."""

    def __init__(
        self,
        title: str,
        content: str,
        icon: str = "ℹ️",
        border_style: str = "blue",
        **kwargs
    ):
        super().__init__(**kwargs)
        self.title = title
        self.content = content
        self.icon = icon
        self.border_style = border_style

    def render(self):
        """Renderizar el panel con información."""
        panel = Panel(
            f"[cyan]{self.content}[/cyan]",
            title=f"{self.icon} {self.title}",
            border_style=self.border_style,
            padding=(1, 2),
        )
        return panel


class CategoryCard(Static):
    """Tarjeta para mostrar una categoría de escaneo."""

    def __init__(
        self,
        nombre: str,
        descripcion: str,
        icon: str,
        modulos_count: int = 0,
        selected: bool = False,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.nombre = nombre
        self.descripcion = descripcion
        self.icon = icon
        self.modulos_count = modulos_count
        self.selected = selected

    def render(self):
        """Renderizar la tarjeta de categoría."""
        border_color = "green" if self.selected else "cyan"
        border_type = "heavy" if self.selected else "light"

        title = f"{self.icon} {self.nombre}"
        if self.modulos_count > 0:
            title += f" ({self.modulos_count})"

        content = f"[yellow]{self.descripcion}[/yellow]"

        panel = Panel(
            content,
            title=title,
            border_style=border_color,
            padding=(1, 2),
        )
        return panel


class OPSECCard(Static):
    """Tarjeta para mostrar opciones OPSEC."""

    def __init__(
        self,
        nombre: str,
        descripcion: str,
        delay_min: float,
        delay_max: float,
        selected: bool = False,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.nombre = nombre
        self.descripcion = descripcion
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.selected = selected

    def render(self):
        """Renderizar la tarjeta de OPSEC."""
        border_color = "green" if self.selected else "yellow"
        title = f"🔐 {self.nombre}"

        content_parts = [
            f"[cyan]{self.descripcion}[/cyan]",
            f"Delays: {self.delay_min}s - {self.delay_max}s",
        ]
        content = "\n".join(content_parts)

        panel = Panel(
            content,
            title=title,
            border_style=border_color,
            padding=(1, 2),
        )
        return panel


class ScanSummary(Static):
    """Resumen de la configuración antes de ejecutar escaneo."""

    def __init__(
        self,
        categoria: str,
        opsec_mode: str,
        target: Optional[str] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.categoria = categoria
        self.opsec_mode = opsec_mode
        self.target = target

    def render(self):
        """Renderizar el resumen."""
        table = Table(title="📋 Resumen de Escaneo", show_header=False)
        table.add_column("Parámetro", style="cyan")
        table.add_column("Valor", style="green")

        table.add_row("Categoría", self.categoria)
        table.add_row("Modo OPSEC", self.opsec_mode)
        if self.target:
            table.add_row("Target", self.target)

        panel = Panel(
            table,
            title="⚙️ Configuración",
            border_style="magenta",
            padding=(1, 2),
        )
        return panel


class StatusMessage(Static):
    """Mensaje de estado con colores."""

    def __init__(
        self,
        message: str,
        status: str = "info",  # info, success, warning, error
        **kwargs
    ):
        super().__init__(**kwargs)
        self.message = message
        self.status = status

    def render(self):
        """Renderizar el mensaje de estado."""
        colors = {
            "info": "blue",
            "success": "green",
            "warning": "yellow",
            "error": "red",
        }
        color = colors.get(self.status, "white")
        icons = {
            "info": "ℹ️",
            "success": "✓",
            "warning": "⚠️",
            "error": "✗",
        }
        icon = icons.get(self.status, "•")

        return f"[{color}]{icon} {self.message}[/{color}]"
