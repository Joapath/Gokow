"""
Menú interactivo principal de Gokow.

Proporciona una interfaz TUI limpia y profesional para ejecutar escaneos.
"""

import asyncio
from textual.app import ComposeResult, App
from textual.widgets import (
    Select, Button, Static, Header, Footer, Label, Input, OptionList
)
from textual.widgets.option_list import Option
from textual.containers import Container, Vertical, Horizontal, ScrollableContainer
from textual.binding import Binding
from textual.screen import Screen
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from gokow.cli.menu_config import MENU_CSS, SCAN_CATEGORIES
from gokow.cli.menu_state import MenuState
from gokow.cli.menu_components import (
    InfoPanel, CategoryCard, OPSECCard, ScanSummary, StatusMessage
)
from gokow.modules.scanner.host_discovery import HostDiscoveryScanner
from gokow.modules.scanner.port_scanner import PortScanner
from gokow.modules.scanner.dns_scanner import DNSEnumerationScanner
from gokow.modules.scanner.service_detection import ServiceDetectionScanner
from gokow.modules.scanner.subdomain_scanner import SubdomainEnumerationScanner
from gokow.modules.scanner.web_fingerprinting import WebFingerprintingScanner
from gokow.modules.scanner.content_discovery import ContentDiscoveryScanner
from gokow.modules.scanner.ssl_tls_scanner import SSLTLSAnalysisScanner
from gokow.utils.validators import TargetValidator

console = Console()


class CategorySelectionScreen(Screen):
    """Pantalla para seleccionar categoría."""

    BINDINGS = [
        Binding("q", "quit", "Atrás"),
        Binding("enter", "select", "Seleccionar"),
    ]

    def __init__(self, menu_state: MenuState):
        super().__init__()
        self.menu_state = menu_state

    def compose(self) -> ComposeResult:
        """Componer la pantalla."""
        yield Header()
        yield Label("[bold cyan]Selecciona una categoría de escaneo[/bold cyan]")

        # Crear opciones de categorías
        options = []
        for cat_id, cat_info in self.menu_state.obtener_categorias():
            options.append(Option(cat_id))

        yield OptionList(*options, id="category_list")
        yield Footer()

    def on_option_list_selected(self, event):
        """Manejar selección."""
        if self.menu_state.seleccionar_categoria(event.option.id.split()[-1]):
            self.app.pop_screen()


class OPSECSelectionScreen(Screen):
    """Pantalla para seleccionar modo OPSEC."""

    BINDINGS = [
        Binding("q", "quit", "Atrás"),
        Binding("enter", "select", "Seleccionar"),
    ]

    def __init__(self, menu_state: MenuState):
        super().__init__()
        self.menu_state = menu_state

    def compose(self) -> ComposeResult:
        """Componer la pantalla."""
        yield Header()
        yield Label("[bold yellow]Selecciona modo OPSEC[/bold yellow]")

        # Crear opciones de OPSEC
        options = []
        for modo_id, modo_info in self.menu_state.obtener_modos_opsec():
            options.append(Option(modo_id))

        yield OptionList(*options, id="opsec_list")
        yield Footer()

    def on_option_list_selected(self, event):
        """Manejar selección."""
        modo_id = event.option.id.split("🔐 ")[1].split(" -")[0]
        if self.menu_state.seleccionar_opsec(modo_id):
            self.app.pop_screen()


class TargetInputScreen(Screen):
    """Pantalla para ingresar target."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancelar"),
    ]

    def __init__(self, menu_state: MenuState):
        super().__init__()
        self.menu_state = menu_state

    def compose(self) -> ComposeResult:
        """Componer la pantalla."""
        yield Header()
        with Vertical():
            yield Label("[bold cyan]Ingresa el target[/bold cyan]")
            yield Label("[dim]Ejemplos: 192.168.1.0/24, example.com[/dim]")
            yield Input(placeholder="Target", id="target_input")
        yield Footer()

    def on_input_submitted(self, event):
        """Manejar envío de input."""
        if self.menu_state.establecer_target(event.value):
            self.app.pop_screen()


class ScannerSelectionScreen(Screen):
    """Pantalla para seleccionar scanner específico dentro de una categoría."""

    BINDINGS = [
        Binding("q", "quit", "Atrás"),
        Binding("enter", "select", "Seleccionar"),
    ]

    def __init__(self, menu_state: MenuState):
        super().__init__()
        self.menu_state = menu_state

    def compose(self) -> ComposeResult:
        """Componer la pantalla."""
        yield Header()
        
        categoria_id = self.menu_state.config.categoria
        categoria_info = SCAN_CATEGORIES.get(categoria_id, {})
        
        yield Label(f"[bold yellow]{categoria_info.get('nombre', 'Scanner')} - Selecciona módulo[/bold yellow]")
        
        # Crear opciones de scanners
        options = []
        modulos = categoria_info.get('modulos', [])
        for modulo in modulos:
            options.append(Option(modulo))
        
        yield OptionList(*options, id="scanner_list")
        yield Footer()

    def on_option_list_selected(self, event):
        """Manejar selección."""
        scanner_id = event.option.id
        self.menu_state.seleccionar_scanner(scanner_id)
        
        # Pasar a pantalla de progreso
        self.app.pop_screen()
        self.app.push_screen(ScanProgressScreen(self.menu_state))


class ScanProgressScreen(Screen):
    """Pantalla para mostrar progreso del escaneo."""

    BINDINGS = [
        Binding("q", "quit", "Atrás"),
    ]

    def __init__(self, menu_state: MenuState):
        super().__init__()
        self.menu_state = menu_state

    def compose(self) -> ComposeResult:
        """Componer la pantalla."""
        yield Header()
        with Vertical():
            yield Label("[bold cyan]Ejecutando escaneo...[/bold cyan]")
            yield Static(id="progress_display")
            yield Static(id="result_display")
        yield Footer()

    def on_mount(self):
        """Ejecutar el escaneo al montar la pantalla."""
        self.run_worker(self._execute_scan())

    async def _execute_scan(self):
        """Ejecutar el escaneo de forma asincrónica."""
        try:
            target = self.menu_state.config.target
            categoria = self.menu_state.config.categoria
            scanner_type = self.menu_state.config.scanner_type
            
            # Actualizar display
            progress_display = self.query_one("#progress_display", Static)
            result_display = self.query_one("#result_display", Static)
            
            progress_display.update("[yellow]⏳ Iniciando escaneo...[/yellow]")
            
            # Validar target
            es_valido, msg, tipo = TargetValidator.validar(target)
            if not es_valido:
                result_display.update(f"[red]✗ Error: {msg}[/red]")
                return
            
            # Preparar configuración OPSEC
            opsec_config = {
                'opsec': {
                    'stealth': self.menu_state.config.opsec_mode != 'normal'
                }
            }
            
            scanner = None
            scanner_name = "Scanner"
            
            # Seleccionar scanner basado en tipo
            if scanner_type == "host-discovery":
                scanner = HostDiscoveryScanner(target, {'timeout': 2, **opsec_config})
                scanner_name = "Descubrimiento de Hosts"
            elif scanner_type == "port-scan":
                scanner = PortScanner(target, {'ports': '1-1000', 'timeout': 2, **opsec_config})
                scanner_name = "Escaneo de Puertos"
            elif scanner_type == "service-detection":
                scanner = ServiceDetectionScanner(target, {'ports': '80,443,22,21,3306', 'timeout': 5, **opsec_config})
                scanner_name = "Detección de Servicios"
            elif scanner_type == "dns-enumeration":
                scanner = DNSEnumerationScanner(target, {'record_types': ['A', 'AAAA', 'MX', 'NS', 'TXT'], 'timeout': 5, **opsec_config})
                scanner_name = "Enumeración DNS"
            elif scanner_type == "wordlist-enumeration":
                scanner = SubdomainEnumerationScanner(target, {'timeout': 10, **opsec_config})
                scanner_name = "Enumeración de Subdominios"
            elif scanner_type == "technology-detection":
                scanner = WebFingerprintingScanner(target, {'timeout': 5, **opsec_config})
                scanner_name = "Fingerprinting Web"
            elif scanner_type == "directory-enumeration":
                scanner = ContentDiscoveryScanner(target, {'timeout': 5, 'max_concurrent': 5, **opsec_config})
                scanner_name = "Descubrimiento de Contenido"
            elif scanner_type in {"tls-analysis", "ssl-analysis"}:
                scanner = SSLTLSAnalysisScanner(target, {'port': 443, 'timeout': 10, **opsec_config})
                scanner_name = "Análisis SSL/TLS"
            
            if not scanner:
                result_display.update("[red]✗ Scanner no disponible[/red]")
                return
            
            progress_display.update(f"[cyan]▶ Ejecutando: {scanner_name}[/cyan]")
            
            # Ejecutar escaneo
            result = await scanner.scan()
            
            # Mostrar resultados
            if result.findings:
                hallazgos = f"[green]✓ Encontrados {len(result.findings)} hallazgos[/green]"
                detalles = "\n".join([
                    f"  • [{f.get('severity', 'info')}] {f.get('title', 'Sin título')}"
                    for f in result.findings[:5]  # Mostrar primeros 5
                ])
                result_display.update(f"{hallazgos}\n\n{detalles}")
            else:
                result_display.update("[yellow]⚠ Sin hallazgos encontrados[/yellow]")
            
            progress_display.update("[cyan]✓ Escaneo completado[/cyan]\n\n[dim]Presiona Q para volver[/dim]")
        
        except Exception as e:
            result_display.update(f"[red]✗ Error: {str(e)}[/red]")

    def action_quit(self):
        """Volver al menú principal."""
        self.app.pop_screen()


class GokowMenu(App):
    """Aplicación principal del menú de Gokow."""

    BINDINGS = [
        Binding("q", "quit", "Salir"),
        Binding("c", "categories", "Categorías"),
        Binding("o", "opsec", "OPSEC"),
        Binding("t", "target", "Target"),
        Binding("r", "run", "Ejecutar"),
    ]

    CSS = MENU_CSS
    TITLE = "Gokow - Herramienta de Pentesting"
    SUB_TITLE = "Reconocimiento de seguridad avanzado"

    def __init__(self):
        super().__init__()
        self.menu_state = MenuState()

    def compose(self) -> ComposeResult:
        """Componer la aplicación."""
        yield Header()

        with Vertical(id="main-container"):
            # Panel de información
            yield Label(
                "[bold cyan]Gokow - Herramienta de Pentesting Avanzada[/bold cyan]",
                classes="info-text"
            )

            with Vertical(id="category-section"):
                yield Label("[bold]Categoría Seleccionada:[/bold]")
                yield Static(
                    self._get_category_display(),
                    id="category_display"
                )

            with Vertical(id="opsec-section"):
                yield Label("[bold]Modo OPSEC:[/bold]")
                yield Static(
                    self._get_opsec_display(),
                    id="opsec_display"
                )

            with Vertical(id="control-section"):
                yield Label("[bold]Acciones:[/bold]")
                with Horizontal():
                    yield Button("Categoría (C)", id="btn_category", variant="primary")
                    yield Button("OPSEC (O)", id="btn_opsec", variant="primary")
                    yield Button("Target (T)", id="btn_target", variant="primary")
                    yield Button("Ejecutar (R)", id="btn_run", variant="success")
                    yield Button("Salir (Q)", id="btn_quit", variant="error")

        yield Footer()

    def _get_category_display(self) -> str:
        """Obtener texto para mostrar categoría seleccionada."""
        if not self.menu_state.config.categoria:
            return "[yellow]No seleccionada[/yellow]"

        cat_info = self.menu_state.obtener_informacion_categoria()
        return f"{cat_info.get('icon', '')} {cat_info.get('nombre', '')}"

    def _get_opsec_display(self) -> str:
        """Obtener texto para mostrar OPSEC seleccionado."""
        opsec_info = self.menu_state.obtener_informacion_opsec()
        return f"🔐 {opsec_info.get('nombre', 'Normal')}"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Manejar presión de botones."""
        button_id = event.button.id
        if button_id == "btn_category":
            self.action_categories()
        elif button_id == "btn_opsec":
            self.action_opsec()
        elif button_id == "btn_target":
            self.action_target()
        elif button_id == "btn_run":
            self.action_run()
        elif button_id == "btn_quit":
            self.action_quit()

    def action_categories(self):
        """Mostrar pantalla de selección de categorías."""
        self.push_screen(CategorySelectionScreen(self.menu_state))

    def action_opsec(self):
        """Mostrar pantalla de selección de OPSEC."""
        self.push_screen(OPSECSelectionScreen(self.menu_state))

    def action_target(self):
        """Mostrar pantalla de ingreso de target."""
        self.push_screen(TargetInputScreen(self.menu_state))

    def action_run(self):
        """Ejecutar el escaneo."""
        es_valida, mensaje = self.menu_state.validar_configuration()

        if not es_valida:
            console.print(f"[red]Error: {mensaje}[/red]")
            return

        # Mostrar pantalla de selección de scanner
        self.push_screen(ScannerSelectionScreen(self.menu_state))

    def watch_menu_state(self):
        """Observar cambios en el estado del menú."""
        self.query_one("#category_display", Static).update(
            self._get_category_display()
        )
        self.query_one("#opsec_display", Static).update(
            self._get_opsec_display()
        )


def run_interactive_menu():
    """
    Lanzar el menú interactivo.

    Esta es la función de entrada principal para el modo interactivo.
    """
    app = GokowMenu()
    app.run()