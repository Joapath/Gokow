"""
Guía para Desarrolladores - Gokow

Cómo trabajar con el código de Gokow de manera limpia y eficiente.
"""

# CONFIGURACIÓN DEL ENTORNO DE DESARROLLO
# ========================================

# 1. Clonar y configurar
# $ git clone <repo>
# $ cd gokow
# $ python3 -m venv venv
# $ source venv/bin/activate
# $ pip install -e ".[dev]"

# 2. Entender la estructura (ver ARCHITECTURE.md)


# FLUJO DE TRABAJO TÍPICO
# =======================

# 1. Seleccionar tarea (feature/bug)
# 2. Criar rama: git checkout -b feature/nombre

# 3. Implementar cambios:
#    - CLI: cli/commands.py
#    - UI: cli/interactive.py
#    - Lógica: modules/scanner/
#    - Config: config/settings.py

# 4. Testear localmente:
#    $ gokow --help
#    $ gokow --version
#    $ gokow recon-network host-discovery 192.168.1.0/24

# 5. Commit y push
# 6. Pull request


# CONVENCIONES DE CÓDIGO
# ======================

# Type Hints (OBLIGATORIO)
def procesar_target(target: str) -> bool:
    """Procesar y validar un target."""
    return len(target) > 0


# Docstrings (OBLIGATORIO)
class MiScanner:
    """
    Escáner personalizado.
    
    Descripción detallada de qué hace.
    """

    def scan(self) -> dict:
        """
        Ejecutar el escaneo.
        
        Returns:
            Diccionario con resultados
        """
        pass


# Constantes en MAYÚSCULAS
MAX_WORKERS = 4
DEFAULT_TIMEOUT = 5


# Strings con f-strings
nombre = "Juan"
mensaje = f"Hola {nombre}"  # Bien
# mensaje = "Hola {}".format(nombre)  # No

# Boolean sin comparaciones explícitas
if lista_vacia:  # Bien
    pass
# if len(lista_vacia) == 0:  # No

# Imports organizados
from typing import Optional, List  # Stdlib types
from dataclasses import dataclass  # Stdlib

from rich.console import Console  # Third-party
from click import command  # Third-party

from gokow.utils.validators import TargetValidator  # Project


# ESTRUCTURA DE ARCHIVOS PARA NUEVO SCANNER
# ==========================================

# modules/scanner/ejemplo_scanner.py

"""
Descripción del scanner.

Qué hace, cuáles son sus entradas, salidas típicas.
"""

from typing import Optional, Dict, Any
from gokow.modules.base import BaseScanner, ScanResult
from gokow.utils.opsec import OPSECManager


class EjemploScanner(BaseScanner):
    """
    Escáner de ejemplo.
    
    Explain qué busca, cómo lo hace, etc.
    """

    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(target, config)
        self.opciones_especificas = config.get('opciones', {})

    async def scan(self) -> ScanResult:
        """
        Ejecutar escaneo.
        
        Returns:
            ScanResult con hallazgos
        """
        try:
            self._validar_target()
            
            # Implementar lógica
            hallazgos = self._realizar_busqueda()
            
            # Procesar resultados
            for hallazgo in hallazgos:
                self._log_finding(
                    severity=hallazgo['severidad'],
                    title=hallazgo['titulo'],
                    details=hallazgo['detalles']
                )
            
            self.result.end_time = datetime.now()
            return self.result
            
        except Exception as e:
            self._log_error(str(e))
            return self.result

    def _validar_target(self) -> bool:
        """Validar que el target es apropiado para este scanner."""
        # Validar formato, no estoy en blacklist, etc.
        return True

    def _realizar_busqueda(self) -> list:
        """Realizar búsqueda real."""
        # Implementación real aquí
        return []


# DESARROLLO DE NUEVOS COMANDOS CLI
# =================================

# cli/commands.py

@cli.group()
def nueva_categoria():
    """
    📌 Descripción breve.
    
    Descripción más detallada de qué herramientas incluye.
    """
    pass


@nueva_categoria.command()
@click.argument('target', callback=validate_target)
@click.option('--opcion', type=str, default='valor', help='Descripción')
@click.pass_context
def nuevo_comando(ctx, target, opcion):
    """
    Descripción del comando.
    
    Incluye ejemplos de uso en la ayuda.
    """
    try:
        console.print(f"[cyan]Iniciando operación...[/cyan]")
        console.print(f"  • Target: {target}")
        console.print(f"  • Opción: {opcion}")
        
        # Implementación
        
        console.print("[green]✓ Completado[/green]")
        
    except Exception as e:
        ErrorFormatter.format_error(str(e))
        ctx.exit(1)


# TESTING
# =======

# tests/test_validators.py

import pytest
from gokow.utils.validators import TargetValidator

def test_validar_ip():
    """Testear validación de IP."""
    assert TargetValidator.validar_ip_simple("192.168.1.1")
    assert not TargetValidator.validar_ip_simple("999.999.999.999")

def test_validar_cidr():
    """Testear validación CIDR."""
    assert TargetValidator.validar_cidr("192.168.1.0/24")
    assert not TargetValidator.validar_cidr("192.168.1.0/33")

# Correr tests: pytest tests/


# DEBUGGING
# =========

# Activar modo verbose
$ gokow --verbose --stealth recon-network host-discovery 192.168.1.0/24

# Ver logs completos y tracebacks
settings.debug = True

# Usar console.print con etiquetas
from rich.console import Console
console = Console()

console.print("[red]Error[/red]")
console.print("[green]Éxito[/green]")
console.print("[yellow]Advertencia[/yellow]")
console.print("[blue]Info[/blue]")


# COMMITS Y GIT
# =============

# Buena commit
git commit -m "feat: agregar validador CIDR a TargetValidator

- Validar notación CIDR (ej: 192.168.1.0/24)
- Rechazar CIDR inválidos (ej: /33)
- Tests incluidos"

# Mal commit
git commit -m "actualizar codigo"

# Tipos recomendados:
# feat: nueva funcionalidad
# fix: corrección de bug
# docs: cambios de documentación
# refactor: cambios de código sin funcionalidad nueva
# test: agregar tests
# chore: cambios en configuración, deps, etc


# RECURSOS ÚTILES
# ===============

# Documentación
# - Textual: https://textual.textualize.io/
# - Click: https://click.palletsprojects.com/
# - Rich: https://rich.readthedocs.io/
# - Pydantic: https://docs.pydantic.dev/
# - Scapy: https://scapy.readthedocs.io/

# Localmente
# - Ver ARCHITECTURE.md para estructura del proyecto
# - Ver cada módulo para docstrings
# - Tests en tests/ para ejemplos de uso
