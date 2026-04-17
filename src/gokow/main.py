"""
Punto de entrada principal de Gokow.

Proporciona la lógica para decidir entre menú interactivo o CLI.
"""

import sys
from pathlib import Path
from rich.console import Console

# Asegurar que puede importar desde src/
sys.path.insert(0, str(Path(__file__).parent.parent))

from gokow.cli.interactive import run_interactive_menu
from gokow.cli.commands import cli
from gokow.config.settings import settings

console = Console()


def main():
    """
    Punto de entrada principal.

    Lógica:
    - Sin argumentos: Lanza menú interactivo
    - Con argumentos: Ejecuta comandos CLI
    """
    try:
        # Si se ejecuta sin argumentos, mostrar menú interactivo
        if len(sys.argv) == 1:
            console.print(
                "[bold cyan]╭─────────────────────────────────────╮\n"
                "│    Gokow - Herramienta de Pentesting    │\n"
                "╰─────────────────────────────────────╯[/bold cyan]\n"
            )
            console.print("[dim]Iniciando menú interactivo...\n[/dim]")
            run_interactive_menu()
        else:
            # Ejecutar CLI normal
            cli()

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Interrumpido por el usuario.[/yellow]")
        sys.exit(0)

    except Exception as e:
        console.print(f"[red bold]✗ Error fatal: {e}[/red bold]")
        if settings.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()