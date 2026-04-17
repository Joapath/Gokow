"""Output formatters using Rich."""

from rich.table import Table
from rich.panel import Panel
from rich.console import Console
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing import List, Dict, Any
import json
import csv
from pathlib import Path

console = Console()


class ScanFormatter:
    """Handles output formatting for scan results."""

    @staticmethod
    def format_scan_results(results: Dict[str, Any], output_format: str = "text") -> str:
        """Format scan results in the specified format."""
        if output_format == "json":
            return json.dumps(results, indent=2, default=str)
        elif output_format == "csv":
            return ScanFormatter._to_csv(results)
        elif output_format == "markdown":
            return ScanFormatter._to_markdown(results)
        else:
            return ScanFormatter._to_text(results)

    @staticmethod
    def _to_text(results: Dict[str, Any]) -> str:
        """Format as rich text table."""
        table = Table(title=f"Resultados de escaneo - {results.get('scan_type', 'Desconocido')}")

        if results.get('findings'):
            table.add_column("Severidad", style="red", no_wrap=True)
            table.add_column("Título", style="cyan")
            table.add_column("Detalles", style="yellow")

            for finding in results['findings']:
                table.add_row(
                    finding.get('severity', 'info'),
                    finding.get('title', 'Sin título'),
                    str(finding.get('details', {}))
                )
        else:
            table.add_row("Sin hallazgos", "", "")

        console.print(table)
        return ""

    @staticmethod
    def _to_csv(results: Dict[str, Any]) -> str:
        """Format as CSV."""
        output = []
        if results.get('findings'):
            output.append("severity,title,details,timestamp")
            for finding in results['findings']:
                output.append(
                    f"{finding.get('severity', 'info')},"
                    f"{finding.get('title', 'Sin título')},"
                    f"{finding.get('details', {})},"
                    f"{finding.get('timestamp', '')}"
                )
        return "\n".join(output)

    @staticmethod
    def _to_markdown(results: Dict[str, Any]) -> str:
        """Format as Markdown."""
        lines = [f"# Resultados de escaneo - {results.get('scan_type', 'Desconocido')}\n"]

        if results.get('findings'):
            lines.append("| Severidad | Título | Detalles | Timestamp |")
            lines.append("|-----------|--------|----------|-----------|")

            for finding in results['findings']:
                lines.append(
                    f"| {finding.get('severity', 'info')} | "
                    f"{finding.get('title', 'Sin título')} | "
                    f"{finding.get('details', {})} | "
                    f"{finding.get('timestamp', '')} |"
                )
        else:
            lines.append("Sin hallazgos encontrados.")

        return "\n".join(lines)

    @staticmethod
    def save_results(results: Dict[str, Any], output_file: Path, output_format: str = "text"):
        """Save results to file."""
        formatted = ScanFormatter.format_scan_results(results, output_format)

        if output_format == "text":
            # For text, we already printed, so save the dict as JSON
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
        else:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(formatted)

        console.print(f"[green]Resultados guardados en {output_file}[/green]")

    @staticmethod
    def create_progress() -> Progress:
        """Create a progress bar."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        )


class ErrorFormatter:
    """Handles error formatting."""

    @staticmethod
    def format_error(error: str):
        """Format and display an error."""
        console.print(f"[bold red]ERROR:[/bold red] {error}")

    @staticmethod
    def format_warning(warning: str):
        """Format and display a warning."""
        console.print(f"[bold yellow]WARNING:[/bold yellow] {warning}")

    @staticmethod
    def format_info(info: str):
        """Format and display info."""
        console.print(f"[bold blue]INFO:[/bold blue] {info}")

    @staticmethod
    def format_success(success: str):
        """Format and display success."""
        console.print(f"[bold green]SUCCESS:[/bold green] {success}")