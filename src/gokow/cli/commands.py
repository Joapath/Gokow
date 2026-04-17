"""
Comandos CLI de Gokow.

Define todos los comandos disponibles organizados por categoría.
Utiliza Click para proporcionar una interfaz de línea de comandos intuitiva.
"""

import asyncio
import json
import click
from rich.console import Console
from pathlib import Path

from gokow.config.settings import settings
from gokow.utils.formatters import ErrorFormatter, ScanFormatter
from gokow.utils.validators import TargetValidator, ConfigValidator
from gokow.modules.scanner.host_discovery import HostDiscoveryScanner
from gokow.modules.scanner.port_scanner import PortScanner
from gokow.modules.scanner.dns_scanner import DNSEnumerationScanner
from gokow.modules.scanner.service_detection import ServiceDetectionScanner
from gokow.modules.scanner.subdomain_scanner import SubdomainEnumerationScanner
from gokow.modules.scanner.web_fingerprinting import WebFingerprintingScanner
from gokow.modules.scanner.content_discovery import ContentDiscoveryScanner
from gokow.modules.scanner.ssl_tls_scanner import SSLTLSAnalysisScanner

console = Console()


def validate_target(ctx, param, value):
    """Callback para validar target."""
    if value:
        es_valido, mensaje, tipo = TargetValidator.validar(value)
        if not es_valido:
            raise click.BadParameter(mensaje)
    return value


@click.group(invoke_without_command=True)
@click.option('--config', type=click.Path(exists=True), help='Archivo de configuración YAML')
@click.option('--verbose', '-v', is_flag=True, help='Modo verbose')
@click.option('--stealth', '-s', is_flag=True, help='Modo sigiloso (OPSEC)')
@click.option('--output', '-o', type=click.Path(), help='Archivo de salida')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'csv', 'markdown']), 
              default='text', help='Formato de salida')
@click.pass_context
def cli(ctx, config, verbose, stealth, output, format):
    """
    Gokow - Herramienta avanzada de pentesting.

    Proporciona reconocimiento de seguridad con enfoque en OPSEC.
    """
    ctx.ensure_object(dict)
    ctx.obj['config'] = config
    ctx.obj['verbose'] = verbose
    ctx.obj['stealth'] = stealth
    ctx.obj['output'] = output
    ctx.obj['format'] = format

    # Actualizar configuración global
    settings.debug = verbose
    settings.default_config.opsec.stealth = stealth
    settings.default_config.output_format = format
    if output:
        settings.default_config.output_file = output

    # Si no hay subcomando, mostrar ayuda
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


def run_async_scanner(scanner_class, target: str, config: dict, ctx):
    """Helper para ejecutar scanner async."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    scanner = scanner_class(target, config)
    result = loop.run_until_complete(scanner.scan())
    
    # Convertir ScanResult a dict para formateo
    result_dict = {
        'scan_type': result.scan_type,
        'target': result.target,
        'findings': [
            {
                'severity': f.get('severity', 'info'),
                'title': f.get('title', 'Sin título'),
                'details': f.get('details', ''),
                'timestamp': f.get('timestamp', '')
            }
            for f in result.findings
        ],
        'start_time': str(result.start_time) if result.start_time else None,
        'end_time': str(result.end_time) if result.end_time else None,
    }
    
    # Formatear salida
    format_choice = ctx.obj.get('format', 'text')
    output_file = ctx.obj.get('output')
    
    output = ScanFormatter.format_scan_results(result_dict, format_choice)
    
    # No imprimir nada si el formatter ya hizo print (para text)
    if format_choice != 'text':
        console.print(output)
    
    if output_file:
        Path(output_file).write_text(output if output else json.dumps(result_dict, indent=2, default=str))
        console.print(f"[green]✓ Resultados guardados en: {output_file}[/green]")


# Grupo: Reconocimiento de Red
@cli.group()
def recon_network():
    """
    🌐 Reconocimiento de red y superficie.

    Descubrimiento de hosts, escaneo de puertos e identificación de servicios.
    """
    pass


@recon_network.command()
@click.argument('target', callback=validate_target)
@click.option('--timeout', type=int, default=2, help='Timeout en segundos')
@click.option('--techniques', type=str, default='icmp,arp,tcp', help='Técnicas: icmp,arp,tcp')
@click.pass_context
def host_discovery(ctx, target, timeout, techniques):
    """
    Descubrir hosts activos en una red.

    Usa ICMP, ARP y TCP para identificar sistemas activos.
    Resistente a WAF y proxies (múltiples técnicas).
    """
    try:
        console.print(f"[cyan]Iniciando descubrimiento de hosts...[/cyan]")
        console.print(f"  • Target: {target}")
        console.print(f"  • Timeout: {timeout}s")
        console.print(f"  • Técnicas: {techniques}")
        
        if ctx.obj.get('stealth'):
            console.print(f"  [yellow]• Modo sigiloso activado[/yellow]")

        config = {
            'timeout': timeout,
            'techniques': techniques.split(','),
            'opsec': {'stealth': ctx.obj.get('stealth', False)}
        }
        
        run_async_scanner(HostDiscoveryScanner, target, config, ctx)

    except Exception as e:
        ErrorFormatter.format_error(str(e))
        ctx.exit(1)


@recon_network.command()
@click.argument('target', callback=validate_target)
@click.option('--ports', default='1-1000', help='Rango de puertos (ej: 1-1000, 80,443,8080)')
@click.option('--timeout', type=int, default=2, help='Timeout por puerto')
@click.option('--technique', type=click.Choice(['connect', 'syn']), default='connect', 
              help='Técnica de escaneo')
@click.pass_context
def port_scan(ctx, target, ports, timeout, technique):
    """
    Escanear puertos abiertos.

    Soporta:
    - TCP Connect (compatible con WAF)
    - TCP SYN (stealth mode)
    """
    try:
        console.print(f"[cyan]Iniciando escaneo de puertos...[/cyan]")
        console.print(f"  • Target: {target}")
        console.print(f"  • Puertos: {ports}")
        console.print(f"  • Técnica: {technique}")
        console.print(f"  • Timeout: {timeout}s")

        if ctx.obj.get('stealth'):
            console.print(f"  [yellow]• Modo sigiloso activado[/yellow]")

        config = {
            'ports': ports,
            'timeout': timeout,
            'technique': technique,
            'rate_limit': 0.05 if ctx.obj.get('stealth') else 0.02,
            'opsec': {'stealth': ctx.obj.get('stealth', False)}
        }
        
        run_async_scanner(PortScanner, target, config, ctx)

    except Exception as e:
        ErrorFormatter.format_error(str(e))
        ctx.exit(1)


@recon_network.command()
@click.argument('target', callback=validate_target)
@click.option('--ports', default='80,443,22,21,3306', help='Puertos a analyizar')
@click.option('--timeout', type=int, default=5, help='Timeout para conexión')
@click.pass_context
def service_detection(ctx, target, ports, timeout):
    """
    Detectar servicios en puertos abiertos.

    Identifica:
    - Web servers (Apache, Nginx, IIS)
    - SSH, FTP y otros servicios
    - Versiones (cuando es posible)
    """
    try:
        console.print(f"[cyan]Iniciando detección de servicios...[/cyan]")
        console.print(f"  • Target: {target}")
        console.print(f"  • Puertos: {ports}")
        console.print(f"  • Timeout: {timeout}s")

        if ctx.obj.get('stealth'):
            console.print(f"  [yellow]• Modo sigiloso activado[/yellow]")

        config = {
            'ports': ports,
            'timeout': timeout,
            'opsec': {'stealth': ctx.obj.get('stealth', False)}
        }
        
        run_async_scanner(ServiceDetectionScanner, target, config, ctx)

    except Exception as e:
        ErrorFormatter.format_error(str(e))
        ctx.exit(1)


# Grupo: DNS y Activos
@cli.group()
def dns_active():
    """
    🔍 DNS y activos.

    Enumeración DNS, resolución de nombres y detección de wildcard.
    """
    pass


@dns_active.command()
@click.argument('domain')
@click.option('--record-types', default='A,AAAA,MX,NS,TXT,SOA', 
              help='Tipos de registros a enumerar')
@click.option('--timeout', type=int, default=5, help='Timeout DNS')
@click.pass_context
def enumerate(ctx, domain, record_types, timeout):
    """
    Enumerar registros DNS de un dominio.

    Consulta múltiples tipos de registros:
    - A/AAAA (IPv4/IPv6)
    - MX (Mail servers)
    - NS (Nameservers)
    - TXT (SPF, DKIM, etc.)
    - SOA (Start of Authority)
    """
    try:
        console.print(f"[cyan]Enumerando DNS para {domain}[/cyan]")
        console.print(f"  • Dominio: {domain}")
        console.print(f"  • Tipos: {record_types}")
        console.print(f"  • Timeout: {timeout}s")

        config = {
            'record_types': record_types.split(','),
            'timeout': timeout,
            'opsec': {'stealth': ctx.obj.get('stealth', False)}
        }
        
        run_async_scanner(DNSEnumerationScanner, domain, config, ctx)

    except Exception as e:
        ErrorFormatter.format_error(str(e))
        ctx.exit(1)


# Grupo: Descubrimiento de Subdominios
@cli.group()
def subdomain_discovery():
    """
    🎯 Descubrimiento de subdominios.

    Búsqueda pasiva y activa de subdominios.
    """
    pass


@subdomain_discovery.command()
@click.argument('domain')
@click.option('--timeout', type=int, default=10, help='Timeout para DNS queries')
@click.pass_context
def enumerate(ctx, domain, timeout):
    """
    Enumerar subdominios usando múltiples técnicas.

    Incluye:
    - DNS brute-force
    - Certificate Transparency
    - CNAME enumeration
    """
    try:
        console.print(f"[cyan]Enumerando subdominios para {domain}[/cyan]")
        console.print(f"  • Dominio: {domain}")
        console.print(f"  • Timeout: {timeout}s")

        if ctx.obj.get('stealth'):
            console.print(f"  [yellow]• Modo sigiloso activado[/yellow]")

        config = {
            'timeout': timeout,
            'opsec': {'stealth': ctx.obj.get('stealth', False)}
        }
        
        run_async_scanner(SubdomainEnumerationScanner, domain, config, ctx)

    except Exception as e:
        ErrorFormatter.format_error(str(e))
        ctx.exit(1)


# Grupo: Fingerprinting Web
@cli.group()
def web_fingerprint():
    """
    🔎 Fingerprinting web.

    Detección de tecnologías, servidores y frameworks.
    """
    pass


@web_fingerprint.command()
@click.argument('target')
@click.option('--timeout', type=int, default=5, help='Timeout de conexión')
@click.pass_context
def detect(ctx, target, timeout):
    """
    Detectar tecnologías en un servidor web.

    Identifica:
    - Servidor web (Apache, Nginx, IIS)
    - CMS (WordPress, Drupal, etc)
    - Frameworks y versiones
    - Headers de seguridad
    """
    try:
        console.print(f"[cyan]Detectando tecnologías en {target}[/cyan]")
        console.print(f"  • Target: {target}")
        console.print(f"  • Timeout: {timeout}s")

        if ctx.obj.get('stealth'):
            console.print(f"  [yellow]• Modo sigiloso activado[/yellow]")

        config = {
            'timeout': timeout,
            'opsec': {'stealth': ctx.obj.get('stealth', False)}
        }
        
        run_async_scanner(WebFingerprintingScanner, target, config, ctx)

    except Exception as e:
        ErrorFormatter.format_error(str(e))
        ctx.exit(1)


# Grupo: Descubrimiento de Contenido
@cli.group()
def content_discovery():
    """
    📁 Descubrimiento de contenido.

    Enumeración de directorios y archivos.
    """
    pass


@content_discovery.command()
@click.argument('target')
@click.option('--timeout', type=int, default=5, help='Timeout de conexión')
@click.option('--max-concurrent', type=int, default=5, help='Requests concurrentes')
@click.pass_context
def enumerate_paths(ctx, target, timeout, max_concurrent):
    """
    Enumerar directorios y archivos en un servidor web.

    Realiza brute-force de directorios comunes:
    - Rutas públicas
    - Backups
    - Archivos de configuración
    - Directorios de desarrollo
    """
    try:
        console.print(f"[cyan]Enumerando contenido en {target}[/cyan]")
        console.print(f"  • Target: {target}")
        console.print(f"  • Timeout: {timeout}s")
        console.print(f"  • Concurrent: {max_concurrent}")

        if ctx.obj.get('stealth'):
            console.print(f"  [yellow]• Modo sigiloso activado[/yellow]")

        config = {
            'timeout': timeout,
            'max_concurrent': max_concurrent,
            'opsec': {'stealth': ctx.obj.get('stealth', False)}
        }
        
        run_async_scanner(ContentDiscoveryScanner, target, config, ctx)

    except Exception as e:
        ErrorFormatter.format_error(str(e))
        ctx.exit(1)


# Grupo: Análisis SSL/TLS
@cli.group()
def ssl_analysis():
    """
    🔒 Análisis SSL/TLS y certificados.

    Análisis de certificados, cipher suites y detección de vulnerabilidades.
    """
    pass


@ssl_analysis.command()
@click.argument('target', callback=validate_target)
@click.option('--port', type=int, default=443, help='Puerto SSL/TLS')
@click.option('--timeout', type=int, default=10, help='Timeout en segundos')
@click.option('--no-vulns', is_flag=True, help='Omitir verificación de vulnerabilidades')
@click.pass_context
def analyze(ctx, target, port, timeout, no_vulns):
    """
    Analizar configuración SSL/TLS completa.

    Incluye:
    - Validación de certificado
    - Cipher suites soportadas
    - Detección de vulnerabilidades comunes
    - Información del servidor
    """
    try:
        console.print(f"[cyan]Iniciando análisis SSL/TLS...[/cyan]")
        console.print(f"  • Target: {target}")
        console.print(f"  • Puerto: {port}")
        console.print(f"  • Timeout: {timeout}s")
        console.print(f"  • Verificar vulnerabilidades: {'No' if no_vulns else 'Sí'}")

        if ctx.obj.get('stealth'):
            console.print(f"  [yellow]• Modo sigiloso activado[/yellow]")

        config = {
            'port': port,
            'timeout': timeout,
            'check_vulnerabilities': not no_vulns,
            'opsec': {'stealth': ctx.obj.get('stealth', False)}
        }
        
        run_async_scanner(SSLTLSAnalysisScanner, target, config, ctx)

    except Exception as e:
        ErrorFormatter.format_error(str(e))
        ctx.exit(1)


# Comandos raíz útiles
@cli.command()
@click.pass_context
def interactive(ctx):
    """
    Lanzar interfaz interactiva (menú TUI).

    Proporciona una experiencia más amigable para principiantes.
    """
    from gokow.cli.interactive import run_interactive_menu
    run_interactive_menu()


@cli.command()
def version():
    """Mostrar versión de Gokow."""
    console.print(f"[cyan bold]Gokow[/cyan bold] v{settings.version}")
    console.print("[dim]Herramienta avanzada de pentesting[/dim]")


@cli.command()
@click.option('--output', type=click.Path(), required=True, help='Archivo de salida')
def generate_config(output):
    """
    Generar archivo de configuración de ejemplo.

    Crea un template YAML para personalizar Gokow.
    """
    try:
        config_template = """# Configuración de Gokow
app:
  name: Gokow
  version: 0.1.0
  debug: false

# Configuración OPSEC
opsec:
  stealth: true
  delays:
    min: 1.0
    max: 3.0
  user_agent_rotation: true

# Configuración de escaneos
scanning:
  timeout: 5
  max_workers: 4
  output_format: text
  
# Configuración de reportes
reporting:
  save_history: true
  history_dir: ./reports
"""
        Path(output).write_text(config_template)
        console.print(f"[green]✓ Archivo de configuración generado: {output}[/green]")

    except Exception as e:
        ErrorFormatter.format_error(str(e))


if __name__ == '__main__':
    cli()