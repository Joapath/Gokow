"""
Documentación de Arquitectura de Gokow.

Este módulo proporciona una visión general de la estructura del proyecto.

ESTRUCTURA DEL PROYECTO
=======================

gokow/
├── __init__.py              # Metadatos del módulo
├── main.py                  # Punto de entrada principal
│
├── cli/                     # Interfaz de usuario (CLI e Interactivo)
│   ├── __init__.py
│   ├── commands.py          # Definiciones de comandos Click
│   ├── interactive.py       # Aplicación TUI con Textual
│   ├── menu_config.py       # Configuración y constantes del menú
│   ├── menu_state.py        # Gestor de estado del menú
│   └── menu_components.py   # Componentes reutilizables de UI
│
├── modules/                 # Módulos de escaneo (funcionalidad core)
│   ├── __init__.py
│   ├── base.py              # Clases base para scanners
│   └── scanner/             # Implementación de scanners específicos
│       ├── __init__.py
│       ├── port_scanner.py
│       ├── dns_scanner.py
│       └── ...
│
├── config/                  # Gestión de configuración
│   ├── __init__.py
│   └── settings.py          # Configuración con Pydantic
│
├── models/                  # Modelos de datos
│   ├── __init__.py
│   ├── scan_result.py
│   └── ...
│
└── utils/                   # Utilidades compartidas
    ├── __init__.py
    ├── opsec.py             # Gestión de OPSEC
    ├── formatters.py        # Formateo de salida
    ├── validators.py        # Validación de entrada
    └── logger.py            # Logging (futuro)


FLUJO DE EJECUCIÓN
==================

1. INICIO (main.py)
   └─► Sin argumentos: Menú interactivo
   └─► Con argumentos: CLI

2. MENÚ INTERACTIVO (cli/interactive.py) - PHASE 3 ✅
   ├─► GokowMenu (app principal)
   ├─► CategorySelectionScreen (seleccionar categoría)
   ├─► OPSECSelectionScreen (seleccionar OPSEC)
   ├─► TargetInputScreen (ingresar target)
   ├─► ScannerSelectionScreen (NEW - seleccionar scanner específico)
   ├─► ScanProgressScreen (NEW - ejecutar y mostrar progreso)
   └─► MenuState (gestión de estado + scanner_type)

3. CLI (cli/commands.py) - PHASE 3 ✅
   ├─► Click groups por categoría
   ├─► Commands específicos (host_discovery, port_scan, service_detection, dns_enumerate)
   ├─► Validators para validar entrada
   └─► run_async_scanner() helper para ejecutar scanners async

4. EJECUCIÓN DE ESCANEO (modules/base.py + modules/scanner/)
   ├─► BaseScanner (clase base con OPSEC integrado)
   ├─► HostDiscoveryScanner (ICMP, ARP, TCP methods)
   ├─► PortScanner (TCP Connect + SYN, banner grabbing)
   ├─► DNSEnumerationScanner (8+ record types, async DNS)
   ├─► ServiceDetectionScanner (HTTP, SSH, FTP, generic)
   ├─► OPSEC Integration (utils/opsec.py - async delays + headers)
   └─► ScanResult (modelos con resultados)

5. FORMATO Y SALIDA (utils/formatters.py)
   ├─► JSON, CSV, Markdown, Text
   └─► Rich console output


PATRONES DE DISEÑO USADOS
=========================

1. SEPARACIÓN DE RESPONSABILIDADES

   UI Layer (cli/)
   ├─ No accede directamente a modules/
   ├─ Va a través de MenuState o CLI handlers
   └─ Responsable: Presentación

   Business Logic (modules/)
   ├─ No conoce de UI
   ├─ Responsable: Escaneo y análisis
   └─ Retorna ScanResult

   Configuration (config/)
   ├─ Centralizada
   └─ Accesible desde todos lados

2. STATE PATTERN (menu_state.py)
   ├─ MenuState mantiene el estado
   ├─ UI consulta y modifica el estado
   └─ Fácil de testear y debuggear

3. FACTORY PATTERN (base.py)
   ├─ BaseScanner como clase base
   └─ Subclasses específicas para cada tipo

4. STRATEGY PATTERN (opsec.py)
   ├─ OPSECManager encapsula estrategias
   ├─ Fácil agregar nuevas técnicas
   └─ Configurable en tiempo de ejecución


CÓMO EXTENDER EL PROYECTO
===========================

AGREGAR UN NUEVO SCANNER

1. Crear archivo en modules/scanner/:
   # modules/scanner/my_scanner.py
   
   from gokow.modules.base import BaseScanner, ScanResult
   
   class MyScanner(BaseScanner):
       async def scan(self) -> ScanResult:
           # Implementar lógica
           self._log_finding("info", "Hallazgo encontrado")
           return self.result

2. Registrar comando en cli/commands.py:
   
   @recon_network.command()
   @click.argument('target')
   def my_scan(ctx, target):
       # Usar MyScanner aquí

3. Agregar entrada en menu_config.py si es necesario


AGREGAR UNA NUEVA CATEGORÍA

1. Actualizar menu_config.py (SCAN_CATEGORIES)
2. Crear arquivo de scanner si es necesario
3. Agregar grupo Click en cli/commands.py
4. Actualizar menú interactivo automáticamente (usa SCAN_CATEGORIES)


IMPORTANTE: CONVENCIONES DE CÓDIGO
===================================

- Usar type hints en todas las funciones
- Documentar con docstrings en español
- Separar UI de lógica de negocio
- Mantener archivos <500 líneas
- Usar async/await para operaciones I/O
- Validar entrada en la capa de entrada
- Log de errores, no silenciar


PHASE 3: SCANNERS CORE - IMPLEMENTACIÓN ✅
============================================

SCANNERS DISPONIBLES

1. HostDiscoveryScanner (host_discovery.py)
   ├─ Métodos: ICMP ping, ARP broadcast, TCP connect
   ├─ Evasión: Múltiples técnicas, limitación de IPs
   ├─ Uso CLI: gokow recon-network host-discovery <target>
   ├─ Uso Menú: Categoría → Recon Network → Host Discovery
   
2. PortScanner (port_scanner.py)
   ├─ Técnicas: TCP Connect (default), TCP SYN (stealth)
   ├─ Características: Banner grabbing, service fingerprinting
   ├─ Evasión: Randomización puerto origen, delays, rate limiting
   ├─ Uso CLI: gokow recon-network port-scan <target> --ports 1-1000
   
3. DNSEnumerationScanner (dns_scanner.py)
   ├─ Registros: A, AAAA, CNAME, MX, NS, TXT, SOA, SRV
   ├─ Características: Queries asincrónicas, preservación TTL
   ├─ Ventaja: DNS no bloqueado por WAF/proxy
   ├─ Uso CLI: gokow dns-active enumerate <domain>
   
4. ServiceDetectionScanner (service_detection.py)
   ├─ Protocolos: HTTP, SSH, FTP, generic fallback
   ├─ Características: Análisis de headers, versión extraction
   ├─ Evasión: User-Agent rotation, minimal requests
   ├─ Uso CLI: gokow recon-network service-detection <target>


EVASIÓN WAF/PROXY - TÉCNICAS IMPLEMENTADAS
=============================================

Técnica                    | Scanner      | Implementación
---------------------------|--------------|------------------
Source port randomization  | PortScanner  | socket.bind() random
Request shuffling          | Todos        | random.shuffle()
Rate limiting              | Todos        | 0.05-0.1s delays
User-Agent rotation        | HTTP methods | get_random_user_agent()
Realistic headers          | HTTP methods | Complete header sets
Multi-technique approach   | HostDiscovery| ICMP + ARP + TCP
DNS leverage               | DNSScanner   | Separate channel
Minimal requests           | Service Det. | 1 request per port
Async operations           | Todos        | async/await patterns


INTEGRACIÓN MENÚ + SCANNERS
============================

Flujo desde Menú Interactivo:

GokowMenu → action_run()
    ↓
ScannerSelectionScreen (mostrar scanners de categoría)
    ↓
MenuState.seleccionar_scanner(scanner_type)
    ↓
ScanProgressScreen → _execute_scan()
    ↓
Scanner.scan() (async)
    ↓
ScanResult → Display en TUI


Flujo desde CLI:

Click Command (recon-network port-scan)
    ↓
run_async_scanner() helper
    ↓
asyncio.run(scanner.scan())
    ↓
Formatter (JSON/CSV/Markdown/Text)
    ↓
Console output


FLUJO DE MODIFICACIÓN TÍPICO
=============================

Quiero agregar feature X:

1. Planificar: ¿Qué capa afecta? (UI/Logic/Config)
2. Identificar: ¿Archivo existente o nuevo?
3. Implementar: Mantener patrones existentes
4. Testear: Funcionalidad local
5. Integrar: CLI o menú
6. Documentar: Docstrings y cambios importantes
"""

__all__ = [
    'main',
    'cli',
    'interactive',
]
