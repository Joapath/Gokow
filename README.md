# Gokow - Herramienta Avanzada de Pentesting

Herramienta modular y extensible para pentesting con enfoque en reconocimiento, análisis de seguridad web y OPSEC.

**Tabla de Contenidos**
- [Instalación](#instalación)
- [Uso Rápido](#uso-rápido)
- [Características](#características)
- [Estructura del Proyecto](#estructura-del-proyecto)
- [Progreso del Desarrollo](#progreso-del-desarrollo)

## Instalación

### Requisitos
- Python 3.8+
- pip (gestor de paquetes)

### Pasos

```bash
# 1. Clonar o descargar el proyecto
cd gokow

# 2. Crear entorno virtual
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# o en Windows:
venv\Scripts\activate

# 3. Instalar en modo desarrollo
pip install -e .
```

## Uso Rápido

### Menú Interactivo (Recomendado)

Lanzar la interfaz interactiva con TUI:

```bash
gokow
```

Características:
- Seleccionar categoría de escaneo
- Configurar modo OPSEC
- Ingresar target
- Ejecutar escaneo

### Línea de Comandos (CLI)

Estructura general:
```bash
gokow [OPCIONES] CATEGORÍA COMANDO TARGET [OPCIONES]
```

Opciones globales:
- `--verbose, -v` - Mostrar información detallada
- `--stealth, -s` - Activar modo sigiloso (OPSEC)
- `--config CONFIG` - Usar archivo de configuración YAML
- `--output, -o` - Guardar resultados en archivo
- `--format, -f` - Formato de salida (text, json, csv, markdown)

Ejemplos:

```bash
# Descubrimiento de hosts en una red
gokow recon-network host-discovery 192.168.1.0/24 --timeout 5

# Escaneo de puertos
gokow recon-network port-scan 192.168.1.1 --ports 1-1000

# Enumeración DNS
gokow dns-active enumerate example.com

# Ver versión
gokow version

# Ver ayuda de comando
gokow recon-network --help
```

## Características

### 🛡️ OPSEC Integrado
- Rotación de User-Agent realista
- Delays configurables entre requests
- Headers HTTP realistas
- Cache-busting automático
- Múltiples modos: Paranoia, Sigiloso, Normal, Agresivo

### 📊 Múltiples Formatos de Salida
- Text (por defecto)
- JSON (para integración con otros tools)
- CSV (para análisis en Excel)
- Markdown (para reportes)

### 🎨 Interfaz Amigable
- Menú interactivo intuitivo
- Diseño responsive
- Salida coloreada y formateada
- Mensajes claros de progreso

### 🔧 Altamente Extensible
- Arquitectura modular con BaseScanner
- Fácil agregar nuevos módulos
- Configuración centralizada
- Validación automática de entrada

### 📚 Categorías de Escaneo

1. **Reconocimiento de Red** - Host discovery, Port scanning, Service detection
2. **DNS y Activos** - Enumeración DNS, Wildcard detection, DNSSEC
3. **Descubrimiento de Contenido** - Path discovery, Virtual hosts, Fuzzing
4. **Análisis Web** - Header analysis, Cookie inspection, Form detection
5. **Análisis SSL/TLS** - Certificate analysis, Vulnerabilities, Cipher suite
6. **OSINT Pasivo** - Whois, IP geolocation, Email enumeration
7. **Análisis de Tecnología** - Framework detection, CMS detection, Fingerprinting
8. **Vulnerabilidades Comunes** - SQL injection, XSS, CSRF, LFI/RFI
9. **Análisis de Configuración** - Default credentials, Insecure headers, Misconfigurations
10. **Reportes y Exportación** - HTML reports, PDF generation, Data export

### Entrada de Targets

Formatos soportados:
- **IP Simple**: `192.168.1.1`
- **Rango de IPs**: `192.168.1.1-192.168.1.255`
- **Notación CIDR**: `192.168.1.0/24`
- **Dominio**: `example.com`
- **Subdominio**: `api.example.com`
- **URL**: `https://example.com:8443/path`

## Estructura del Proyecto

```
gokow/
├── src/gokow/
│   ├── cli/                    # Interfaz de usuario
│   │   ├── commands.py         # Comandos CLI con Click
│   │   ├── interactive.py      # Menú TUI con Textual
│   │   ├── menu_config.py      # Configuración del menú
│   │   ├── menu_state.py       # Gestor de estado
│   │   └── menu_components.py  # Componentes reutilizables
│   │
│   ├── modules/                # Módulos de escaneo
│   │   ├── base.py             # Clases base (BaseScanner, ScanResult)
│   │   └── scanner/            # Implementación de scanners
│   │
│   ├── config/                 # Configuración
│   │   └── settings.py         # Configuración con Pydantic
│   │
│   ├── utils/                  # Utilidades
│   │   ├── opsec.py            # Gestor de OPSEC
│   │   ├── formatters.py       # Formateo de salida
│   │   ├── validators.py       # Validación de entrada
│   │   └── logger.py           # Sistema de logging
│   │
│   ├── main.py                 # Punto de entrada
│   └── ARCHITECTURE.md         # Documentación de arquitectura
│
├── tests/                      # Suite de tests (pendiente)
├── pyproject.toml              # Configuración del proyecto
├── README.md                   # Este archivo
├── LICENSE                     # Licencia MIT
└── DEVELOPMENT.md              # Guía de desarrollo

```

Para más detalles, ver [ARCHITECTURE.md](src/gokow/ARCHITECTURE.md).

## Configuración

### Archivo de Configuración YAML

Generar template:
```bash
gokow generate-config --output config.yaml
```

Usar configuración:
```bash
gokow --config config.yaml recon-network ...
```

### Variables de Entorno

```bash
# Activar modo debug
export GOKOW_DEBUG=true

# Configurar timeout por defecto
export GOKOW_TIMEOUT=10
```

## Progreso del Desarrollo

### ✅ Fase 1: Estructura Base (Completada)
- [x] Estructura de proyecto con src layout
- [x] Entorno virtual y dependencias
- [x] BaseScanner y ScanResult
- [x] Sistema de configuración (Pydantic)
- [x] OPSEC integrado
- [x] Formateo de salida (JSON, CSV, Markdown, Text)
- [x] CLI básico con Click
- [x] Menú interactivo inicial

### 🔄 Fase 2: Arquitectura Limpia (En Progreso)
- [x] Refactorización del menú interactivo
- [x] Componentes reutilizables de UI
- [x] Gestor de estado desacoplado
- [x] Validador de targets
- [x] Sistema de logging
- [x] Documentación de arquitectura
- [x] Guía de desarrollo
- [ ] Testing de menú interactivo
- [ ] Integración completa de pantallas

### ⏳ Fase 3: Scanners Core (Próxima)
- [ ] Host Discovery (ICMP, ARP, TCP)
- [ ] Port Scanner (TCP/UDP)
- [ ] DNS Enumeration
- [ ] Service Detection
- [ ] Tests unitarios

### ⏳ Fase 4: Web Scanners
- [ ] Content Discovery
- [ ] Subdomain Enumeration
- [ ] Web Fingerprinting
- [ ] SSL/TLS Analysis

### ⏳ Fase 5-7: Módulos Avanzados y Reportes
- [ ] OSINT pasivo
- [ ] Análisis de vulnerabilidades comunes
- [ ] Generador de reportes
- [ ] Suite de tests completa

## Convenciones de Código

Este proyecto sigue estas convenciones para mantener código limpio:

- **Type Hints**: Todas las funciones tienen type hints
- **Docstrings**: En español, con ejemplos
- **Separación**: UI desacoplada de lógica de negocio
- **Validación**: En capa de entrada
- **Modularidad**: Funciones cortas y reutilizables
- **Nombres**: Claros y descriptivos en español/inglés

Para más detalles, ver [DEVELOPMENT.md](DEVELOPMENT.md).

## Contribuciones

Estamos abiertos a contribuciones. Por favor:

1. Fork el proyecto
2. Crear rama: `git checkout -b feature/nombre`
3. Commit: `git commit -m "feat: descripción"`
4. Push: `git push origin feature/nombre`
5. Pull request

## Licencia

Este proyecto está bajo licencia MIT. Ver [LICENSE](LICENSE).

## Soporte

Para problemas, preguntas o sugerencias:
- Crear un issue en GitHub
- Ver documentación en `src/gokow/ARCHITECTURE.md`
- Consultar guía de desarrollo en `DEVELOPMENT.md`

---

**Versión**: 0.1.0  
**Estado**: En desarrollo (Fase 2)  
**Última actualización**: 2024