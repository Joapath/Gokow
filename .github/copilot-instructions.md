# Instrucciones de Copilot para Gokow

Guía específica para trabajar con el proyecto Gokow.

## Estado Actual de Desarrollo

**Fase Actual**: Fase 2 - Arquitectura Limpia (85% completada)

### Completado en Fase 1 ✅
- Estructura de proyecto con src layout
- Entorno virtual y todas las dependencias instaladas
- BaseScanner y ScanResult implementados
- Sistema de configuración con Pydantic
- OPSEC integrado en base.py
- Formateo de salida (JSON, CSV, Markdown, Text)
- CLI básico con Click
- Menú interactivo inicial

### En Progreso - Fase 2 🔄
- [x] Refactorización de menú interactivo con arquitectura limpia
  - Separación: UI (interactive.py) → State (menu_state.py) → Config (menu_config.py)
  - Componentes reutilizables (menu_components.py)
  - Múltiples screens para cada paso del flujo

- [x] Validador completo de targets (validators.py)
  - Soporta: IP simple, rango, CIDR, dominio, subdominio, URL
  - Detección automática de tipo
  - Validación de puertos

- [x] Sistema de logging centralizado (logger.py)
  - Logging a console con Rich
  - Persistencia en archivos con rotación
  - Singleton para uso global

- [x] Documentación completa
  - ARCHITECTURE.md: Estructura y patrones
  - DEVELOPMENT.md: Guía para desarrolladores
  - README.md: Documentación de usuario

- [x] CLI mejorado
  - Validación de targets con callbacks
  - Comandos más limpios y documentados
  - Mejor organización con grupos

### Próximas en Fase 2
- [ ] Testeo de menú interactivo en terminal
- [ ] Verificación de navegación entre screens
- [ ] Pruebas de validaciones

### Fase 3 - Próxima: Implementar Scanners Core
- Host Discovery (descubrimiento de hosts)
- Port Scanner (escaneo de puertos)
- DNS Enumeration (enumeración DNS)
- Service Detection (detección de servicios)

## Principios de Código

### SIEMPRE SEGUIR
1. **Type Hints Obligatorios**
   ```python
   def procesar(target: str) -> bool:  # Siempre
   ```

2. **Docstrings en Español**
   ```python
   def scan(self) -> ScanResult:
       """
       Ejecutar escaneo.
       
       Returns:
           ScanResult con hallazgos
       """
   ```

3. **Separación UI ↔ Lógica**
   - UI no accede directamente a modules/
   - Usa MenuState o CLI handlers
   - Lógica no conoce de Textual/Rich (salvo imports)

4. **Validación en Entrada**
   - Usar TargetValidator para targets
   - Usar ConfigValidator para configuraciones
   - Callbacks en Click para CLI

5. **Modularidad**
   - Archivos < 500 líneas
   - Funciones con responsabilidad única
   - Reutilizar componentes

### EVITAR
- Silenciar excepciones sin loguear
- Código duplicado (extraer a utils/)
- Funciones con múltiples responsabilidades
- Imports circulares (revisar estructura)
- Hardcoding (usar config/)

## Estructura de Directorios

```
src/gokow/
├── __init__.py
├── main.py                    # Punto de entrada
├── ARCHITECTURE.md            # Documentación interna
│
├── cli/                       # User Interface
│   ├── commands.py            # Comandos Click
│   ├── interactive.py         # Aplicación Textual
│   ├── menu_config.py         # Configuración del menú
│   ├── menu_state.py          # Gestor de estado
│   └── menu_components.py     # Componentes de UI
│
├── modules/                   # Core functionality
│   ├── base.py                # BaseScanner, ScanResult
│   └── scanner/               # Implementaciones
│       ├── port_scanner.py
│       ├── dns_scanner.py
│       └── ...
│
├── config/
│   └── settings.py            # Configuración con Pydantic
│
└── utils/
    ├── opsec.py               # OPSEC Manager
    ├── formatters.py          # Formateadores de salida
    ├── validators.py          # Validadores de entrada
    └── logger.py              # Sistema de logging

tests/                         # (Pendiente)
```

## Cómo Extender

### Agregar Nuevo Scanner

1. **Crear archivo**:
   ```python
   # src/gokow/modules/scanner/mi_scanner.py
   class MiScanner(BaseScanner):
       async def scan(self) -> ScanResult:
           self._log_finding("info", "Título", "Detalles")
           return self.result
   ```

2. **Agregar comando**:
   ```python
   # cli/commands.py
   @categoria.command()
   @click.argument('target', callback=validate_target)
   def mi_comando(ctx, target):
       console.print("[cyan]Ejecutando...[/cyan]")
   ```

3. **Actualizar menú**:
   - menu_config.py - SCAN_CATEGORIES

### Agregar Nueva Categoría

1. Actualizar `menu_config.py` (SCAN_CATEGORIES)
2. Crear grupo en `cli/commands.py`
3. Menú se actualiza automáticamente

## Ejecución y Testing

```bash
# Entrar al directorio
cd /home/iwnl/Tools/multifuncional

# Activar venv
source venv/bin/activate

# Instalar en modo desarrollo
pip install -e .

# Ejecutar menú interactivo
gokow

# Ejecutar comando CLI
gokow recon-network host-discovery 192.168.1.1

# Ver ayuda
gokow --help
gokow recon-network --help

# Modo verbose
gokow -v recon-network host-discovery 192.168.1.1

# Modo sigiloso
gokow -s recon-network host-discovery 192.168.1.1

# Salida en JSON
gokow -f json recon-network host-discovery 192.168.1.1
```

## Recursos Documentación

- **Textual**: https://textual.textualize.io/
- **Click**: https://click.palletsprojects.com/
- **Rich**: https://rich.readthedocs.io/
- **Pydantic**: https://docs.pydantic.dev/
- **Scapy**: https://scapy.readthedocs.io/

## Próximos Pasos

1. **Testing del Menú** (Fase 2 final)
   - Confirmar navegación entre screens
   - Verificar validaciones
   - Testear keyboard bindings

2. **Implementar Scanner Host Discovery** (Fase 3)
   - Usar Scapy o ping
   - Integrar con OPSEC
   - Retornar ScanResult formateado

3. **Crear Suite de Tests**
   - Tests para validators
   - Tests para menu_state
   - Tests para scanners individuales

## Recuerde

- **Código limpio es código mantenible**
- **Documentación = Menos búsqueda luego**
- **Separación de concerns = Fácil de testear**
- **OPSEC primero = Seguridad asegurada**
- **El usuario viene primero = Buena UX**

---

Última actualización: 2024 - Fase 2 (85% - Arquitectura Limpia)