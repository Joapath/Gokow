"""
Módulo de configuración y constantes para el menú interactivo.

Define todas las categorías de escaneo, opciones OPSEC y temas visuales.
"""

# Categorías principales de escaneo
SCAN_CATEGORIES = {
    "recon-network": {
        "nombre": "Reconocimiento de Red",
        "descripcion": "Descubrimiento de hosts y escaneo de puertos",
        "icon": "🌐",
        "modulos": [
            "host-discovery",
            "port-scan",
            "service-detection",
        ]
    },
    "dns-active": {
        "nombre": "DNS y Activos",
        "descripcion": "Enumeración DNS y resolución de nombres",
        "icon": "🔍",
        "modulos": [
            "dns-enumeration",
        ]
    },
    "subdomain-discovery": {
        "nombre": "Descubrimiento de Subdominios",
        "descripcion": "Búsqueda pasiva y activa de subdominios",
        "icon": "🎯",
        "modulos": [
            "wordlist-enumeration",
        ]
    },
    "web-fingerprint": {
        "nombre": "Fingerprinting Web",
        "descripcion": "Detección de tecnologías y frameworks",
        "icon": "🔎",
        "modulos": [
            "technology-detection",
        ]
    },
    "content-discovery": {
        "nombre": "Descubrimiento de Contenido",
        "descripcion": "Enumeración de directorios y archivos",
        "icon": "📁",
        "modulos": [
            "directory-enumeration",
        ]
    },
    "web-security": {
        "nombre": "Seguridad Web",
        "descripcion": "Verificaciones de seguridad headers y TLS",
        "icon": "🔐",
        "modulos": [
            "tls-analysis",
        ]
    },
}

# Configuración OPSEC
OPSEC_MODES = {
    "paranoid": {
        "nombre": "Paranoia Máxima",
        "descripcion": "Máxima evasión, muy lento",
        "delay_min": 5.0,
        "delay_max": 15.0,
        "stealth": True,
        "randomize": True,
    },
    "stealth": {
        "nombre": "Modo Sigiloso",
        "descripcion": "Buena evasión, moderadamente lento",
        "delay_min": 2.0,
        "delay_max": 5.0,
        "stealth": True,
        "randomize": True,
    },
    "normal": {
        "nombre": "Normal",
        "descripcion": "Equilibrado",
        "delay_min": 0.5,
        "delay_max": 2.0,
        "stealth": False,
        "randomize": False,
    },
    "aggressive": {
        "nombre": "Agresivo",
        "descripcion": "Rápido pero detectable",
        "delay_min": 0.0,
        "delay_max": 0.5,
        "stealth": False,
        "randomize": False,
    },
}

# Estilos CSS para Textual
MENU_CSS = """
Screen {
    background: $surface;
}

#header-panel {
    width: 100%;
    height: 3;
    background: $boost;
    border: heavy $primary;
}

#title {
    text-align: center;
    width: 100%;
    height: 1;
    content-align: middle top;
}

#subtitle {
    width: 100%;
    height: 1;
    text-align: center;
    color: $text-muted;
}

#main-container {
    width: 100%;
    height: 1fr;
    border: solid $primary;
    padding: 1;
}

#category-section {
    width: 100%;
    height: auto;
    border: solid $accent;
    padding: 1;
}

#opsec-section {
    width: 100%;
    height: auto;
    border: solid $warning;
    padding: 1;
}

#control-section {
    width: 100%;
    height: auto;
    padding: 1;
}

.info-text {
    color: $text-muted;
    margin-bottom: 1;
}

Button {
    margin: 0 1;
}

Button.primary {
    background: $boost;
}

Button.danger {
    background: $error;
}
"""
