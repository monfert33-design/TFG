import subprocess
from pathlib import Path
from typing import Dict, Any, List

# Rutas de logs autorizadas que el agente puede inspeccionar
ALLOWED_LOGS = {
    "auth": Path("/var/log/auth.log"),
    "syslog": Path("/var/log/syslog"),
    "kern": Path("/var/log/kern.log"),
    "nginx_access": Path("/var/log/nginx/access.log"),
    "nginx_error": Path("/var/log/nginx/error.log")
}

def tool_leer_segmento_log(tipo_log: str, ultimas_lineas: int = 50) -> Dict[str, Any]:
    """
    Lee las últimas N líneas de un log del sistema permitido.
    """
    if tipo_log not in ALLOWED_LOGS:
        return {
            "error": f"Log no permitido. Fuentes válidas: {list(ALLOWED_LOGS.keys())}"
        }

    log_path = ALLOWED_LOGS[tipo_log]
    if not log_path.exists():
        return {"error": f"El archivo de log {log_path} no existe en este servidor."}

    try:
        # Limitamos a un máximo de 150 líneas para no desbordar el contexto de la IA
        n = min(max(ultimas_lineas, 5), 150)
        result = subprocess.run(
            ["tail", "-n", str(n), str(log_path)],
            capture_output=True,
            text=True,
            timeout=5
        )
        return {
            "tipo_log": tipo_log,
            "lineas_leidas": n,
            "contenido": result.stdout
        }
    except Exception as e:
        return {"error": f"Fallo al leer log: {str(e)}"}


def tool_listar_conexiones_red(filtro_ip: str = "") -> Dict[str, Any]:
    """
    Inspecciona sockets y conexiones de red activas (TCP/UDP) mediante ss.
    Permite filtrar por una IP sospechosa específica.
    """
    try:
        # ss -antp: sockets TCP numéricos con proceso asociado
        cmd = ["ss", "-antp"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        
        lines = result.stdout.splitlines()
        header = lines[0] if lines else ""
        data_lines = lines[1:] if len(lines) > 1 else []

        if filtro_ip.strip():
            target_ip = filtro_ip.strip()
            data_lines = [l for l in data_lines if target_ip in l]

        # Tomamos hasta 40 conexiones relevantes
        data_lines = data_lines[:40]

        return {
            "total_encontradas": len(data_lines),
            "filtro_aplicado": filtro_ip,
            "conexiones": "\n".join([header] + data_lines) if data_lines else "No hay sockets activos coincidentes."
        }
    except Exception as e:
        return {"error": f"Fallo al inspeccionar conexiones de red: {str(e)}"}


def tool_inspeccionar_procesos(filtro: str = "") -> Dict[str, Any]:
    """
    Lista procesos en ejecución para detectar posibles shells reversas o binarios anómalos.
    """
    try:
        cmd = ["ps", "aux"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        
        lines = result.stdout.splitlines()
        header = lines[0] if lines else ""
        data_lines = lines[1:] if len(lines) > 1 else []

        if filtro.strip():
            f = filtro.strip().lower()
            data_lines = [l for l in data_lines if f in l.lower()]

        # Limitamos la salida para mantener el contexto limpio
        data_lines = data_lines[:30]

        return {
            "total_procesos": len(data_lines),
            "filtro": filtro,
            "procesos": "\n".join([header] + data_lines) if data_lines else "No se encontraron procesos coincidentes."
        }
    except Exception as e:
        return {"error": f"Fallo al listar procesos: {str(e)}"}


# ================= DEFINICIÓN DEL ESQUEMA JSON PARA GROQ =================
# Esta lista le explica al LLM en su propio formato qué herramientas tiene disponibles y cuándo usarlas

AGENT_TOOLS_SPEC: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "tool_leer_segmento_log",
            "description": "Lee las últimas líneas de un log del sistema (auth, syslog, kern, nginx_access, nginx_error).",
            "parameters": {
                "type": "object",
                "properties": {
                    "tipo_log": {
                        "type": "string",
                        "enum": ["auth", "syslog", "kern", "nginx_access", "nginx_error"],
                        "description": "El tipo de log a consultar."
                    },
                    "ultimas_lineas": {
                        "type": "integer",
                        "description": "Número de líneas a recuperar (entre 10 y 100)."
                    }
                },
                "required": ["tipo_log"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "tool_listar_conexiones_red",
            "description": "Consulta conexiones de red activas en el servidor para verificar si una IP sigue conectada o atacando.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filtro_ip": {
                        "type": "string",
                        "description": "Dirección IP para filtrar los sockets (opcional)."
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "tool_inspeccionar_procesos",
            "description": "Inspecciona la tabla de procesos activos para detectar ejecuciones sospechosas, shells o comandos vinculados a un ataque.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filtro": {
                        "type": "string",
                        "description": "Nombre del binario, usuario o término a buscar (ej: sshd, python, sh, nc)."
                    }
                }
            }
        }
    }
]
