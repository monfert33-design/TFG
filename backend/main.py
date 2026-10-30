import os
import json
import hashlib
import traceback
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from google import genai
from google.genai import types

import agent_tools

# ==============================================================================
# 1. CARGA DE CONFIGURACIÓN Y CLIENTE DE IA
# ==============================================================================
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(dotenv_path=BASE_DIR / ".env")

app = FastAPI(
    title="DFIR Gemini Multi-Incident Platform",
    version="4.3.0",
    description="Motor defensivo con ingesta multicanal, auditoría de kernel, FIM e inferencia agéntica"
)

LLM_API_KEY = os.getenv("LLM_API_KEY")
MODEL_NAME = os.getenv("AI_MODEL", "gemini-2.5-flash")

if not LLM_API_KEY:
    raise RuntimeError("Falta LLM_API_KEY en el archivo .env")

# Cliente oficial
client = genai.Client(api_key=LLM_API_KEY)

# ==============================================================================
# 2. DEFINICIÓN DE FUENTES DE TELEMETRÍA Y CONTROL DE INTEGRIDAD
# ==============================================================================
# Rutas de los canales del sistema bajo monitorización
LOG_SOURCES = {
    "auth": Path("/var/log/auth.log"),
    "kernel": Path("/var/log/kern.log"),
    "nginx": Path("/var/log/nginx/access.log"),
    "syslog": Path("/var/log/syslog"),
    "audit": Path("/var/log/audit/audit.log")
}

# Archivos y binarios esenciales auditados por el verificador de integridad FIM
CRITICAL_FILES = [
    Path("/etc/passwd"),
    Path("/etc/shadow"),
    Path("/etc/sudoers"),
    Path("/bin/ps"),
    Path("/bin/ls")
]

# Archivos de persistencia local de estado
FIM_CACHE_FILE = BASE_DIR / ".fim_hashes.json"
CURSOR_FILE = BASE_DIR / ".log_cursor.json"

# ==============================================================================
# 3. DIRECTIVAS DE SISTEMA PARA EL AGENTE FORENSE
# ==============================================================================
SYSTEM_PROMPT_AGENT = """
Eres un Agente Especialista en DFIR y Respuesta a Incidentes en Linux.
Analizas telemetría heterogénea multicanal (auth, kernel, nginx, syslog, audit de kernel y FIM).

INSTRUCCIÓN CLAVE:
Si en la telemetría conviven vectores de ataque distintos (ej. escaneo Nmap en kernel, inyección en nginx, o intento de elevación de privilegios en auth), NO los fusiones en una sola alerta. Debes separarlos como incidentes distintos dentro de la lista 'incidentes'.

VECTORES RECONOCIDOS:
- Red: Escaneos Nmap SYN (T1046).
- Acceso: Fuerza bruta SSH (T1110.001).
- Web: Inyección SQL, Path Traversal, Fuzzing (T1190).
- Escalada / Abuso: Fuerza bruta o fallos en sudo/su (T1548.003).
- Persistencia: Inyección de tareas programadas (T1053.003).
- Ejecución / C2: Shell reversa activa (T1059.004).
- Evasión de Defensas: Truncado de logs (T1070.002).
- Acceso a Credenciales: Lectura no autorizada de secretos (T1003.008).
- Ejecución de Binarios Furtivos / Malware: Ejecución de scripts o binarios sospechosos en /tmp o /dev/shm detectados por auditd (T1059 / T1204 - User Execution).
- Manipulación de Binarios del Sistema (Trojaning / FIM): Alteración de archivos críticos del SO o binarios core detectada por hash o auditoría (T1036 - Masquerading, T1565 - Data Manipulation).

EN ACCIÓN PROPUESTA:
- Si detectas una shell reversa activa o proceso malicioso con PID identificado:
  "tipo": "MATAR_PROCESO",
  "objetivo": "PID_DEL_PROCESO",
  "comando_sugerido": "kill -9 PID_DEL_PROCESO",
  "justificacion": "Terminar la sesión interactiva del atacante."
- Si es un ataque de red externo:
  "tipo": "BLOQUEAR_IP",
  "objetivo": "IP_ATACANTE",
  "comando_sugerido": "iptables -I INPUT -s IP_ATACANTE -j DROP"
- Si es alteración de registros o evasión:
  "tipo": "AUDITAR_SISTEMA",
  "objetivo": "Archivo o subsistema afectado",
  "comando_sugerido": "chattr +a /var/log/auth.log (o inspección de procesos activos)",
  "justificacion": "Impedir la sobrescritura y preservar la cadena de custodia forense."
- Si es robo de credenciales vía web:
  "tipo": "BLOQUEAR_IP",
  "objetivo": "IP_ATACANTE",
  "comando_sugerido": "iptables -I INPUT -s IP_ATACANTE -j DROP"
- Si es intento local sobre archivos protegidos:
  "tipo": "AUDITAR_SISTEMA",
  "objetivo": "Archivo comprometido (ej. /etc/shadow)",
  "comando_sugerido": "chmod 000 /etc/shadow; auditctl -w /etc/shadow -p rwa -k shadow_access",
  "justificacion": "Revocar permisos temporales y activar auditoría inmediata sobre el fichero."

DEBES responder con un objeto JSON estrictamente válido con esta estructura:
{
  "incidentes": [
    {
      "ataque_detectado": true,
      "canal_origen": "kernel | auth | nginx | syslog | audit | fim",
      "tipo_ataque": "Nombre formal (ej. Abuso de Privilegios Sudo / Persistencia Cron / Fuerza Bruta SSH)",
      "tecnica_mitre": "T1548.003 o técnica correspondiente",
      "severidad": "CRÍTICA | ALTA | MEDIA | BAJA | INFORMATIVA",
      "ip_atacante": "IP detectada o null si es local",
      "usuario_objetivo": "root o usuario afectado",
      "resumen_forense": "Dictamen específico detallando la evidencia hallada en el canal.",
      "accion_propuesta": {
        "requiere_accion": true,
        "tipo": "BLOQUEAR_IP | AISLAR_USUARIO | AUDITAR_SISTEMA | MATAR_PROCESO",
        "objetivo": "IP o usuario o PID objetivo",
        "comando_sugerido": "iptables -I INPUT -s IP -j DROP o comando aplicable",
        "justificacion": "Mitigación del vector de ataque."
      }
    }
  ]
}
Si la actividad es legítima o ruido operativo sin peligro, pon "ataque_detectado": false, "severidad": "BAJA", y "requiere_accion": false.
No incluyas explicaciones en texto plano fuera del objeto JSON.
"""

# ==============================================================================
# 4. GESTIÓN DE CURSORES MULTICANAL Y FIM
# ==============================================================================
def get_cursors() -> Dict[str, int]:
    """Carga los desplazamientos (offsets en bytes) previos de cada archivo de telemetría."""
    if CURSOR_FILE.exists():
        try:
            with open(CURSOR_FILE, "r") as f:
                data = json.load(f)
                return data.get("offsets", {})
        except Exception:
            return {}
    return {}

def save_cursors(offsets: Dict[str, int]):
    """Persiste los desplazamientos actualizados tras una lectura exitosa."""
    with open(CURSOR_FILE, "w") as f:
        json.dump({"offsets": offsets, "updated_at": datetime.utcnow().isoformat()}, f)

def check_file_integrity() -> List[str]:
    """Verifica alteraciones no autorizadas en ficheros sensibles mediante hashes SHA-256."""
    alerts = []
    saved_hashes = {}
    if FIM_CACHE_FILE.exists():
        try:
            with open(FIM_CACHE_FILE, "r") as f:
                saved_hashes = json.load(f)
        except Exception:
            saved_hashes = {}

    current_hashes = {}
    for fpath in CRITICAL_FILES:
        if not fpath.exists():
            continue
        try:
            h = hashlib.sha256(fpath.read_bytes()).hexdigest()
            current_hashes[str(fpath)] = h

            if str(fpath) in saved_hashes and saved_hashes[str(fpath)] != h:
                alerts.append(
                    f"ALERTA_FIM: Modificación no autorizada del binario/archivo crítico {fpath} "
                    f"(Hash previo: {saved_hashes[str(fpath)][:10]}... -> Actual: {h[:10]}...)"
                )
        except Exception:
            pass

    with open(FIM_CACHE_FILE, "w") as f:
        json.dump(current_hashes, f)

    return alerts

def collect_multisource_telemetry() -> tuple[Dict[str, List[str]], Dict[str, int], bool]:
    """
    Lee deltas en los cinco canales de telemetría, ejecuta filtrado por firmas,
    detecta evasiones por truncado de logs y ejecuta el escaneo de integridad FIM.
    """
    cursors = get_cursors()
    new_offsets = dict(cursors)
    aggregated_events: Dict[str, List[str]] = {}
    total_new_lines = 0

    for source_key, file_path in LOG_SOURCES.items():
        if not file_path.exists():
            continue

        try:
            current_size = file_path.stat().st_size
            last_offset = cursors.get(source_key, 0)

            # Control de evasión: si el archivo disminuye de tamaño abruptamente fue truncado
            if current_size < last_offset:
                aggregated_events.setdefault("security_alerts", []).append(
                    f"ALERTA_INTEGRIDAD: El archivo {file_path} ha sido truncado/vaciado intencionadamente "
                    f"(tamaño previo: {last_offset}B -> nuevo: {current_size}B). Posible evasión de defensas."
                )
                total_new_lines += 1
                last_offset = 0

            # Inicialización para ficheros voluminosos en primer arranque
            if last_offset == 0 and current_size > 3000:
                last_offset = current_size - 3000

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(last_offset)
                content = f.read()
                new_offsets[source_key] = f.tell()

            raw_lines = [l.strip() for l in content.splitlines() if l.strip()]

            # --- FILTRADO POR PATRONES DE AMENAZA ---
            if source_key == "kernel":
                raw_lines = [l for l in raw_lines if "FW_PORT_SCAN" in l or "DROPPED" in l]

            elif source_key == "nginx":
                patrones_web = [
                    "../", "..%2f", "etc/passwd", "select", "union", "%27", "'",
                    "<script", "wp-config", "gobuster", "sqlmap", "nikto", "dirb",
                    ".env", ".git", "id_rsa", "config.php", "backup", ".sql"
                ]
                lineas_sospechosas = []
                for l in raw_lines:
                    l_lower = l.lower()
                    if any(p in l_lower for p in patrones_web) or " 404 " in l or " 403 " in l:
                        lineas_sospechosas.append(l)
                raw_lines = lineas_sospechosas

            elif source_key == "auth":
                patrones_auth = [
                    "sshd", "sudo:", "su:", "pam_unix", "failed password",
                    "authentication failure", "useradd", "new user", "password changed",
                    "/etc/shadow", "id_rsa", "unauthorized access"
                ]
                raw_lines = [l for l in raw_lines if any(p in l.lower() for p in patrones_auth)]

            elif source_key == "syslog":
                patrones_syslog = [
                    "cron", "crontab", "systemd[1]: started", "systemd[1]: stopped",
                    "reverse shell", "segfault", "oom-killer", "rsyslogd: received",
                    "clearing log", "history -c", "bash_history", "audit:", "AVC apparmor"
                ]
                raw_lines = [l for l in raw_lines if any(p in l.lower() for p in patrones_syslog)]

            elif source_key == "audit":
                patrones_audit = ["execution_tmp", "execution_shm", "binary_tampering", "net_config", "type=EXECVE"]
                raw_lines = [l for l in raw_lines if any(p in l for p in patrones_audit)]

            if raw_lines:
                # Acotamos a un bloque representativo para optimizar contexto
                aggregated_events[source_key] = raw_lines[-30:]
                total_new_lines += len(aggregated_events[source_key])

        except Exception as e:
            print(f"Error al procesar fuente {source_key}: {e}")

    # Ejecución del escaneo de integridad de archivos críticos
    fim_alerts = check_file_integrity()
    if fim_alerts:
        aggregated_events.setdefault("fim_alerts", []).extend(fim_alerts)
        total_new_lines += len(fim_alerts)

    return aggregated_events, new_offsets, total_new_lines > 0

# ==============================================================================
# 5. ENDPOINTS DE LA API REST
# ==============================================================================
@app.post("/api/forensics/ai-analyze")
def agentic_forensic_analysis() -> Dict[str, Any]:
    """
    Recolecta telemetría, calcula el hash SHA-256 de la evidencia
    y consulta al modelo de Gemini para clasificar los incidentes detectados.
    """
    events_by_source, proposed_offsets, has_new_events = collect_multisource_telemetry()

    if not has_new_events:
        return {
            "caso_id": None,
            "timestamp_analisis": datetime.utcnow().isoformat() + "Z",
            "nuevas_lineas": 0,
            "sin_cambios": True,
            "mensaje": "Sin novedades en los canales de telemetría."
        }

    # Sello criptográfico SHA-256 sobre la evidencia estructurada
    evidence_payload = json.dumps(events_by_source, sort_keys=True)
    evidence_hash = hashlib.sha256(evidence_payload.encode("utf-8")).hexdigest()
    total_lines = sum(len(lines) for lines in events_by_source.values())

    # Agrupación de contextos por canal para la IA
    context_blocks = []
    for src, lines in events_by_source.items():
        context_blocks.append(f"=== CANAL [{src.upper()}] ({len(lines)} eventos) ===\n" + "\n".join(lines))
    telemetry_text = "\n\n".join(context_blocks)

    user_prompt = f"Analiza esta telemetría reciente ({total_lines} líneas):\n\n{telemetry_text}"

    try:
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT_AGENT,
                temperature=0.1,
                response_mime_type="application/json"
            )
        )

        final_text = (response.text or "").strip()

        # Limpieza de posibles bloques markdown
        if final_text.startswith("```json"):
            final_text = final_text[7:]
        if final_text.startswith("```"):
            final_text = final_text[3:]
        if final_text.endswith("```"):
            final_text = final_text[:-3]

        dictamen_ia = json.loads(final_text.strip())

        # Normalización de la lista de incidentes
        if isinstance(dictamen_ia, dict) and "incidentes" in dictamen_ia:
            incidentes_detectados = dictamen_ia["incidentes"]
        elif isinstance(dictamen_ia, list):
            incidentes_detectados = dictamen_ia
        else:
            incidentes_detectados = [dictamen_ia]

        # Guardado del puntero únicamente tras un análisis y parseo exitoso
        save_cursors(proposed_offsets)

    except Exception as e:
        print("\n--- ERROR DETALLADO EN GENERATE_CONTENT ---")
        traceback.print_exc()
        print("------------------------------------------\n")
        raise HTTPException(status_code=500, detail=f"Fallo en Gemini: {str(e)}")

    primer_dictamen = incidentes_detectados[0] if incidentes_detectados else {}

    return {
        "caso_id": f"CASE-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
        "timestamp_analisis": datetime.utcnow().isoformat() + "Z",
        "evidencia_sha256": evidence_hash,
        "lineas_analizadas": total_lines,
        "sin_cambios": False,
        "incidentes": incidentes_detectados,
        "dictamen_pericial": primer_dictamen
    }

@app.post("/api/forensics/reset-cursor")
def reset_cursor():
    """Restablece los punteros de lectura al tamaño actual de cada archivo."""
    offsets = {}
    for k, v in LOG_SOURCES.items():
        if v.exists():
            offsets[k] = v.stat().st_size
    save_cursors(offsets)
    return {"status": "Cursores reseteados al final actual."}

# ==============================================================================
# 6. MODELOS Y ENDPOINTS DE REMEDIACIÓN SUPERVISADA (HITL)
# ==============================================================================
class RemediationRequest(BaseModel):
    tipo: str
    objetivo: str
    justificacion: Optional[str] = None

@app.post("/api/remediation/apply")
def apply_remediation(req: RemediationRequest) -> Dict[str, Any]:
    """
    Ejecuta en el sistema operativo la contramedida autorizada por el analista
    desde el panel de control de Avalonia UI.
    """
    if req.tipo == "BLOQUEAR_IP":
        ip = req.objetivo.strip()
        if ip in ["127.0.0.1", "localhost", "::1"]:
            raise HTTPException(status_code=400, detail="No se puede bloquear la interfaz local.")

        try:
            # Comprobar idempotencia: verificar si la regla ya existía previamente
            check_cmd = ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]
            exists = subprocess.run(check_cmd, capture_output=True).returncode == 0
            if exists:
                return {"status": "ya_aplicado", "mensaje": f"La IP {ip} ya se encontraba bloqueada."}

            apply_cmd = ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.run(apply_cmd, capture_output=True, text=True, check=True)
            return {
                "status": "exito",
                "mensaje": f"IP {ip} bloqueada exitosamente.",
                "comando_ejecutado": f"iptables -I INPUT -s {ip} -j DROP",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        except subprocess.CalledProcessError as e:
            raise HTTPException(status_code=500, detail=f"Fallo al ejecutar iptables: {e.stderr}")

    elif req.tipo == "MATAR_PROCESO":
        pid = req.objetivo.strip()
        # Validación de seguridad: evitar matar init/systemd o procesos núcleo
        if not pid.isdigit() or int(pid) <= 1:
            raise HTTPException(status_code=400, detail="PID no válido o protegido del sistema.")

        try:
            apply_cmd = ["sudo", "kill", "-9", pid]
            subprocess.run(apply_cmd, capture_output=True, text=True, check=True)
            return {
                "status": "exito",
                "mensaje": f"Proceso malicioso PID {pid} terminado inmediatamente.",
                "comando_ejecutado": f"kill -9 {pid}",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        except subprocess.CalledProcessError as e:
            raise HTTPException(status_code=500, detail=f"Fallo al terminar proceso: {e.stderr}")

    else:
        raise HTTPException(status_code=400, detail=f"Tipo de acción '{req.tipo}' no soportada.")

# ==============================================================================
# 7. DIAGNÓSTICO INICIAL
# ==============================================================================
@app.get("/api/system/health")
def system_health_check() -> Dict[str, Any]:
    """Diagnóstico rápido de subsistemas para la pantalla de carga."""
    # 1. Comprobación de lectura en canales de logs
    logs_status = {}
    for key, path in LOG_SOURCES.items():
        logs_status[key] = path.exists() and os.access(path, os.R_OK)

    # 2. Comprobación de auditd y reglas activas
    auditd_active = False
    try:
        res = subprocess.run(["sudo", "auditctl", "-s"], capture_output=True, text=True)
        auditd_active = "enabled 1" in res.stdout or "enabled 2" in res.stdout
    except Exception:
        auditd_active = False

    # 3. Comprobación del modelo LLm
    llm_status = False
    llm_error = None
    try:
        test_resp = client.models.generate_content(
            model=MODEL_NAME,
            contents="ping",
            config=types.GenerateContentConfig(max_output_tokens=5)
        )
        if test_resp and test_resp.text:
            llm_status = True
    except Exception as e:
        llm_error = str(e)

    all_ready = all(logs_status.values()) and llm_status

    return {
        "status": "ready" if all_ready else "degraded",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "subsystems": {
            "llm_ai": {"ok": llm_status, "model": MODEL_NAME, "error": llm_error},
            "kernel_auditd": {"ok": auditd_active},
            "telemetry_sources": logs_status,
            "fim_cache_ready": FIM_CACHE_FILE.exists()
        }
    }
