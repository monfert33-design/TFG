import os
import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Tuple
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from google import genai
from google.genai import types

# ================= 1. CONFIGURACIÓN Y CLIENTE =================
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(dotenv_path=BASE_DIR / ".env")

app = FastAPI(title="DFIR AI Assistant - Stateful Engine", version="2.5.0")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
MODEL_NAME = os.getenv("AI_MODEL", "gemini-2.5-flash")

if not GEMINI_API_KEY:
    raise RuntimeError("Falta configurar GEMINI_API_KEY en el archivo .env")

client = genai.Client(api_key=GEMINI_API_KEY)

AUTH_LOG_PATH = Path("/var/log/auth.log")
CURSOR_FILE = BASE_DIR / ".log_cursor.json"

# ================= 2. PROMPT =================
SYSTEM_PROMPT_FORENSE = """
Eres un Perito Judicial en Ciberseguridad e Ingeniero Senior de DFIR (Digital Forensics and Incident Response).
Analiza con rigor forense estricto las NUEVAS líneas de telemetría de autenticación (/var/log/auth.log) recibidas.
Tu análisis debe ser técnico y exhaustivo, deduciendo intencionalidad, metodología y origen.

DEBES responder EXCLUSIVAMENTE con un objeto JSON válido con la siguiente estructura exacta:
{
  "ataque_detectado": true,
  "tipo_ataque": "Nombre formal del incidente (ej. Fuerza Bruta SSH / Password Spraying)",
  "tecnica_mitre": "ID y Nombre oficial MITRE ATT&CK (ej. T1110.001 - Password Guessing)",
  "severidad": "CRÍTICA | ALTA | MEDIA | BAJA | INFORMATIVA",
  "ip_atacante": "IP origen detectada (o null si es local)",
  "usuario_objetivo": "Cuenta de destino afectada (o null)",
  "metricas_ataque": {
    "intentos_estimados": 0,
    "rango_puertos_origen": "ej. 45000-45120 o null",
    "frecuencia": "Ráfaga de alta velocidad (<2 seg) | Espaciado | N/A"
  },
  "resumen_forense": "Dictamen pericial detallado: describe la secuencia temporal exacta y evidencia encontrada.",
  "impacto_potencial": "Riesgo real para la integridad, confidencialidad o disponibilidad del servidor.",
  "contramedida_recomendada": "Comando exacto de mitigación en consola (ej. iptables -I INPUT -s IP -j DROP)"
}
Si no hay indicios de amenaza y es actividad normal, pon "ataque_detectado": false, "severidad": "BAJA", y null en los campos correspondientes.
No devuelvas texto fuera del bloque JSON.
"""

# ================= 3. CONTROL DE CURSOR Y ESTADO =================
def get_last_cursor() -> int:
    """Obtiene la posición en bytes del archivo procesado anteriormente."""
    if CURSOR_FILE.exists():
        try:
            with open(CURSOR_FILE, "r") as f:
                data = json.load(f)
                return data.get("byte_offset", 0)
        except Exception:
            return 0
    return 0

def save_cursor(offset: int):
    """Guarda la posición en bytes para no volver a procesar registros antiguos."""
    with open(CURSOR_FILE, "w") as f:
        json.dump({"byte_offset": offset, "updated_at": datetime.utcnow().isoformat()}, f)

def read_new_log_entries() -> Tuple[str, int, bool]:
    """
    Lee únicamente las líneas nuevas desde el último offset guardado.
    Maneja la rotación de logs (logrotate) y primeras ejecuciones.
    """
    if not AUTH_LOG_PATH.exists():
        raise HTTPException(status_code=500, detail="No se encuentra el archivo /var/log/auth.log")

    current_size = AUTH_LOG_PATH.stat().st_size
    last_offset = get_last_cursor()

    # Detección de logrotate: el archivo fue truncado o reemplazado
    if current_size < last_offset:
        last_offset = 0

    # Inicialización de primer arranque si el fichero es voluminoso
    if last_offset == 0 and current_size > 4000:
        last_offset = current_size - 4000

    with open(AUTH_LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(last_offset)
        new_content = f.read()
        new_offset = f.tell()

    lines = [l for l in new_content.splitlines() if l.strip()]
    has_new_logs = len(lines) > 0

    return "\n".join(lines), new_offset, has_new_logs

# ================= 4. ENDPOINTS =================
@app.post("/api/forensics/ai-analyze")
def ai_analyze_incident() -> Dict[str, Any]:
    """Lee únicamente los nuevos deltas de logs y ejecuta el dictamen forense."""
    try:
        new_logs, proposed_offset, has_new_logs = read_new_log_entries()

        # Si no hay líneas nuevas, se aborta la consulta a la IA ahorrando recursos
        if not has_new_logs:
            return {
                "caso_id": None,
                "timestamp_analisis": datetime.utcnow().isoformat() + "Z",
                "nuevas_lineas": 0,
                "sin_cambios": True,
                "mensaje": "No se registraron nuevas líneas en auth.log desde el último análisis."
            }

        evidence_hash = hashlib.sha256(new_logs.encode("utf-8")).hexdigest()
        line_count = len(new_logs.splitlines())

        user_prompt = f"Analiza esta nueva ventana de telemetría de auth.log ({line_count} líneas):\n\n{new_logs}"

        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT_FORENSE,
                temperature=0.1,
                response_mime_type="application/json"
            )
        )

        final_text = (response.text or "{}").strip()

        if final_text.startswith("```json"):
            final_text = final_text[7:]
        if final_text.startswith("```"):
            final_text = final_text[3:]
        if final_text.endswith("```"):
            final_text = final_text[:-3]

        dictamen_ia = json.loads(final_text.strip())

        # Solo persistimos el nuevo cursor si la llamada y el parseo tuvieron éxito
        save_cursor(proposed_offset)

        return {
            "caso_id": f"CASE-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            "timestamp_analisis": datetime.utcnow().isoformat() + "Z",
            "evidencia_sha256": evidence_hash,
            "lineas_analizadas": line_count,
            "sin_cambios": False,
            "dictamen_pericial": dictamen_ia
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error durante el análisis forense: {str(e)}")

@app.post("/api/forensics/reset-cursor")
def reset_cursor():
    """Endpoint auxiliar para mover el cursor al final actual del fichero."""
    if AUTH_LOG_PATH.exists():
        save_cursor(AUTH_LOG_PATH.stat().st_size)
        return {"status": "Cursor reseteado al final del archivo."}
    return {"status": "Error", "detail": "El archivo de log no existe."}
