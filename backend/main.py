import os
import json
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from google import genai
from google.genai import types
# Importamos las herramientas locales del agente
import agent_tools
# ================= 1. CONFIGURACIÓN Y CLIENTE =================
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(dotenv_path=BASE_DIR / ".env")

app = FastAPI(title="DFIR Agentic Platform", version="3.1.0")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
MODEL_NAME = os.getenv("AI_MODEL", "gemini-2.5-flash")

if not GEMINI_API_KEY:
    raise RuntimeError("Falta configurar GEMINI_API_KEY en el archivo .env")

client = genai.Client(api_key=GEMINI_API_KEY)

AUTH_LOG_PATH = Path("/var/log/auth.log")
CURSOR_FILE = BASE_DIR / ".log_cursor.json"

AVAILABLE_FUNCTIONS = {
    "tool_leer_segmento_log": agent_tools.tool_leer_segmento_log,
    "tool_listar_conexiones_red": agent_tools.tool_listar_conexiones_red,
    "tool_inspeccionar_procesos": agent_tools.tool_inspeccionar_procesos
}
# ================= 2. PROMPT =================
SYSTEM_PROMPT_AGENT = """
Eres un Agente Autónomo de Investigación Forense Digital y Respuesta a Incidentes (DFIR).
Analizas telemetría sospechosa en un servidor Linux.

INSTRUCCIONES:
1. Puedes solicitar herramientas de inspección si necesitas corroborar si el atacante mantiene sockets abiertos o procesos sospechosos.
2. Una vez completada la investigación, emite tu DICTAMEN PERICIAL FINAL.

FORMATO OBLIGATORIO DE RESPUESTA FINAL (JSON estricto sin bloques de texto adicionales):
{
  "ataque_detectado": true,
  "tipo_ataque": "Nombre formal (ej. Fuerza Bruta SSH)",
  "tecnica_mitre": "T1110.001 - Password Guessing",
  "severidad": "CRÍTICA | ALTA | MEDIA | BAJA | INFORMATIVA",
  "ip_atacante": "192.168.56.X o null",
  "usuario_objetivo": "root u otro o null",
  "resumen_forense": "Dictamen pericial exhaustivo detallando la evidencia hallada en el sistema.",
  "accion_propuesta": {
    "requiere_accion": true,
    "tipo": "BLOQUEAR_IP",
    "objetivo": "192.168.56.X",
    "comando_sugerido": "iptables -I INPUT -s 192.168.56.X -j DROP",
    "justificacion": "Cortar el intento de autenticación automatizada en el servidor."
  }
}
Si la actividad es legítima o ruido operativo, pon "ataque_detectado": false, "severidad": "BAJA", y en "accion_propuesta" pon "requiere_accion": false.
"""
# ================= 3. CODE =================
def get_last_cursor() -> int:
    if CURSOR_FILE.exists():
        try:
            with open(CURSOR_FILE, "r") as f:
                return json.load(f).get("byte_offset", 0)
        except Exception:
            return 0
    return 0

def save_cursor(offset: int):
    with open(CURSOR_FILE, "w") as f:
        json.dump({"byte_offset": offset, "updated_at": datetime.utcnow().isoformat()}, f)

def read_new_log_entries() -> tuple[str, int, bool]:
    if not AUTH_LOG_PATH.exists():
        raise HTTPException(status_code=500, detail="No se encuentra /var/log/auth.log")

    current_size = AUTH_LOG_PATH.stat().st_size
    last_offset = get_last_cursor()

    if current_size < last_offset:
        last_offset = 0

    if last_offset == 0 and current_size > 3000:
        last_offset = current_size - 3000

    with open(AUTH_LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(last_offset)
        new_content = f.read()
        new_offset = f.tell()

    lines = [l for l in new_content.splitlines() if l.strip()]
    return "\n".join(lines), new_offset, len(lines) > 0


@app.post("/api/forensics/ai-analyze")
def agentic_forensic_analysis() -> Dict[str, Any]:
    new_logs, proposed_offset, has_new_logs = read_new_log_entries()

    if not has_new_logs:
        return {
            "caso_id": None,
            "timestamp_analisis": datetime.utcnow().isoformat() + "Z",
            "nuevas_lineas": 0,
            "sin_cambios": True,
            "mensaje": "Sin nuevas entradas de telemetría."
        }

    evidence_hash = hashlib.sha256(new_logs.encode("utf-8")).hexdigest()
    lines = new_logs.splitlines()
    line_count = len(lines)
    sample_logs = "\n".join(lines[-40:]) if line_count > 40 else new_logs

    # Lista de herramientas en formato nativo para Google GenAI
    tools_callables = list(AVAILABLE_FUNCTIONS.values())

    chat = client.chats.create(
        model=MODEL_NAME,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT_AGENT,
            temperature=0.1,
            tools=tools_callables
        )
    )

    prompt_inicial = f"Nueva ventana de eventos en auth.log ({line_count} líneas detectadas):\n\n{sample_logs}"
    response = chat.send_message(prompt_inicial)

    # Bucle de interacción con herramientas si el modelo las invoca
    max_turns = 3
    turns = 0
    while response.function_calls and turns < max_turns:
        turns += 1
        tool_responses = []
        for call in response.function_calls:
            func_name = call.name
            func_args = dict(call.args) if call.args else {}
            if func_name in AVAILABLE_FUNCTIONS:
                tool_output = AVAILABLE_FUNCTIONS[func_name](**func_args)
            else:
                tool_output = {"error": f"Herramienta {func_name} no disponible"}

            tool_responses.append(
                types.Part.from_function_response(
                    name=func_name,
                    response={"result": tool_output}
                )
            )

        response = chat.send_message(tool_responses)

    final_text = (response.text or "{}").strip()

    if final_text.startswith("```json"):
        final_text = final_text[7:]
    if final_text.startswith("```"):
        final_text = final_text[3:]
    if final_text.endswith("```"):
        final_text = final_text[:-3]

    try:
        dictamen_ia = json.loads(final_text.strip())
    except Exception:
        # Petición de fallback para forzar el formato JSON si hubo dispersión
        fallback_prompt = "Resume tu análisis final respetando estrictamente el esquema JSON solicitado."
        fallback_res = chat.send_message(
            fallback_prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.1
            )
        )
        dictamen_ia = json.loads((fallback_res.text or "{}").strip())

    save_cursor(proposed_offset)

    return {
        "caso_id": f"CASE-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
        "timestamp_analisis": datetime.utcnow().isoformat() + "Z",
        "evidencia_sha256": evidence_hash,
        "lineas_analizadas": line_count,
        "sin_cambios": False,
        "dictamen_pericial": dictamen_ia
    }


# ================= ENDPOINT DE REMEDIACIÓN ACTIVA (HITL) =================
class RemediationRequest(BaseModel):
    tipo: str
    objetivo: str
    justificacion: Optional[str] = None

@app.post("/api/remediation/apply")
def apply_remediation(req: RemediationRequest) -> Dict[str, Any]:
    if req.tipo == "BLOQUEAR_IP":
        ip = req.objetivo.strip()

        if ip in ["127.0.0.1", "localhost", "::1"]:
            raise HTTPException(status_code=400, detail="No se puede bloquear la interfaz local.")

        try:
            check_cmd = ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]
            exists = subprocess.run(check_cmd, capture_output=True).returncode == 0
            if exists:
                return {
                    "status": "ya_aplicado",
                    "mensaje": f"La IP {ip} ya se encontraba bloqueada en iptables."
                }

            apply_cmd = ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.run(apply_cmd, capture_output=True, text=True, check=True)

            return {
                "status": "exito",
                "mensaje": f"IP {ip} bloqueada exitosamente en el firewall del servidor.",
                "comando_ejecutado": f"iptables -I INPUT -s {ip} -j DROP",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        except subprocess.CalledProcessError as e:
            raise HTTPException(status_code=500, detail=f"Fallo al ejecutar iptables: {e.stderr}")
    else:
        raise HTTPException(status_code=400, detail=f"Tipo de acción '{req.tipo}' no soportada.")
