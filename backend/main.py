import os
import json
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from google import genai
from google.genai import types

# ================= 1. CARGA DE CONFIGURACIÓN (.env) =================
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(dotenv_path=BASE_DIR / ".env")

app = FastAPI(title="DFIR AI Assistant", version="2.0.0")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
MODEL_NAME = os.getenv("AI_MODEL", "gemini-3.5-flash")

if not GEMINI_API_KEY:
    raise RuntimeError("Falta configurar GEMINI_API_KEY en el archivo .env")

# Cliente oficial de Google GenAI
client = genai.Client(api_key=GEMINI_API_KEY)

# ================= 2. PROMPT DE INGENIERÍA FORENSE =================
SYSTEM_PROMPT_FORENSE = """
Eres un perito experto en Ciberseguridad y Análisis Forense Digital (DFIR).
Analiza las líneas de log proporcionadas correspondientes a un incidente en un servidor Linux.

DEBES responder EXCLUSIVAMENTE en formato JSON estricto con los siguientes campos:
{
  "ataque_detectado": true,
  "tipo_ataque": "Nombre del vector de ataque (ej. Fuerza Bruta SSH)",
  "tecnica_mitre": "Código y Nombre MITRE ATT&CK (ej. T1110.001 - Password Guessing)",
  "severidad": "CRÍTICA | ALTA | MEDIA | BAJA",
  "ip_atacante": "IP origen detectada o null",
  "usuario_objetivo": "Usuario atacado o null",
  "resumen_forense": "Explicación pericial concisa de la evidencia encontrada.",
  "contramedida_recomendada": "Comando iptables o regla concreta para frenar el incidente"
}
Si la actividad es legítima o ruido operativo, pon "ataque_detectado": false, "severidad": "BAJA", "ip_atacante": null y "usuario_objetivo": null.
No devuelvas texto adicional, explicaciones ni formato markdown fuera del bloque JSON.
"""

# ================= 3. ENDPOINTS =================
@app.post("/api/forensics/ai-analyze")
def ai_analyze_incident() -> Dict[str, Any]:
    """Extrae las últimas evidencias de auth.log, genera el hash SHA-256 y solicita el triaje pericial a Gemini."""
    try:
        # 1. Extracción de evidencia cruda (últimas 30 líneas de auth.log)
        result = subprocess.run(
            ["tail", "-n", "30", "/var/log/auth.log"],
            capture_output=True,
            text=True,
            check=True
        )
        log_sample = result.stdout.strip()
        if not log_sample:
            raise HTTPException(status_code=400, detail="El registro auth.log está vacío.")

        # 2. Sellado de integridad forense (SHA-256)
        evidence_hash = hashlib.sha256(log_sample.encode("utf-8")).hexdigest()

        # 3. Consulta al modelo de Gemini
        user_prompt = f"Analiza esta evidencia cruda de autenticación:\n\n{log_sample}"
        
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

        # Limpieza defensiva de bloques markdown en caso de que el modelo los incluya
        if final_text.startswith("```json"):
            final_text = final_text[7:]
        if final_text.startswith("```"):
            final_text = final_text[3:]
        if final_text.endswith("```"):
            final_text = final_text[:-3]

        dictamen_ia = json.loads(final_text.strip())

        return {
            "caso_id": f"CASE-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            "timestamp_analisis": datetime.utcnow().isoformat() + "Z",
            "evidencia_sha256": evidence_hash,
            "lineas_analizadas": 30,
            "dictamen_pericial": dictamen_ia
        }

    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Error al leer /var/log/auth.log: {e.stderr}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error durante el análisis forense: {str(e)}")
