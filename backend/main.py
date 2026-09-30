import re
import hashlib
from datetime import datetime
from typing import List, Dict, Any
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="DFIR Forensics Agent", version="1.0.0")

LOG_PATH = "/var/log/auth.log"

class ForensicEvidence(BaseModel):
    case_id: str
    timestamp_analysis: str
    target_host: str
    attacker_ip: str
    targeted_user: str
    failed_attempts_count: int
    first_attempt_time: str
    last_attempt_time: str
    attack_technique_mitre: str
    evidence_sha256: str
    raw_log_sample: List[str]

def parse_auth_log() -> Dict[str, Any]:
    failed_attempts = []
    raw_lines = []
    
    # Regex para capturar timestamp, usuario e IP según tu salida real
    # Ejemplo: 2026-09-22T10:05:35.982420+00:00 marcosserver sshd[1449]: Failed password for root from 192.168.56.10
    pattern = re.compile(
        r"^(?P<timestamp>\S+)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
    )

    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return {"error": "Archivo de log no encontrado"}

    for line in lines:
        match = pattern.search(line)
        if match:
            data = match.groupdict()
            failed_attempts.append(data)
            raw_lines.append(line.strip())

    if not failed_attempts:
        return {"message": "No se encontraron incidentes de fuerza bruta recientes"}

    # Calcular SHA-256 de todas las líneas concatenadas (Sellado forense)
    evidence_block = "\n".join(raw_lines)
    sha256_hash = hashlib.sha256(evidence_block.encode("utf-8")).hexdigest()

    # Extraer estadísticas básicas
    first_evt = failed_attempts[0]
    last_evt = failed_attempts[-1]

    return {
        "case_id": f"CASE-SSH-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "timestamp_analysis": datetime.utcnow().isoformat() + "Z",
        "target_host": first_evt["host"],
        "attacker_ip": first_evt["ip"],
        "targeted_user": first_evt["user"],
        "failed_attempts_count": len(failed_attempts),
        "first_attempt_time": first_evt["timestamp"],
        "last_attempt_time": last_evt["timestamp"],
        "attack_technique_mitre": "T1110.001 - Brute Force: Password Guessing",
        "evidence_sha256": sha256_hash,
        "raw_log_sample": raw_lines[-10:] # Enviamos las últimas 10 como muestra de evidencia
    }

@app.get("/api/forensics/analyze", response_model=Dict[str, Any])
def analyze_incident():
    """Endpoint para que el Frontend en C# consulte el análisis de la evidencia"""
    return parse_auth_log()
