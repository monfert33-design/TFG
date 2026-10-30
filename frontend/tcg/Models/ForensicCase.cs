using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace tcg.Models
{
    // Respuesta del endpoint de análisis forense: metadatos de la sesión, sellado SHA-256 e incidentes
    public class ForensicCaseResponse
    {
        // Identificador del caso generado por el backend (ej. CASE-20260929-173149)
        [JsonPropertyName("caso_id")]
        public string? CasoId { get; set; }

        // Momento (UTC) en que se completó el análisis
        [JsonPropertyName("timestamp_analisis")]
        public DateTime TimestampAnalisis { get; set; }

        // Hash de la evidencia cruda para garantizar la cadena de custodia
        [JsonPropertyName("evidencia_sha256")]
        public string EvidenciaSha256 { get; set; } = string.Empty;

        // Líneas de log evaluadas en este análisis
        [JsonPropertyName("lineas_analizadas")]
        public int LineasAnalizadas { get; set; }

        // True si no hubo eventos nuevos desde la última lectura
        [JsonPropertyName("sin_cambios")]
        public bool SinCambios { get; set; }

        // Mensaje informativo del backend
        [JsonPropertyName("mensaje")]
        public string? Mensaje { get; set; }

        // Todos los incidentes clasificados en el análisis
        [JsonPropertyName("incidentes")]
        public List<ExpertOpinion> Incidentes { get; set; } = new();

        // Dictamen principal, el que se muestra destacado en la interfaz
        [JsonPropertyName("dictamen_pericial")]
        public ExpertOpinion DictamenPericial { get; set; } = new();
    }

    // Análisis detallado de un incidente concreto realizado por el modelo de IA
    public class ExpertOpinion
    {
        // Canal de log del que sale la evidencia (ej. auth, kernel, nginx, syslog, audit)
        [JsonPropertyName("canal_origen")]
        public string CanalOrigen { get; set; } = string.Empty;

        // True si es una amenaza real; false si es actividad legítima
        [JsonPropertyName("ataque_detectado")]
        public bool AtaqueDetectado { get; set; }

        // Tipo de ataque identificado (ej. Fuerza Bruta SSH, Escaneo Nmap)
        [JsonPropertyName("tipo_ataque")]
        public string TipoAtaque { get; set; } = string.Empty;

        // Técnica según MITRE ATT&CK (ej. T1110.001)
        [JsonPropertyName("tecnica_mitre")]
        public string TecnicaMitre { get; set; } = string.Empty;

        // Criticidad: CRÍTICA, ALTA, MEDIA, BAJA o INFORMATIVA
        [JsonPropertyName("severidad")]
        public string Severidad { get; set; } = string.Empty;

        // IP de origen del ataque (null en eventos puramente locales)
        [JsonPropertyName("ip_atacante")]
        public string? IpAtacante { get; set; }

        // Usuario atacado o que ejecutó la acción sospechosa
        [JsonPropertyName("usuario_objetivo")]
        public string? UsuarioObjetivo { get; set; }

        // Explicación de la IA con la correlación de eventos y evidencias
        [JsonPropertyName("resumen_forense")]
        public string ResumenForense { get; set; } = string.Empty;

        // Contramedida sugerida para neutralizar el incidente
        [JsonPropertyName("accion_propuesta")]
        public RemediationAction AccionPropuesta { get; set; } = new();
    }

    // Acción defensiva propuesta, pendiente de aprobación del operador (Human-in-the-Loop)
    public class RemediationAction
    {
        // True si el incidente requiere que el operador intervenga
        [JsonPropertyName("requiere_accion")]
        public bool RequiereAccion { get; set; }

        // Tipo de contramedida (ej. BLOQUEAR_IP, MATAR_PROCESO, AUDITAR_SISTEMA)
        [JsonPropertyName("tipo")]
        public string Tipo { get; set; } = string.Empty;

        // Sobre qué se aplica: una IP o un PID
        [JsonPropertyName("objetivo")]
        public string Objetivo { get; set; } = string.Empty;

        // Comando exacto que se ejecutaría en el servidor (ej. iptables -I INPUT -s ... -j DROP)
        [JsonPropertyName("comando_sugerido")]
        public string ComandoSugerido { get; set; } = string.Empty;

        // Motivo técnico que justifica la acción
        [JsonPropertyName("justificacion")]
        public string Justificacion { get; set; } = string.Empty;
    }

    // Resultado devuelto por el servidor tras ejecutar una contramedida
    public class RemediationResult
    {
        // Estado final de la operación (ej. "exito", "ya_aplicado", "error")
        [JsonPropertyName("status")]
        public string Status { get; set; } = string.Empty;

        // Detalle legible del resultado
        [JsonPropertyName("mensaje")]
        public string Mensaje { get; set; } = string.Empty;

        // Comando que se ejecutó realmente en el servidor
        [JsonPropertyName("comando_ejecutado")]
        public string? ComandoEjecutado { get; set; }
    }
}