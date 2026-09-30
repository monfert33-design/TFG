using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace tcg.Models
{
    /// <summary>
    /// Representa la respuesta global devuelta por el endpoint de análisis forense del backend.
    /// Contiene los metadatos de la sesión, el sellado criptográfico y los incidentes identificados.
    /// </summary>
    public class ForensicCaseResponse
    {
        // Identificador único del caso forense generado por el backend (ej. CASE-20260929-173149)
        [JsonPropertyName("caso_id")]
        public string? CasoId { get; set; }

        // Marca de tiempo en formato UTC en la que se completó la adquisición y el análisis
        [JsonPropertyName("timestamp_analisis")]
        public DateTime TimestampAnalisis { get; set; }

        // Hash SHA-256 calculado sobre la evidencia cruda para garantizar la cadena de custodia
        [JsonPropertyName("evidencia_sha256")]
        public string EvidenciaSha256 { get; set; } = string.Empty;

        // Volumen total de líneas de registro (logs) evaluadas en este ciclo de análisis
        [JsonPropertyName("lineas_analizadas")]
        public int LineasAnalizadas { get; set; }

        // Indica si no hubo nuevos eventos en los registros desde la última lectura del cursor
        [JsonPropertyName("sin_cambios")]
        public bool SinCambios { get; set; }

        // Mensaje informativo contextual generado por el backend o el servidor web
        [JsonPropertyName("mensaje")]
        public string? Mensaje { get; set; }

        // Lista completa de amenazas independientes clasificadas durante la ingesta multicanal
        [JsonPropertyName("incidentes")]
        public List<ExpertOpinion> Incidentes { get; set; } = new();

        // Dictamen principal o de primer orden extraído para su visualización destacada en la interfaz
        [JsonPropertyName("dictamen_pericial")]
        public ExpertOpinion DictamenPericial { get; set; } = new();
    }

    /// <summary>
    /// Modela el análisis detallado de un incidente específico realizado por el modelo de IA.
    /// </summary>
    public class ExpertOpinion
    {
        // Fuente o canal de telemetría de donde se extrajo la evidencia (ej. auth, kernel, nginx, syslog, audit)
        [JsonPropertyName("canal_origen")]
        public string CanalOrigen { get; set; } = string.Empty;

        // Determina si el evento representa una amenaza real confirmada o actividad benigna
        [JsonPropertyName("ataque_detectado")]
        public bool AtaqueDetectado { get; set; }

        // Denominación formal del vector de ataque identificado (ej. Fuerza Bruta SSH, Escaneo Nmap)
        [JsonPropertyName("tipo_ataque")]
        public string TipoAtaque { get; set; } = string.Empty;

        // Código y técnica estandarizada según la matriz MITRE ATT&CK (ej. T1110.001, T1059.004)
        [JsonPropertyName("tecnica_mitre")]
        public string TecnicaMitre { get; set; } = string.Empty;

        // Nivel de criticidad asignado al incidente (CRÍTICA, ALTA, MEDIA, BAJA, INFORMATIVA)
        [JsonPropertyName("severidad")]
        public string Severidad { get; set; } = string.Empty;

        // Dirección IP identificada como origen de la agresión (o null en caso de eventos puramente locales)
        [JsonPropertyName("ip_atacante")]
        public string? IpAtacante { get; set; }

        // Usuario del sistema que ha sido objetivo del ataque o que ejecutó la acción sospechosa
        [JsonPropertyName("usuario_objetivo")]
        public string? UsuarioObjetivo { get; set; }

        // Explicación redactada por la IA detallando la correlación de eventos y evidencias
        [JsonPropertyName("resumen_forense")]
        public string ResumenForense { get; set; } = string.Empty;

        // Contramedida  sugerida por el agente para mitigar o neutralizar el incidente
        [JsonPropertyName("accion_propuesta")]
        public RemediationAction AccionPropuesta { get; set; } = new();
    }

    /// <summary>
    /// Especifica los parámetros de la acción defensiva sugerida por el sistema para su aprobación supervisada (HITL).
    /// </summary>
    public class RemediationAction
    {
        // Bandera que indica si la severidad del ataque requiere la intervención  del operador
        [JsonPropertyName("requiere_accion")]
        public bool RequiereAccion { get; set; }

        // Tipología de contramedida a ejecutar (ej. BLOQUEAR_IP, MATAR_PROCESO, AUDITAR_SISTEMA)
        [JsonPropertyName("tipo")]
        public string Tipo { get; set; } = string.Empty;

        // Entidad sobre la que se aplicará la acción defensiva (ej. una dirección IP o un PID)
        [JsonPropertyName("objetivo")]
        public string Objetivo { get; set; } = string.Empty;

        // Sintaxis exacta del comando a ejecutar en el servidor (ej. iptables -I INPUT -s ... -j DROP)
        [JsonPropertyName("comando_sugerido")]
        public string ComandoSugerido { get; set; } = string.Empty;

        // Argumentación técnica que justifica la ejecución de la acción defensiva propuesta
        [JsonPropertyName("justificacion")]
        public string Justificacion { get; set; } = string.Empty;
    }

    /// <summary>
    /// Modela el resultado devuelto por el servidor tras la ejecución efectiva de una contramedida defensiva.
    /// </summary>
    public class RemediationResult
    {
        // Estado final de la operación (ej. "exito", "ya_aplicado", "error")
        [JsonPropertyName("status")]
        public string Status { get; set; } = string.Empty;

        // Detalle legible sobre el resultado de la aplicación de la contramedida en el sistema
        [JsonPropertyName("mensaje")]
        public string Mensaje { get; set; } = string.Empty;

        // Comando exacto ejecutado a nivel de sistema operativo en el servidor Ubuntu
        [JsonPropertyName("comando_ejecutado")]
        public string? ComandoEjecutado { get; set; }
    }
}