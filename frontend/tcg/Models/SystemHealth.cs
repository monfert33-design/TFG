using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace tcg.Models
{
    // Respuesta del endpoint /api/system/health: estado general del backend y de sus subsistemas
    public class SystemHealthResponse
    {
        // Estado global del servidor
        [JsonPropertyName("status")]
        public string Status { get; set; } = string.Empty;

        // Momento en que el servidor generó la comprobación
        [JsonPropertyName("timestamp")]
        public DateTime Timestamp { get; set; }

        [JsonPropertyName("subsystems")]
        public SubsystemsHealth Subsystems { get; set; } = new();
    }

    // Estado individual de cada componente del que depende el análisis forense
    public class SubsystemsHealth
    {
        // Motor de IA que genera el dictamen pericial
        [JsonPropertyName("llm_engine")]
        public ComponentStatus LlmEngine { get; set; } = new();

        // Auditoría del kernel (auditd)
        [JsonPropertyName("kernel_auditd")]
        public ComponentStatus KernelAuditd { get; set; } = new();

        // Fuentes de logs disponibles: nombre del canal -> activa o no
        [JsonPropertyName("telemetry_sources")]
        public Dictionary<string, bool> TelemetrySources { get; set; } = new();

        // Indica si la caché de integridad de archivos (FIM) está lista
        [JsonPropertyName("fim_cache_ready")]
        public bool FimCacheReady { get; set; }
    }

    // Estado de un componente: Ok, y opcionalmente el modelo en uso o el error si falla
    public class ComponentStatus
    {
        [JsonPropertyName("ok")]
        public bool Ok { get; set; }

        [JsonPropertyName("model")]
        public string? Model { get; set; }

        [JsonPropertyName("error")]
        public string? Error { get; set; }
    }
}