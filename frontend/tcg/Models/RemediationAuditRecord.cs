using System;

namespace tcg.Models
{
    // Registro de auditoría de una contramedida ejecutada (se guarda en remediation_history.json)
    public class RemediationAuditRecord
    {
        // Caso que originó la acción
        public string CasoId { get; set; } = string.Empty;

        // Momento de la ejecución, en UTC
        public DateTime TimestampEjecucion { get; set; } = DateTime.UtcNow;

        // Tipo de contramedida (ej. BLOQUEAR_IP, MATAR_PROCESO) y su objetivo (IP o PID)
        public string Tipo { get; set; } = string.Empty;
        public string Objetivo { get; set; } = string.Empty;

        // Comando que se ejecutó realmente en el servidor
        public string ComandoEjecutado { get; set; } = string.Empty;

        // Motivo pericial que justificó la acción
        public string Justificacion { get; set; } = string.Empty;

        // Resultado devuelto por el servidor
        public string Status { get; set; } = string.Empty;
    }
}
