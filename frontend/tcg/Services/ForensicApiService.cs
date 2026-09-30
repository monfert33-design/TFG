using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using tcg.Models;

namespace tcg.Services
{
    /// <summary>
    /// Servicio de comunicación HTTP encargado de consumir los endpoints REST expuestos
    /// por el backend en FastAPI (Ubuntu Server) para el análisis forense y la remediación activa.
    /// </summary>
    public class ForensicsApiService
    {
        // Instancia reutilizable de cliente HTTP para optimizar conexiones mediante pooling de sockets
        private readonly HttpClient _httpClient;

        // Dirección IP y puerto asignados a la máquina virtual defensiva (Ubuntu Server) en la red interna
        private const string BaseUrl = "http://192.168.56.20:8000";

        /// <summary>
        /// Constructor del servicio. Configura la URL base y un tiempo de espera adecuado
        /// para tolerar la latencia de inferencia y llamadas a herramientas del LLM.
        /// </summary>
        public ForensicsApiService()
        {
            _httpClient = new HttpClient
            {
                BaseAddress = new Uri(BaseUrl),
                // Se define un timeout de 30 segundos para soportar la ejecución del bucle agéntico en el backend
                Timeout = TimeSpan.FromSeconds(30) // Margen para el bucle agéntico
            };
        }

        /// <summary>
        /// Solicita al backend la ingesta de telemetría reciente, el sellado criptográfico
        /// y el dictamen pericial generado por el modelo de IA.
        /// </summary>
        /// <returns>Objeto estructurado con los detalles del caso o null si ocurrió un error en la solicitud.</returns>
        public async Task<ForensicCaseResponse?> AnalyzeIncidentAsync()
        {
            try
            {
                // Invocación al endpoint neurálgico de análisis forense (sin cuerpo en la petición)
                var response = await _httpClient.PostAsync("/api/forensics/ai-analyze", null);

                // Valida que el código de respuesta HTTP pertenezca al rango 200-299; de lo contrario lanza excepción
                response.EnsureSuccessStatusCode();

                // Lectura del contenido de la respuesta devuelto por FastAPI en formato JSON
                var jsonString = await response.Content.ReadAsStringAsync();

                // Deserialización hacia el modelo de datos de la aplicación
                return JsonSerializer.Deserialize<ForensicCaseResponse>(jsonString);
            }
            catch (Exception ex)
            {
                // Registro del error en consola local para diagnóstico sin interrumpir la ejecución de la UI
                Console.WriteLine($"Error al consultar el backend: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Envía una orden de mitigación activa supervisada (HITL) hacia el backend
        /// para aplicar una contramedida (bloqueo en iptables o terminación de procesos hostiles).
        /// </summary>
        /// <param name="tipo">Identificador de la contramedida (ej. BLOQUEAR_IP, MATAR_PROCESO).</param>
        /// <param name="objetivo">Elemento objetivo de la acción (dirección IP hostil o PID de proceso).</param>
        /// <param name="justificacion">Explicación pericial que motiva la aplicación de la regla defensiva.</param>
        /// <returns>Resultado de la ejecución en el sistema operativo o null ante fallos de conexión.</returns>
        public async Task<RemediationResult?> ApplyRemediationAsync(string tipo, string objetivo, string justificacion)
        {
            try
            {
                // Objeto anónimo que define el contrato JSON requerido por el endpoint de remediación
                var payload = new
                {
                    tipo = tipo,
                    objetivo = objetivo,
                    justificacion = justificacion
                };

                // Serialización del payload a JSON y preparación del cuerpo de la petición con codificación UTF-8
                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

                // Envío asíncrono de la solicitud de mitigación autorizada por el analista
                var response = await _httpClient.PostAsync("/api/remediation/apply", content);

                // Verificación del estado de éxito del comando defensivo
                response.EnsureSuccessStatusCode();

                // Lectura del reporte de remediación devuelto por el servidor
                var jsonString = await response.Content.ReadAsStringAsync();

                // Conversión del JSON a la entidad RemediationResult para su reflejo en la interfaz
                return JsonSerializer.Deserialize<RemediationResult>(jsonString);
            }
            catch (Exception ex)
            {
                // Captura y registro de excepciones en la llamada de respuesta activa
                Console.WriteLine($"Error al aplicar remediación: {ex.Message}");
                return null;
            }
        }
    }
}