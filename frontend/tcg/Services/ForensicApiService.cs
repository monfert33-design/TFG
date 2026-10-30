using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using tcg.Models;

namespace tcg.Services
{
    // Cliente HTTP del backend FastAPI (Ubuntu Server): análisis forense, remediación y estado del sistema
    public class ForensicsApiService
    {
        // Cliente reutilizable para aprovechar el pooling de conexiones
        private readonly HttpClient _httpClient;

        // IP y puerto de la máquina virtual defensiva en la red interna
        private const string BaseUrl = "http://192.168.56.20:8000";

        public ForensicsApiService()
        {
            _httpClient = new HttpClient
            {
                BaseAddress = new Uri(BaseUrl),
                // Margen amplio para el bucle agéntico del LLM en el backend
                Timeout = TimeSpan.FromSeconds(30)
            };
        }

        // Pide al backend analizar la telemetría reciente; devuelve el caso o null si falla la petición
        public async Task<ForensicCaseResponse?> AnalyzeIncidentAsync()
        {
            try
            {
                // Endpoint de análisis forense (sin cuerpo en la petición)
                var response = await _httpClient.PostAsync("/api/forensics/ai-analyze", null);

                // Lanza excepción si el código HTTP no está en el rango 200-299
                response.EnsureSuccessStatusCode();

                var jsonString = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<ForensicCaseResponse>(jsonString);
            }
            catch (Exception ex)
            {
                // Se registra en consola y se devuelve null para no interrumpir la UI
                Console.WriteLine($"Error al consultar el backend: {ex.Message}");
                return null;
            }
        }

        // Envía la contramedida confirmada por el analista (HITL), ej. BLOQUEAR_IP o MATAR_PROCESO
        public async Task<RemediationResult?> ApplyRemediationAsync(string tipo, string objetivo, string justificacion)
        {
            try
            {
                // Contrato JSON que espera el endpoint de remediación
                var payload = new
                {
                    tipo = tipo,
                    objetivo = objetivo,
                    justificacion = justificacion
                };

                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync("/api/remediation/apply", content);
                response.EnsureSuccessStatusCode();

                var jsonString = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<RemediationResult>(jsonString);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al aplicar remediación: {ex.Message}");
                return null;
            }
        }

        // Comprueba si el backend responde; usa un timeout propio de 8s, más corto que el del cliente
        public async Task<SystemHealthResponse?> CheckHealthAsync()
        {
            try
            {
                using var cts = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(8));
                var response = await _httpClient.GetAsync("/api/system/health", cts.Token);
                if (!response.IsSuccessStatusCode) return null;

                var jsonString = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<SystemHealthResponse>(jsonString);
            }
            catch
            {
                // Cualquier fallo (timeout, red caída) se interpreta como servidor no disponible
                return null;
            }
        }
    }
}