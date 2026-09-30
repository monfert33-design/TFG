using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using tcg.Models;
using tcg.Services;

namespace tcg.ViewModels
{
    /// <summary>
    /// ViewModel principal que orquesta la lógica de negocio, el enlace de datos (Data Binding),
    /// el filtrado en tiempo real, el bucle de sondeo automático y la remediación activa (HITL).
    /// </summary>
    public partial class MainViewModel : ObservableObject
    {
        // Instancia del cliente HTTP que conecta con la API de FastAPI
        private readonly ForensicsApiService _apiService;

        // Repositorio en memoria con la totalidad de los incidentes recibidos durante la sesión
        private readonly ObservableCollection<ForensicCaseResponse> _allCases = new();

        // Registro de hashes SHA-256 ya procesados para deduplicación estricta y preservación de cadena de custodia
        private readonly HashSet<string> _processedEvidenceHashes = new();

        // Timer para la monitorización automática continua ejecutado sobre el hilo principal de la UI
        private readonly DispatcherTimer _autoScanTimer;

        // Colección visible en la interfaz tras aplicar los filtros de búsqueda por texto
        [ObservableProperty]
        private ObservableCollection<ForensicCaseResponse> _filteredCases = new();

        // Caso forense seleccionado actualmente en el panel central de detalles
        [ObservableProperty]
        private ForensicCaseResponse? _selectedCase;

        // Controla la visibilidad del menú o barra lateral
        [ObservableProperty]
        private bool _isSidebarOpen = false;

        // Indica si existe una petición HTTP o inferencia de IA en curso (para mostrar spinners de carga)
        [ObservableProperty]
        private bool _isLoading = false;

        // Estado del motor de sondeo periódico (activo o en pausa)
        [ObservableProperty]
        private bool _isAutoScanActive = true;

        // Texto introducido por el operador en el cuadro de búsqueda superior
        [ObservableProperty]
        private string _searchText = string.Empty;

        // Mensaje informativo mostrado en la barra inferior de estado del dashboard
        [ObservableProperty]
        private string _statusMessage = "Monitorización activa (Sondeo cada 30s)...";

        /// <summary>
        /// Constructor del ViewModel. Inicializa el temporizador de sondeo y lanza el primer escaneo.
        /// </summary>
        public MainViewModel()
        {
            _apiService = new ForensicsApiService();

            // Configuración del temporizador a 30 segundos en el hilo de UI
            _autoScanTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(30)
            };
            _autoScanTimer.Tick += async (sender, args) => await ExecuteScanInternalAsync(isAutomatic: true);

            // Iniciar la monitorización continua
            _autoScanTimer.Start();

            // Ejecutar un primer chequeo al arrancar la aplicación
            _ = ExecuteScanInternalAsync(isAutomatic: true);
        }

        /// <summary>
        /// Método interceptor de CommunityToolkit.Mvvm que se dispara automáticamente al mutar SearchText.
        /// </summary>
        partial void OnSearchTextChanged(string value)
        {
            ApplyFilter();
        }

        /// <summary>
        /// Alterna el estado de apertura de la barra lateral.
        /// </summary>
        [RelayCommand]
        private void ToggleSidebar()
        {
            IsSidebarOpen = !IsSidebarOpen;
        }

        // Alternar el modo automático (Play / Pause)
        [RelayCommand]
        private void ToggleAutoScan()
        {
            IsAutoScanActive = !IsAutoScanActive;
            if (IsAutoScanActive)
            {
                _autoScanTimer.Start();
                StatusMessage = "Monitorización automática reanudada (30s).";
            }
            else
            {
                _autoScanTimer.Stop();
                StatusMessage = "Monitorización automática pausada.";
            }
        }

        // Comando para disparar manualmente si el usuario pulsa el botón
        [RelayCommand]
        public async Task TriggerAnalysisAsync()
        {
            await ExecuteScanInternalAsync(isAutomatic: false);
        }

        /// <summary>
        /// Núcleo del ciclo de sondeo: contacta con el backend, gestiona hashes SHA-256,
        /// desglosa incidentes concurrentes y actualiza las listas observables.
        /// </summary>
        /// <param name="isAutomatic">Indica si la ejecución proviene del temporizador o de un clic manual.</param>
        private async Task ExecuteScanInternalAsync(bool isAutomatic)
        {
            // Evitar solapamientos si un escaneo ya está en curso
            if (IsLoading) return;

            IsLoading = true;
            if (!isAutomatic)
            {
                StatusMessage = "Extrayendo telemetría e interrogando a la IA...";
            }

            try
            {
                // Consulta asíncrona hacia FastAPI
                var result = await _apiService.AnalyzeIncidentAsync();

                if (result != null)
                {
                    // Si el backend avisa que no hay líneas nuevas o no hay hash
                    if (result.SinCambios || string.IsNullOrWhiteSpace(result.EvidenciaSha256))
                    {
                        StatusMessage = $"[Sin cambios] Telemetría sin novedades ({DateTime.Now:HH:mm:ss}).";
                        return;
                    }

                    // 1. Control de deduplicación forense por SHA-256
                    if (_processedEvidenceHashes.Contains(result.EvidenciaSha256))
                    {
                        StatusMessage = $"[Sin cambios] Evidencia SHA-256 idéntica ({DateTime.Now:HH:mm:ss}). No se duplican alertas.";
                        return;
                    }

                    // 2. Registro de la nueva evidencia
                    _processedEvidenceHashes.Add(result.EvidenciaSha256);

                    // 3. Obtener la lista desagregada de incidentes
                    var listaAvisos = result.Incidentes != null && result.Incidentes.Count > 0
                        ? result.Incidentes
                        : new List<ExpertOpinion> { result.DictamenPericial };

                    int subIndice = 1;
                    ForensicCaseResponse? primerAtaqueDetectado = null;

                    // 4. Crear una tarjeta independiente por cada vector detectado
                    foreach (var inc in listaAvisos)
                    {
                        var tarjetaCaso = new ForensicCaseResponse
                        {
                            CasoId = listaAvisos.Count > 1 ? $"{result.CasoId}-{subIndice++}" : result.CasoId,
                            TimestampAnalisis = result.TimestampAnalisis,
                            EvidenciaSha256 = result.EvidenciaSha256,
                            LineasAnalizadas = result.LineasAnalizadas,
                            DictamenPericial = inc
                        };

                        // Se inserta al principio para que los eventos más recientes aparezcan arriba en la lista
                        _allCases.Insert(0, tarjetaCaso);

                        // Identificar la primera amenaza real para seleccionarla automáticamente
                        if (inc.AtaqueDetectado && primerAtaqueDetectado == null)
                        {
                            primerAtaqueDetectado = tarjetaCaso;
                        }
                    }

                    // Refrescar la colección filtrada con los nuevos registros
                    ApplyFilter();

                    // 5. Seleccionar automáticamente el incidente prioritario
                    if (primerAtaqueDetectado != null)
                    {
                        SelectedCase = primerAtaqueDetectado;
                        StatusMessage = $"¡ALERTA NUEVA! {listaAvisos.Count} eventos catalogados. Principal: {primerAtaqueDetectado.DictamenPericial.TipoAtaque} ({DateTime.Now:HH:mm:ss})";
                    }
                    else
                    {
                        if (!isAutomatic && _allCases.Count > 0)
                        {
                            SelectedCase = _allCases[0];
                        }
                        StatusMessage = $"Logs actualizados: Actividad legítima confirmada ({DateTime.Now:HH:mm:ss}).";
                    }
                }
                else
                {
                    StatusMessage = "Error: Sin respuesta del servidor en 192.168.56.20";
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error de sondeo: {ex.Message}";
            }
            finally
            {
                // Liberar el indicador de carga tanto si terminó con éxito como si falló
                IsLoading = false;
            }
        }

        /// <summary>
        /// Aplica un filtrado multicriterio en memoria (por CaseId, IP, tipo de ataque, técnica MITRE o severidad).
        /// </summary>
        private void ApplyFilter()
        {
            if (string.IsNullOrWhiteSpace(SearchText))
            {
                // Si la caja de búsqueda está vacía, se visualiza el histórico íntegro
                FilteredCases = new ObservableCollection<ForensicCaseResponse>(_allCases);
            }
            else
            {
                var query = SearchText.Trim().ToLowerInvariant();

                // Búsqueda insensible a mayúsculas sobre múltiples campos del incidente
                var matches = _allCases.Where(c =>
                    (c.CasoId != null && c.CasoId.ToLowerInvariant().Contains(query)) ||
                    (c.DictamenPericial.IpAtacante != null && c.DictamenPericial.IpAtacante.ToLowerInvariant().Contains(query)) ||
                    (c.DictamenPericial.TipoAtaque != null && c.DictamenPericial.TipoAtaque.ToLowerInvariant().Contains(query)) ||
                    (c.DictamenPericial.TecnicaMitre != null && c.DictamenPericial.TecnicaMitre.ToLowerInvariant().Contains(query)) ||
                    (c.DictamenPericial.Severidad != null && c.DictamenPericial.Severidad.ToLowerInvariant().Contains(query))
                ).ToList();

                FilteredCases = new ObservableCollection<ForensicCaseResponse>(matches);
            }

            // Si el caso actualmente abierto desaparece del filtro, reposicionar al primero disponible
            if (SelectedCase != null && !FilteredCases.Contains(SelectedCase))
            {
                SelectedCase = FilteredCases.FirstOrDefault();
            }
        }

        /// <summary>
        /// Ejecuta la contramedida autorizada por el operador humano (Human-in-the-Loop)
        /// enviando la orden de remediación activa al backend.
        /// </summary>
        [RelayCommand]
        public async Task ApplyRemediationActionAsync()
        {
            // Validar que exista un caso seleccionado y que realmente exija acción defensiva
            if (SelectedCase == null || !SelectedCase.DictamenPericial.AccionPropuesta.RequiereAccion)
                return;

            var accion = SelectedCase.DictamenPericial.AccionPropuesta;
            StatusMessage = $"Aplicando contramedida sobre {accion.Objetivo}...";

            try
            {
                // Envío asíncrono de los parámetros de mitigación al servidor
                var result = await _apiService.ApplyRemediationAsync(
                    accion.Tipo,
                    accion.Objetivo,
                    accion.Justificacion
                );

                if (result != null)
                {
                    StatusMessage = $"[DEFENSA ACTIVA] {result.Mensaje}";
                    // Desactivamos la necesidad de acción para que el botón refleje que ya se aplicó
                    SelectedCase.DictamenPericial.AccionPropuesta.RequiereAccion = false;
                }
                else
                {
                    StatusMessage = "Fallo al comunicar la orden de mitigación al servidor.";
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error al ejecutar respuesta activa: {ex.Message}";
            }
        }
    }
}