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
    public partial class MainViewModel : ObservableObject
    {
        // Servicios: comunicación con la API forense y persistencia local
        private readonly ForensicsApiService _apiService;
        private readonly StorageService _storageService;

        // Lista maestra de casos (sin filtrar) y hashes ya procesados para evitar duplicados
        private readonly List<ForensicCaseResponse> _allCases = new();
        private readonly HashSet<string> _processedEvidenceHashes = new();
        private readonly DispatcherTimer _autoScanTimer;

        // --- CONTROL DE NAVEGACIÓN Y ALTERNANCIA DE VISTAS ---
        [ObservableProperty]
        private bool _isDashboardVisible = true;

        [ObservableProperty]
        private bool _isReportsVisible = false;

        // Muestra la pantalla de incidentes y oculta la de informes
        [RelayCommand]
        public void ShowDashboard()
        {
            IsDashboardVisible = true;
            IsReportsVisible = false;
        }

        // Muestra la pantalla de informes y oculta la de incidentes
        [RelayCommand]
        public void ShowReports()
        {
            IsDashboardVisible = false;
            IsReportsVisible = true;
        }

        // --- HISTÓRICO Y CLASIFICACIÓN TEMPORAL DE INCIDENTES ---
        [ObservableProperty]
        private ObservableCollection<ForensicCaseResponse> _currentSessionCases = new();

        [ObservableProperty]
        private ObservableCollection<ForensicCaseResponse> _archivedCases = new();

        [ObservableProperty]
        private ForensicCaseResponse? _selectedCase;

        // --- ESTADO DE LA INTERFAZ ---
        [ObservableProperty]
        private bool _isSidebarOpen = false;

        [ObservableProperty]
        private bool _isLoading = false;

        [ObservableProperty]
        private bool _isAutoScanActive = true;

        [ObservableProperty]
        private string _searchText = string.Empty;

        [ObservableProperty]
        private string _statusMessage = "Monitorización activa (Sondeo cada 30s)...";

        public MainViewModel()
        {
            _apiService = new ForensicsApiService();
            _storageService = new StorageService();

            // Temporizador de sondeo automático cada 30 segundos
            _autoScanTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(30)
            };
            _autoScanTimer.Tick += async (sender, args) => await ExecuteScanInternalAsync(isAutomatic: true);

            _ = InitializeSystemAsync();
        }

        // Arranque: carga el histórico guardado, activa el temporizador y lanza un primer análisis
        private async Task InitializeSystemAsync()
        {
            await LoadPersistedDataAsync();
            _autoScanTimer.Start();
            await ExecuteScanInternalAsync(isAutomatic: true);
        }

        // Recupera los incidentes guardados y registra sus hashes para no reanalizarlos
        private async Task LoadPersistedDataAsync()
        {
            var storedCases = await _storageService.LoadIncidentsAsync();
            foreach (var c in storedCases)
            {
                _allCases.Add(c);
                if (!string.IsNullOrWhiteSpace(c.EvidenciaSha256))
                {
                    _processedEvidenceHashes.Add(c.EvidenciaSha256);
                }
            }

            ApplyFilterAndGrouping();

            // Selecciona por defecto el primer caso disponible
            if (_currentSessionCases.Count > 0)
                SelectedCase = _currentSessionCases[0];
            else if (_archivedCases.Count > 0)
                SelectedCase = _archivedCases[0];
        }

        // Re-filtra la lista cada vez que cambia el texto del buscador
        partial void OnSearchTextChanged(string value)
        {
            ApplyFilterAndGrouping();
        }

        [RelayCommand]
        private void ToggleSidebar() => IsSidebarOpen = !IsSidebarOpen;

        // Pausa o reanuda el sondeo automático
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

        // Análisis manual lanzado desde el botón "Forzar Análisis"
        [RelayCommand]
        public async Task TriggerAnalysisAsync()
        {
            await ExecuteScanInternalAsync(isAutomatic: false);
        }

        // Núcleo del sondeo: consulta la API, descarta duplicados y registra los nuevos casos
        private async Task ExecuteScanInternalAsync(bool isAutomatic)
        {
            // Evita solapar dos análisis a la vez
            if (IsLoading) return;
            IsLoading = true;

            if (!isAutomatic)
                StatusMessage = "Extrayendo telemetría e interrogando al LLM...";

            try
            {
                var result = await _apiService.AnalyzeIncidentAsync();

                if (result != null)
                {
                    // Caso 1: el servidor no detecta cambios en los logs
                    if (result.SinCambios || string.IsNullOrWhiteSpace(result.EvidenciaSha256))
                    {
                        ApplyFilterAndGrouping();
                        StatusMessage = $"[Sin cambios] Telemetría sin novedades ({DateTime.Now:HH:mm:ss}).";
                        return;
                    }

                    // Caso 2: la evidencia ya fue analizada anteriormente
                    if (_processedEvidenceHashes.Contains(result.EvidenciaSha256))
                    {
                        ApplyFilterAndGrouping();
                        StatusMessage = $"[Sin cambios] Evidencia SHA-256 idéntica ({DateTime.Now:HH:mm:ss}).";
                        return;
                    }

                    _processedEvidenceHashes.Add(result.EvidenciaSha256);

                    // Un análisis puede contener varios incidentes; si no, se usa el dictamen único
                    var listaAvisos = result.Incidentes != null && result.Incidentes.Count > 0
                        ? result.Incidentes
                        : new List<ExpertOpinion> { result.DictamenPericial };

                    int subIndice = 1;
                    ForensicCaseResponse? primerAtaque = null;

                    // Crea una tarjeta por incidente (con sufijo -1, -2... si hay varios)
                    foreach (var inc in listaAvisos)
                    {
                        var tarjeta = new ForensicCaseResponse
                        {
                            CasoId = listaAvisos.Count > 1 ? $"{result.CasoId}-{subIndice++}" : result.CasoId,
                            TimestampAnalisis = result.TimestampAnalisis,
                            EvidenciaSha256 = result.EvidenciaSha256,
                            LineasAnalizadas = result.LineasAnalizadas,
                            DictamenPericial = inc
                        };

                        _allCases.Insert(0, tarjeta);

                        // Recuerda el primer ataque real para seleccionarlo después
                        if (inc.AtaqueDetectado && primerAtaque == null)
                        {
                            primerAtaque = tarjeta;
                        }
                    }

                    await _storageService.SaveIncidentsAsync(_allCases);

                    ApplyFilterAndGrouping();

                    // Si hay ataque se selecciona y se avisa; si no, se confirma actividad legítima
                    if (primerAtaque != null)
                    {
                        SelectedCase = primerAtaque;
                        StatusMessage = $"¡ALERTA NUEVA! {listaAvisos.Count} eventos catalogados ({DateTime.Now:HH:mm:ss}).";
                    }
                    else
                    {
                        StatusMessage = $"Logs actualizados: Actividad legítima confirmada ({DateTime.Now:HH:mm:ss}).";
                    }
                }
                else
                {
                    StatusMessage = "Error: Sin respuesta del servidor defensivo.";
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error de sondeo: {ex.Message}";
            }
            finally
            {
                IsLoading = false;
            }
        }

        // Aplica el buscador y reparte los casos entre recientes (< 2h) y archivados (>= 2h)
        private void ApplyFilterAndGrouping()
        {
            var query = SearchText?.Trim().ToLowerInvariant() ?? "";
            var limite2Horas = DateTime.UtcNow.AddHours(-2);

            // Filtra por ID, IP, tipo de ataque, técnica MITRE o severidad
            var filtrados = _allCases.Where(c =>
                string.IsNullOrWhiteSpace(query) ||
                (c.CasoId?.ToLowerInvariant().Contains(query) ?? false) ||
                (c.DictamenPericial.IpAtacante?.ToLowerInvariant().Contains(query) ?? false) ||
                (c.DictamenPericial.TipoAtaque?.ToLowerInvariant().Contains(query) ?? false) ||
                (c.DictamenPericial.TecnicaMitre?.ToLowerInvariant().Contains(query) ?? false) ||
                (c.DictamenPericial.Severidad?.ToLowerInvariant().Contains(query) ?? false)
            ).ToList();

            var recientes = filtrados.Where(c => c.TimestampAnalisis >= limite2Horas).ToList();
            var antiguos = filtrados.Where(c => c.TimestampAnalisis < limite2Horas).ToList();

            CurrentSessionCases = new ObservableCollection<ForensicCaseResponse>(recientes);
            ArchivedCases = new ObservableCollection<ForensicCaseResponse>(antiguos);

            // Si el caso seleccionado desaparece con el filtro, se elige otro disponible
            if (SelectedCase != null && !CurrentSessionCases.Contains(SelectedCase) && !ArchivedCases.Contains(SelectedCase))
            {
                SelectedCase = CurrentSessionCases.FirstOrDefault() ?? ArchivedCases.FirstOrDefault();
            }
        }

        // Ejecuta la contramedida propuesta tras la confirmación del analista (Human-in-the-Loop)
        [RelayCommand]
        public async Task ApplyRemediationActionAsync()
        {
            if (SelectedCase == null || !SelectedCase.DictamenPericial.AccionPropuesta.RequiereAccion)
                return;

            var accion = SelectedCase.DictamenPericial.AccionPropuesta;

            // Busca la ventana activa para mostrar el diálogo de confirmación encima
            var desktop = Avalonia.Application.Current?.ApplicationLifetime as Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime;
            var activeWindow = desktop?.Windows.FirstOrDefault(w => w.IsActive && w.IsVisible) ?? desktop?.MainWindow;

            if (activeWindow != null && activeWindow.IsVisible)
            {
                var dialog = new tcg.Views.ConfirmRemediationDialog(
                    accion.Tipo,
                    accion.ComandoSugerido,
                    accion.Justificacion
                );

                await dialog.ShowDialog(activeWindow);

                // Si el operador cancela, no se ejecuta nada
                if (!dialog.Confirmed)
                {
                    StatusMessage = "Acción defensiva cancelada por el operador.";
                    return;
                }
            }

            StatusMessage = $"Aplicando contramedida sobre {accion.Objetivo}...";

            try
            {
                var result = await _apiService.ApplyRemediationAsync(
                    accion.Tipo,
                    accion.Objetivo,
                    accion.Justificacion
                );

                if (result != null)
                {
                    StatusMessage = $"[DEFENSA ACTIVA] {result.Mensaje}";
                    // Desactiva el botón para que no se aplique dos veces
                    SelectedCase.DictamenPericial.AccionPropuesta.RequiereAccion = false;

                    // Registro de auditoría de la acción ejecutada
                    await _storageService.SaveRemediationLogAsync(new RemediationAuditRecord
                    {
                        CasoId = SelectedCase.CasoId ?? "N/A",
                        Tipo = accion.Tipo,
                        Objetivo = accion.Objetivo,
                        ComandoEjecutado = result.ComandoEjecutado ?? accion.ComandoSugerido,
                        Justificacion = accion.Justificacion,
                        Status = result.Status
                    });

                    await _storageService.SaveIncidentsAsync(_allCases);
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