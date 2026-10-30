using System;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;
using tcg.Services;

namespace tcg.Views
{
    public partial class SplashWindow : Window
    {
        private readonly ForensicsApiService _apiService;
        private bool _isChecking = false;

        public SplashWindow()
        {
            InitializeComponent();
            _apiService = new ForensicsApiService();
            Loaded += async (s, e) => await StartHealthCheckProcessAsync();
        }

        private async Task StartHealthCheckProcessAsync()
        {
            if (_isChecking) return;
            _isChecking = true;

            Dispatcher.UIThread.Post(() =>
            {
                SpinnerControl.IsVisible = true;
                IconError.IsVisible = false;
                PanelActions.IsVisible = false;
                TxtStatus.Foreground = new SolidColorBrush(Color.Parse("#C9D1D9"));
                TxtStatus.Text = "Iniciando subsistemas...";
                TxtSubStatus.Text = "Conectando con 192.168.56.20:8000...";
            });

            await Task.Delay(400);

            // --- 1. CONEXIÓN CON UBUNTU SERVER (CRÍTICA) ---
            UpdateStatus("Verificando servidor defensivo...", "Consultando API en 192.168.56.20:8000...");
            var health = await _apiService.CheckHealthAsync();

            int retries = 0;
            const int maxRetries = 3;

            while (health == null && retries < maxRetries)
            {
                retries++;
                UpdateStatus("Reintentando conexión...", $"El backend no responde (Intento {retries}/{maxRetries})...");
                await Task.Delay(1800);
                health = await _apiService.CheckHealthAsync();
            }

            // Si el backend físico no responde, aquí sí se bloquea porque no hay de dónde leer nada
            if (health == null)
            {
                ShowErrorOptions(
                    "Error: El servidor no responde",
                    "No se pudo conectar con Ubuntu Server (192.168.56.20:8000). Revisa que Uvicorn esté iniciado."
                );
                _isChecking = false;
                return;
            }

            // --- 2. FUENTES DE TELEMETRÍA ---
            UpdateStatus("Comprobando fuentes de telemetría...", "Auditd, Nginx, Kern, Syslog y Auth");
            await Task.Delay(400);

            // --- 3. MOTOR DE INTELIGENCIA ARTIFICIAL (NO BLOQUEANTE) ---
            UpdateStatus("Validando motor agéntico...", $"Google Gemini ({health.Subsystems.LlmEngine.Model ?? "gemini-2.5-flash"})");
            await Task.Delay(400);

            bool iaDegradada = !health.Subsystems.LlmEngine.Ok;
            string? errorIa = health.Subsystems.LlmEngine.Error;

            // --- 4. LANZAMIENTO DEL SISTEMA ---
            UpdateStatus("Diagnóstico completado", iaDegradada ? "Iniciando en modo degradado..." : "Abriendo panel de operaciones...");
            await Task.Delay(350);

            Dispatcher.UIThread.Post(() =>
            {
                var mainWindow = new MainWindow();

                // Reasignar la ventana principal de la aplicación para que no quede huérfana
                if (Avalonia.Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
                {
                    desktop.MainWindow = mainWindow;
                }

                mainWindow.Show();
                this.Close();
            });
        }

        private void ShowErrorOptions(string titulo, string descripcion)
        {
            Dispatcher.UIThread.Post(() =>
            {
                SpinnerControl.IsVisible = false;
                IconError.IsVisible = true;
                PanelActions.IsVisible = true;

                TxtStatus.Foreground = new SolidColorBrush(Color.Parse("#F85149")); // Rojo
                TxtStatus.Text = titulo;
                TxtSubStatus.Text = descripcion;
            });
        }

        private void UpdateStatus(string main, string sub)
        {
            Dispatcher.UIThread.Post(() =>
            {
                TxtStatus.Text = main;
                TxtSubStatus.Text = sub;
            });
        }

        private async void OnRetryClicked(object? sender, RoutedEventArgs e)
        {
            await StartHealthCheckProcessAsync();
        }

        private void OnExitClicked(object? sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}