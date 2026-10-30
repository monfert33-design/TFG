using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using tcg.Models;
using tcg.Services;

namespace tcg.ViewModels
{
    public partial class ReportsViewModel : ObservableObject
    {
        // Servicio de persistencia local: de aquí salen los incidentes y las remediaciones guardadas
        private readonly StorageService _storageService;

        // --- CONTADORES GENERALES (tarjetas de resumen) ---
        [ObservableProperty]
        private int _totalIncidentes;

        [ObservableProperty]
        private int _totalIpsUnicas;

        [ObservableProperty]
        private int _totalRemediaciones;

        // --- MÉTRICAS AGRUPADAS PARA LOS PANELES DEL INFORME ---
        [ObservableProperty]
        private ObservableCollection<MetricItem> _topAttackerIps = new();

        [ObservableProperty]
        private ObservableCollection<MetricItem> _attackTypesDistribution = new();

        [ObservableProperty]
        private ObservableCollection<MetricItem> _serverZonesAttacked = new();

        [ObservableProperty]
        private ObservableCollection<MetricItem> _severityDistribution = new();

        public ReportsViewModel()
        {
            _storageService = new StorageService();
            _ = LoadReportDataAsync();
        }

        // Recarga las métricas desde el almacenamiento (botón de actualizar del informe)
        [RelayCommand]
        public async Task RefreshDataAsync()
        {
            await LoadReportDataAsync();
        }

        // Lee el histórico guardado y calcula todas las estadísticas del informe
        public async Task LoadReportDataAsync()
        {
            var incidents = await _storageService.LoadIncidentsAsync();
            var remediations = await _storageService.LoadRemediationsAsync();

            TotalIncidentes = incidents.Count;
            TotalRemediaciones = remediations.Count;

            // Sin incidentes no hay nada que agrupar
            if (TotalIncidentes == 0) return;

            // 1. IPs atacantes: ranking de las 8 con más eventos (se ignoran vacías y "N/A")
            var ips = incidents
                .Where(i => !string.IsNullOrWhiteSpace(i.DictamenPericial.IpAtacante) && i.DictamenPericial.IpAtacante != "N/A")
                .GroupBy(i => i.DictamenPericial.IpAtacante!)
                .Select(g => new MetricItem
                {
                    Etiqueta = g.Key,
                    Cantidad = g.Count(),
                    Porcentaje = (double)g.Count() / TotalIncidentes * 100,
                    DetalleSecundario = $"{g.Count()} eventos detectados"
                })
                .OrderByDescending(x => x.Cantidad)
                .Take(8)
                .ToList();

            TopAttackerIps = new ObservableCollection<MetricItem>(ips);
            TotalIpsUnicas = incidents.Select(i => i.DictamenPericial.IpAtacante).Where(ip => !string.IsNullOrWhiteSpace(ip)).Distinct().Count();

            // 2. Tipos de ataque: se muestran junto a un máximo de 2 técnicas MITRE asociadas
            var types = incidents
                .Where(i => !string.IsNullOrWhiteSpace(i.DictamenPericial.TipoAtaque))
                .GroupBy(i => i.DictamenPericial.TipoAtaque)
                .Select(g => new MetricItem
                {
                    Etiqueta = g.Key,
                    Cantidad = g.Count(),
                    Porcentaje = (double)g.Count() / TotalIncidentes * 100,
                    DetalleSecundario = $"Técnicas: {string.Join(", ", g.Select(x => x.DictamenPericial.TecnicaMitre).Where(t => !string.IsNullOrWhiteSpace(t)).Distinct().Take(2))}"
                })
                .OrderByDescending(x => x.Cantidad)
                .ToList();

            AttackTypesDistribution = new ObservableCollection<MetricItem>(types);

            // 3. Zonas del servidor: agrupa por canal de origen del log (AUTH, KERNEL, NGINX...)
            var zones = incidents
                .Where(i => !string.IsNullOrWhiteSpace(i.DictamenPericial.CanalOrigen))
                .GroupBy(i => i.DictamenPericial.CanalOrigen.ToUpperInvariant())
                .Select(g => new MetricItem
                {
                    Etiqueta = FormatZoneName(g.Key),
                    Cantidad = g.Count(),
                    Porcentaje = (double)g.Count() / TotalIncidentes * 100,
                    DetalleSecundario = $"{g.Count()} alertas originadas en este subsistema"
                })
                .OrderByDescending(x => x.Cantidad)
                .ToList();

            ServerZonesAttacked = new ObservableCollection<MetricItem>(zones);

            // 4. Severidad: los casos sin severidad se cuentan como INFORMATIVA
            var severities = incidents
                .GroupBy(i => string.IsNullOrWhiteSpace(i.DictamenPericial.Severidad) ? "INFORMATIVA" : i.DictamenPericial.Severidad.ToUpperInvariant())
                .Select(g => new MetricItem
                {
                    Etiqueta = g.Key,
                    Cantidad = g.Count(),
                    Porcentaje = (double)g.Count() / TotalIncidentes * 100,
                    DetalleSecundario = $"{g.Count()} casos clasificados"
                })
                .OrderByDescending(x => x.Cantidad)
                .ToList();

            SeverityDistribution = new ObservableCollection<MetricItem>(severities);
        }

        // Traduce el código del canal de log a un nombre legible para el informe
        private static string FormatZoneName(string canal) => canal switch
        {
            "AUTH" => "Autenticación & Acceso (SSH/PAM)",
            "KERNEL" => "Núcleo / Subsistema de Red (iptables)",
            "NGINX" => "Servidor Web & Aplicaciones HTTP",
            "AUDIT" => "Auditoría de Procesos (auditd)",
            "FIM" => "Integridad de Archivos (FIM /etc)",
            _ => $"Canal: {canal}"
        };
    }
}