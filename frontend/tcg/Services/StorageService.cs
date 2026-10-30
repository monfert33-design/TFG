using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using tcg.Models;

namespace tcg.Services
{
    // Persistencia local en JSON: histórico de incidentes y registro de auditoría de remediaciones
    public class StorageService
    {
        private readonly string _storageDir;
        private readonly string _incidentsFilePath;
        private readonly string _remediationsFilePath;

        public StorageService()
        {
            // Guarda los datos en una subcarpeta local de la aplicación
            _storageDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Data");
            if (!Directory.Exists(_storageDir))
            {
                Directory.CreateDirectory(_storageDir);
            }

            _incidentsFilePath = Path.Combine(_storageDir, "incident_history.json");
            _remediationsFilePath = Path.Combine(_storageDir, "remediation_history.json");
        }

        // --- GESTIÓN DE INCIDENTES ---

        // Carga el histórico guardado; si no existe o está corrupto devuelve una lista vacía
        public async Task<List<ForensicCaseResponse>> LoadIncidentsAsync()
        {
            if (!File.Exists(_incidentsFilePath)) return new List<ForensicCaseResponse>();
            try
            {
                var json = await File.ReadAllTextAsync(_incidentsFilePath);
                return JsonSerializer.Deserialize<List<ForensicCaseResponse>>(json) ?? new List<ForensicCaseResponse>();
            }
            catch
            {
                return new List<ForensicCaseResponse>();
            }
        }

        // Sobrescribe el fichero con la lista completa de casos (JSON indentado para poder leerlo)
        public async Task SaveIncidentsAsync(IEnumerable<ForensicCaseResponse> cases)
        {
            try
            {
                var options = new JsonSerializerOptions { WriteIndented = true };
                var json = JsonSerializer.Serialize(cases, options);
                await File.WriteAllTextAsync(_incidentsFilePath, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al guardar incidentes locales: {ex.Message}");
            }
        }

        // --- GESTIÓN DE REMEDIACIONES EJECUTADAS ---

        // Añade un registro de auditoría al principio, de modo que las más recientes salgan primero
        public async Task SaveRemediationLogAsync(RemediationAuditRecord record)
        {
            try
            {
                var list = await LoadRemediationsAsync();
                list.Insert(0, record);
                var options = new JsonSerializerOptions { WriteIndented = true };
                var json = JsonSerializer.Serialize(list, options);
                await File.WriteAllTextAsync(_remediationsFilePath, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al guardar registro de remediación: {ex.Message}");
            }
        }

        // Carga el registro de remediaciones; si no existe o está corrupto devuelve una lista vacía
        public async Task<List<RemediationAuditRecord>> LoadRemediationsAsync()
        {
            if (!File.Exists(_remediationsFilePath)) return new List<RemediationAuditRecord>();
            try
            {
                var json = await File.ReadAllTextAsync(_remediationsFilePath);
                return JsonSerializer.Deserialize<List<RemediationAuditRecord>>(json) ?? new List<RemediationAuditRecord>();
            }
            catch
            {
                return new List<RemediationAuditRecord>();
            }
        }
    }
}