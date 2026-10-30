namespace tcg.Models
{
    // Elemento genérico de estadística que se muestra en los paneles del informe
    public class MetricItem
    {
        // Nombre del grupo (una IP, un tipo de ataque, una zona, una severidad...)
        public string Etiqueta { get; set; } = string.Empty;

        // Número de incidentes del grupo y su peso sobre el total (0-100)
        public int Cantidad { get; set; }
        public double Porcentaje { get; set; }

        // Texto de apoyo bajo la etiqueta (ej. "3 eventos detectados")
        public string DetalleSecundario { get; set; } = string.Empty;
    }
}