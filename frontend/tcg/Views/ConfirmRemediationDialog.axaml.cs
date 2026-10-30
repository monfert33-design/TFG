using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;

namespace tcg.Views
{
    public partial class ConfirmRemediationDialog : Window
    {
        public bool Confirmed { get; private set; } = false;

        public ConfirmRemediationDialog()
        {
            InitializeComponent();
        }

        public ConfirmRemediationDialog(string tipo, string comando, string justificacion) : this()
        {
            TxtAccionTitulo.Text = tipo == "MATAR_PROCESO"
                ? "Se terminará forzosamente el proceso malicioso (SIGKILL):"
                : "Se aplicará la siguiente regla de filtrado en el firewall:";

            TxtComando.Text = string.IsNullOrWhiteSpace(comando) ? "Comando no especificado" : comando;
            TxtJustificacion.Text = $"Motivo: {justificacion}";
        }

        private void OnConfirmClicked(object? sender, RoutedEventArgs e)
        {
            Confirmed = true;
            this.Close();
        }

        private void OnCancelClicked(object? sender, RoutedEventArgs e)
        {
            Confirmed = false;
            this.Close();
        }
        private void OnPointerPressed(object? sender, PointerPressedEventArgs e)
        {
            if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
            {
                BeginMoveDrag(e);
            }
        }
    }
}