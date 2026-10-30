using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;

namespace tcg.Views
{
    public partial class WarningDialog : Window
    {
        public WarningDialog()
        {
            InitializeComponent();
        }

        public WarningDialog(string detalleError) : this()
        {
            if (!string.IsNullOrWhiteSpace(detalleError))
            {
                TxtDetalleError.Text = $"Detalle: {detalleError}\n\nEl sistema continuará en modo lectura/análisis local.";
            }
        }

        private void OnCloseClicked(object? sender, RoutedEventArgs e)
        {
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