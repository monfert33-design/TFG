using Avalonia.Controls;
using tcg.ViewModels;

namespace tcg.Views
{
    public partial class ReportsView : UserControl
    {
        public ReportsView()
        {
            InitializeComponent();
            DataContext = new ReportsViewModel();
        }
    }
}