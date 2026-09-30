using Avalonia.Controls;
using tcg.ViewModels;

namespace tcg
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            DataContext = new MainViewModel();
        }
    }
}