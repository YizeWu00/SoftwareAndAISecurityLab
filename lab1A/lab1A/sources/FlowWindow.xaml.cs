using SharpPcap;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace lab1A.sources
{
    /// <summary>
    /// Window1.xaml 的交互逻辑
    /// </summary>
    public partial class FlowWindow : Window
    {
        public FlowWindow(ICaptureDevice dev)
        {
            InitializeComponent();
            this.dev = dev;
        }
        private ICaptureDevice dev;

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            Trace.WriteLine(Utils.dev2name(dev));
            this.Title = "正在捕获: " + Utils.dev2name(dev);
        }
    }
}
