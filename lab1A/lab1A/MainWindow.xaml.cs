using SharpPcap;
using System;
using System.Collections.Generic;
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
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Diagnostics;
using lab1A.sources;
using System.Data;

namespace lab1A
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private CaptureDeviceList devices;
        private DataTable dt_devices;
        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Retrieve the device list
            devices = CaptureDeviceList.Instance;

            // If no devices were found print an error
            if (devices.Count < 1)
            {
                MessageBox.Show("No devices were found on this machine");
                return;
            }

            // Show device name
            dt_devices = new System.Data.DataTable();
            dt_devices.Columns.Add("device", typeof(string));
            // Extract device name
            foreach (ICaptureDevice dev in devices)
            {
                string devname = Utils.dev2name(dev);
                if (devname != null)
                {
                    DataRow row = dt_devices.NewRow();
                    row["device"] = devname;
                    dt_devices.Rows.Add(row);
                }
            }
            dtgrid_devices.ItemsSource = dt_devices.DefaultView;
        }

        private void dtgrid_devices_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            DataGridCell dc = (DataGridCell)sender;
            TextBlock dc_tb = dc.Content as TextBlock;
            foreach (ICaptureDevice dev in devices)
            {
                string devname = Utils.dev2name(dev);
                if (devname == dc_tb.Text)
                {
                    FlowWindow flowWindow = new FlowWindow(dev as ICaptureDevice);
                    flowWindow.Show();
                    this.Close();
                }
            }
        }

    }
}
