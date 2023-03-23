using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Collections.Concurrent;

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

            this.device = dev;
            this.packets = new DataTable();
            this.packets_lock = new object();
            this.packetsCount = 0;
            this.packetsCount_lock = new object();
            this.startTime = -1.0;
            this.startTime_lock = new object();

            this.filter = "";
        }
        // Capture device instance
        private ICaptureDevice device;

        // Capture result
        private DataTable packets;
        private object packets_lock;
        private uint packetsCount;
        private object packetsCount_lock;
        private double startTime;
        private object startTime_lock;
        // filter string
        private string filter;

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Title
            this.Title = "正在捕获: " + Utils.dev2name(device);
            // Datatable for packets
            /* Visible */
            packets.Columns.Add("number", typeof(string));
            packets.Columns.Add("time", typeof(string));
            packets.Columns.Add("source", typeof(string));
            packets.Columns.Add("destination", typeof(string));
            packets.Columns.Add("protocol", typeof(string));
            packets.Columns.Add("length", typeof(string));
            packets.Columns.Add("info", typeof(string));
            /* Unvisible */
            packets.Columns.Add("raw", typeof(byte[]));
            packets.Columns.Add("protocol_tree", typeof(List<Protocol>));
            packets.Columns.Add("background", typeof(string));
            packets.Columns.Add("visibility", typeof(string));
            this.dg_packets.ItemsSource = packets.DefaultView;
            // Bind lock for consistency
            BindingOperations.EnableCollectionSynchronization(packets.DefaultView, packets_lock);
            // register hander
            device.OnPacketArrival += new SharpPcap.PacketArrivalEventHandler(device_OnPacketArrival);
            // open device
            int readTimeoutMs = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMs);
            // start capture
            device.StartCapture();
        }

        /// <summary>
        /// packet arrival handler
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            if (e == null)
                return;
            // Make sure it is a Ethernet packet
            Packet packet = Packet.ParsePacket(e.Device.LinkType, e.Packet.Data);
            if (packet is not EthernetPacket)
                Trace.WriteLine("Error ethernet");

            // 1.Sequence work can be done here, because it is not complicated
            // Number
            uint my_packetCount;
            lock (packetsCount_lock)
            {
                this.packetsCount += 1;
                my_packetCount = this.packetsCount;
                Trace.WriteLine($"Packet count: {my_packetCount}");
            }
            // Time
            double arrivalRelativeTime = double.Parse(e.Packet.Timeval.ToString().Replace("s", ""));
            if (startTime < 0)
            {
                lock (startTime_lock)
                {
                    if (startTime < 0)
                        startTime = arrivalRelativeTime;
                }
            }
            arrivalRelativeTime -= startTime;

            // 2.Complicated work can be done in a new thread, using concurrent benefit
            new Thread(() =>
            {
                // Get Ethernet info
                EthernetPacket ep = (EthernetPacket)packet;
                string EthernetHwSourceAddr = ep.SourceHwAddress.ToString();
                string EthernetHwDestinationAddr = ep.DestinationHwAddress.ToString();

                // Length
                int length = e.Packet.Data.Length;

                // Protocol, Source, Destination, Info
                /* source, destination and information is depended on protocol */
                string protocol = "", source = "", destination = "", info = "", background = "";
                List<Protocol> protocol_tree = new List<Protocol>();
                ARPPacket arp = (ARPPacket)ep.Extract(typeof(ARPPacket));

                if (arp != null) // ARP
                {
                    ARPInfo arpinfo = new ARPInfo(arp); 
                    protocol_tree.Insert(0, arpinfo);
                    protocol = "ARP";
                    source = arp.SenderHardwareAddress.ToString();
                    destination = arp.TargetHardwareAddress.ToString();
                    if (arp.Operation is ARPOperation.Request)
                        info = "Who has " + arp.TargetProtocolAddress.ToString() + "?" + " Tell " + arp.SenderProtocolAddress.ToString();
                    else
                        info = arp.SenderProtocolAddress.ToString() + "is at " + arp.SenderHardwareAddress.ToString();
                    background = "#FFCC00";
                }
                else //IP
                {
                    // Internet Layer
                    IpPacket ip = (IpPacket)ep.Extract(typeof(IpPacket));
                    if (ip == null)
                    {
                        Trace.WriteLine("Error not ip");
                        return;
                    }
                    IPInfo ipinfo = new IPInfo(ip);
                    protocol_tree.Insert(0, ipinfo);
                    // Transmission Layer
                    var tcp = (TcpPacket)ep.Extract(typeof(TcpPacket));
                    var icmpv4 = (ICMPv4Packet)ep.Extract(typeof(ICMPv4Packet));
                    var icmpv6 = (ICMPv6Packet)ep.Extract(typeof(ICMPv6Packet));
                    var udp = (UdpPacket)ep.Extract(typeof(UdpPacket));
                    if (tcp != null)
                    {
                        TCPInfo tcpinfo = new TCPInfo(tcp);
                        protocol_tree.Insert(0, tcpinfo);
                        source = ip.SourceAddress.ToString();
                        destination = ip.DestinationAddress.ToString();
                        // Maybe http
                        var httpPayload = Encoding.ASCII.GetString(tcp.PayloadData);
                        var httpHeaders = httpPayload.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
                        if (httpHeaders.Length > 1 && httpHeaders[0].Contains("HTTP/"))
                        {
                            // Set protocol
                            HTTPInfo hTTPInfo = new HTTPInfo();
                            protocol_tree.Insert(0, hTTPInfo);
                            protocol = "HTTP";
                            // Extract information from the HTTP headers
                            var userAgent = Utils.GetHeaderValue(httpHeaders, "User-Agent");
                            var host = Utils.GetHeaderValue(httpHeaders, "Host");
                            var referer = Utils.GetHeaderValue(httpHeaders, "Referer");
                            background = "#33FF66";
                            // Print the extracted information
                            //Trace.WriteLine("User-Agent: {0}", userAgent);
                            //Trace.WriteLine("Host: {0}", host);
                            //Trace.WriteLine("Referer: {0}", referer);
                        }
                        if (protocol == "")
                        {
                            info = tcp.SourcePort.ToString() + " -> " + tcp.DestinationPort.ToString();
                            background = "#CC99FF";
                        }
                    }
                    else if (icmpv4 != null)
                    {
                        source = ip.SourceAddress.ToString();
                        destination = ip.DestinationAddress.ToString();
                        info = "icmpv4";
                        background = "#666666";
                        ICMPInfo iCMPv4Info = new ICMPInfo(icmpv4);
                        protocol_tree.Insert(0, iCMPv4Info);
                    }
                    else if (icmpv6 != null)
                    {
                        source = ip.SourceAddress.ToString();
                        destination = ip.DestinationAddress.ToString();
                        info = "icmpv6";
                        background = "#FF66FF";
                        ICMPInfo iCMPv6Info = new ICMPInfo(icmpv6);
                        protocol_tree.Insert(0, iCMPv6Info);
                    }
                    else if (udp != null)
                    {
                        UDPInfo uDPInfo = new UDPInfo(udp);
                        protocol_tree.Insert(0, uDPInfo);
                        source = ip.SourceAddress.ToString();
                        destination = ip.DestinationAddress.ToString();
                        info = "UDP";
                        background = "#00CCFF";
                    }
                }
                // create new row
                DataRow packet_row;
                lock (packets_lock)
                {
                    packet_row = packets.NewRow();
                }
                packet_row["number"] = my_packetCount.ToString();
                packet_row["time"] = arrivalRelativeTime.ToString();
                packet_row["source"] = source;
                packet_row["destination"] = destination;
                packet_row["protocol"] = protocol_tree[0].type.ToUpper() + protocol_tree[0].version;
                packet_row["length"] = length.ToString();
                packet_row["info"] = info;
                packet_row["raw"] = ep.Bytes;
                packet_row["protocol_tree"] = protocol_tree;
                packet_row["background"] = background;
                // add to datatable in seq                
                bool isAdded = false;
                while (!isAdded)
                {
                    lock (packets_lock)
                    {
                        if (packets.Rows.Count == ((int)my_packetCount - 1))
                        {
                            UpdateVisibilityOfRow(packet_row);
                            Trace.WriteLine("1:" + my_packetCount.ToString());
                            //packets.Rows.InsertAt(packet_row, (int)my_packetCount - 1);
                            packets.Rows.Add(packet_row);
                            isAdded = true;
                        }
                    }
                }
                // Refresh UI if previous packets have all been added to the datatable
                Refresh_Datagrid(this.dg_packets);
            }).Start();
        }


        private void Refresh_Datagrid(DataGrid dg)
        {
            this.Dispatcher.Invoke(() => {
                dg.Items.Refresh();
            });
        }

        /// <summary>
        /// ContextMenu for Flow Track
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void dg_packets_DataGridCell_MouseRightButtonUp(object sender, MouseButtonEventArgs e)
        {
            if (sender == null) return;
            // context menu
            ContextMenu contextMenu = new ContextMenu();
            contextMenu.HasDropShadow = true;
            /* flow track item */
            MenuItem flow_track = new MenuItem();
            flow_track.Header = "追踪流";
            // get the row index
            DataGridCell cell = sender as DataGridCell;
            DataGridRow r2 = DataGridRow.GetRowContainingElement(cell);
            int row_index = r2.GetIndex();
            DataRow row = packets.Rows[row_index];
            // If protocol trackable, show it in the menu
            List<Protocol> protocol_tree = (List<Protocol>)row["protocol_tree"];
            foreach (Protocol protocol in protocol_tree)
            {
                if (protocol.IsTrackable)
                {
                    MenuItem flow_track_item = new MenuItem();
                    flow_track_item.Header = protocol.type.ToUpper();
                    flow_track.Items.Add(flow_track_item);
                }
            }
            // add "无" if no protocol can be tracked
            if (flow_track.Items.Count == 0)
            {
                MenuItem no_trackable_item = new MenuItem();
                no_trackable_item.Header = "无";
                no_trackable_item.Foreground = new SolidColorBrush(Colors.Gray);
                no_trackable_item.IsEnabled = false;
                flow_track.Items.Add(no_trackable_item);
            }
            // add flow track option to main menu
            contextMenu.Items.Add(flow_track);
            contextMenu.IsOpen = true;
        }


        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            device.StopCapture();
            device.Close();
            MainWindow mainWindow = new MainWindow();
            mainWindow.Show();
        }
        // accept input when enter
        private void tb_filter_KeyUp(object sender, KeyEventArgs e)
        {
            if (e.Key != Key.Enter) return;
            this.filter = tb_filter.Text;
            //Trace.WriteLine(this.filter);
            UpdateAllVisibility();
        }

        // set visibility of datagrid according to this.filter
        private void UpdateAllVisibility()
        {
            lock (packets_lock) // for consistency
            {
                foreach (DataRow row in packets.Rows)
                {
                    UpdateVisibilityOfRow(row);
                }
            }
        }
        // visibility code
        private enum Visiblity
        {
            Visible,
            Hidden,
            Collapsed
        }

        // for filter to update row's visibility
        private void UpdateVisibilityOfRow(DataRow row)
        {
            if (this.filter == "")
            {
                row["visibility"] = "Visible";
                return;
            }
            // if protocol tree has it in, then visible, else collapsed
            List<Protocol> protocol_tree = (List<Protocol>)row["protocol_tree"];
            foreach (Protocol protocol in protocol_tree)
            {
                if (protocol.type == this.filter)
                {
                    row["visibility"] = "Visible";
                    return;
                }
            }
            row["visibility"] = "Collapsed";
        }
        private void btn_StopCapture_Click(object sender, RoutedEventArgs e)
        {
            device.StopCapture();
            device.Close();
        }

        private void btn_RestartCapture_Click(object sender, RoutedEventArgs e)
        {
            // clear original table
            lock (packets_lock)
            {
                packets.Clear();
            }
            // reset start time
            lock (startTime_lock)
            {
                startTime = -1.0;
            }
            // reset packet count
            lock (packetsCount_lock)
            {
                packetsCount = 0;
            }
            // reset handler
            device.OnPacketArrival += new SharpPcap.PacketArrivalEventHandler(device_OnPacketArrival);
            // reopen device
            int readTimeoutMs = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMs);
            // start capture
            device.StartCapture();
        }
    }
}
