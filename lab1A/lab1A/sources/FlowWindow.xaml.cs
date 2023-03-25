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
using System.Runtime.CompilerServices;
using System.IO;
using System.Windows.Markup;
using System.Text.RegularExpressions;

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

            this.tcp_stream_list = new TCPStreamList();
            this.http_stream_list = new HTTPStreamList();
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
        // streams
        private TCPStreamList tcp_stream_list;
        private HTTPStreamList http_stream_list;
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
            packets.Columns.Add("raw", typeof(string));
            packets.Columns.Add("stream", typeof(string));
            packets.Columns.Add("protocol_tree", typeof(List<Protocol>));
            packets.Columns.Add("background", typeof(string));
            packets.Columns.Add("visibility", typeof(string));
            
            // dg packet source
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
                //Trace.WriteLine($"Packet count: {my_packetCount}");
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
                string source = "", destination = "", info = "", background = "";
                byte[] byte_stream = null;
                List<Protocol> protocol_tree = new List<Protocol>();
                ARPPacket arp = (ARPPacket)ep.Extract(typeof(ARPPacket));

                if (arp != null) // ARP
                {
                    ARPInfo arpinfo = new ARPInfo(arp); 
                    protocol_tree.Insert(0, arpinfo);
                    source = arp.SenderHardwareAddress.ToString();
                    destination = arp.TargetHardwareAddress.ToString();
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
                        // Get tcpinfo
                        TCPInfo tcpinfo = new TCPInfo(tcp, ipinfo.src_addr, ipinfo.dst_addr);
                        // add to tcp stream
                        tcpinfo.stream_id = AddPacketToTCPStreamList(tcpinfo, (int)my_packetCount);
                        //Trace.WriteLine($"id is {tcpinfo.stream_id}");
                        // insert to head of protocol tree
                        protocol_tree.Insert(0, tcpinfo);
                        source = ip.SourceAddress.ToString();
                        destination = ip.DestinationAddress.ToString();
                        byte_stream = tcp.PayloadData; // can be null!
                        // Maybe http
                        var httpPayload = Encoding.ASCII.GetString(tcp.PayloadData);
                        var httpHeaders = httpPayload.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
                        if (httpHeaders.Length > 1 && httpHeaders[0].Contains("HTTP/"))
                        {
                            // Set protocol
                            HTTPInfo hTTPInfo = new HTTPInfo();
                            protocol_tree.Insert(0, hTTPInfo);
                            // Extract information from the HTTP headers
                            var userAgent = Utils.GetHeaderValue(httpHeaders, "User-Agent");
                            var host = Utils.GetHeaderValue(httpHeaders, "Host");
                            var referer = Utils.GetHeaderValue(httpHeaders, "Referer");
                            background = "#33FF66";
                        }
                        if (protocol_tree[0].type != "http")
                        {
                            background = "#CC99FF";
                        }
                        // tcp stream

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
                        byte_stream = udp.PayloadData;
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
                packet_row["info"] = InfoGenerator(protocol_tree);
                packet_row["raw"] = BitConverter.ToString(ep.Bytes);
                packet_row["stream"] = byte_stream == null? "" : System.Text.Encoding.ASCII.GetString(byte_stream);;
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
                            FilterVisibilityOfRow(packet_row);
                            //Trace.WriteLine("1:" + my_packetCount.ToString());
                            packets.Rows.Add(packet_row);
                            isAdded = true;
                        }
                    }
                }
                // Refresh UI if previous packets have all been added to the datatable
                Refresh_Datagrid(this.dg_packets);
            }).Start();
        }
        // add tcp info to stream
        private int AddPacketToTCPStreamList(TCPInfo tcpinfo, int packet_num)
        {
            int id;
            if ((id = tcp_stream_list.CompareAndAddPacketToStreamListSync(tcpinfo, packet_num)) < 0)
            {
                // failure, create stream and add
                TCPStream new_stream = new TCPStream(tcpinfo.src_port, tcpinfo.dst_port, tcpinfo.src_ip_addr, tcpinfo.dst_ip_addr);
                id = tcp_stream_list.AddStreamToStreamListSync(new_stream);
                //Trace.WriteLine($"Create new id : {id}");
            }
            return id;
        }
        // Generate info item in datatable
        private string InfoGenerator(List<Protocol> protocol_tree)
        {
            string info;
            Regex info_start = new Regex(", ");
            Protocol protocol = protocol_tree[0];
            switch (protocol.type) 
            {
                case "arp":
                    ARPInfo arp = (ARPInfo)protocol;
                    if (arp.opcode is ARPOperation.Request)
                        info = "Who has " + arp.dst_ip_addr.ToString() + "?" + " Tell " + arp.src_ip_addr.ToString();
                    else if (arp.opcode is ARPOperation.Response)
                        info = arp.src_ip_addr.ToString() + "is at " + arp.dst_ip_addr.ToString();
                    else
                        info = "Unsupported opcode";
                    break;
                case "tcp":
                    TCPInfo tcp = (TCPInfo)protocol;
                    info = tcp.src_port.ToString() + " -> " + tcp.dst_port.ToString();
                    // flag info
                    string flag_info = "";
                    if (tcp.syn) flag_info += "SYN";
                    if (tcp.fin) flag_info += "FIN";
                    if (tcp.rst) flag_info += "RST";
                    if (tcp.ack) flag_info += ", ACK";
                    // remove ", " if startswith
                    if (flag_info.StartsWith(", "))
                        flag_info = info_start.Replace(flag_info, "", 1);
                    info += " [" + flag_info + "]";
                    //// seq ack info
                    //info += tcp.seq_num.ToString();
                    break;
                case "http":
                    info = "http";
                    break;
                case "icmp":
                    info = "icmp";
                    break;
                case "udp":
                    info = "udp";
                    break;
                default: info = "unknown"; break;
            }
            return info;
        }

        private void Refresh_Datagrid(DataGrid dg)
        {
            this.Dispatcher.Invoke(() => {
                dg.Items.Refresh();
            });
        }

        // Indicate the row index of stream follow
        private int row_index;
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
            MenuItem stream_follow = new MenuItem();
            stream_follow.Header = "追踪流";
            // get the row index
            DataGridCell cell = sender as DataGridCell;
            DataGridRow r2 = DataGridRow.GetRowContainingElement(cell);
            this.row_index = r2.GetIndex();
            DataRow row = packets.Rows[this.row_index];
            // If protocol trackable, show it in the menu
            List<Protocol> protocol_tree = (List<Protocol>)row["protocol_tree"];
            foreach (Protocol protocol in protocol_tree)
            {
                if (protocol.IsFollowable)
                {
                    MenuItem stream_follow_item = new MenuItem();
                    stream_follow_item.Header = protocol.type.ToUpper();
                    stream_follow_item.Click += new RoutedEventHandler(this.ShowStreamFollow);
                    stream_follow.Items.Add(stream_follow_item);
                }
            }
            // add "无" if no protocol can be tracked
            if (stream_follow.Items.Count == 0)
            {
                MenuItem no_trackable_item = new MenuItem();
                no_trackable_item.Header = "无";
                no_trackable_item.Foreground = new SolidColorBrush(Colors.Gray);
                no_trackable_item.IsEnabled = false;
                stream_follow.Items.Add(no_trackable_item);
            }
            // add flow track option to main menu
            contextMenu.Items.Add(stream_follow);
            contextMenu.IsOpen = true;
        }
        // show the window of stream follow
        private void ShowStreamFollow(object sender, RoutedEventArgs e)
        {
            MenuItem stream_follow_item =(MenuItem)sender;
            if (stream_follow_item == null)
            {
                Trace.WriteLine("stream follow null");
                return;
            }
            // stream window
            StreamFollowWindow streamFollowWindow = new StreamFollowWindow();
            streamFollowWindow.dg_stream.ItemsSource = packets.DefaultView;
            // type
            string stream_type = stream_follow_item.Header.ToString().ToLower();
            // id
            DataRow row = packets.Rows[this.row_index];
            List<Protocol> protocol_tree = (List<Protocol>)row["protocol_tree"];
            int stream_id = -1;
            foreach (Protocol protocol in protocol_tree)
            {
                if (protocol.type == stream_type)
                {
                    // change to followable
                    FollowableProtocol followableProtocol = (FollowableProtocol)protocol;
                    stream_id = followableProtocol.stream_id; break;
                }
            }
            if (stream_id == -1)
            {
                Trace.WriteLine("id not found??");
                return;
            }
            // set visibility of packets by type and stream
            this.filter = stream_type + ".stream eq " + stream_id.ToString();
            tb_filter.Text = this.filter;
            StreamFollowAllVisibility(stream_type, stream_id);

            streamFollowWindow.Show();

        }

        // update stream follow all visibility
        private void StreamFollowAllVisibility(string stream_type, int stream_id)
        {
            lock (packets_lock)
            {
                foreach (DataRow row in packets.Rows)
                {
                    bool isvisible = false;
                    List<Protocol> protocol_tree = row["protocol_tree"] as List<Protocol>;
                    foreach (Protocol protocol in protocol_tree)
                    {
                        if (protocol.IsFollowable == true && protocol.type == stream_type)
                        {
                            FollowableProtocol f = (FollowableProtocol)protocol;
                            if (f.stream_id == stream_id)
                            {
                                isvisible = true;
                                break;
                            }

                        }
                    }
                    if (!isvisible)
                        row["visibility"] = "Collapsed";
                    else
                        row["visibility"] = "Visible";
                }
            }
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
            FilterAllVisibility();
        }

        // set visibility of datagrid according to this.filter
        private void FilterAllVisibility()
        {
            lock (packets_lock) // for consistency
            {
                foreach (DataRow row in packets.Rows)
                {
                    FilterVisibilityOfRow(row);
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
        private void FilterVisibilityOfRow(DataRow row)
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

        // show packet hex in textbox
        private void dg_packets_DataGridCell_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            DataGridCell cell = sender as DataGridCell;
            DataGridRow r2 = DataGridRow.GetRowContainingElement(cell);
            this.row_index = r2.GetIndex();
            DataRow row = packets.Rows[this.row_index];
            this.tb_raw_packet.Text = (string)row["raw"];
        }
    }
}
