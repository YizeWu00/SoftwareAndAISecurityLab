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
        }
        // Capture device instance
        private ICaptureDevice device;

        // Capture result
        private DataTable packets = new DataTable();
        UInt64 packetsCount = 0;
        private double startTime = -1.0, arrivalRelativeTime = 0;
        object packets_lock = new object();
        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Title
            this.Title = "正在捕获: " + Utils.dev2name(device);
            // Datatable for packets
            packets.Columns.Add("number", typeof(string));
            packets.Columns.Add("time", typeof(string));
            packets.Columns.Add("source", typeof(string));
            packets.Columns.Add("destination", typeof(string));
            packets.Columns.Add("protocol", typeof(string));
            packets.Columns.Add("length", typeof(string));
            packets.Columns.Add("info", typeof(string));
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

        private void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            if (e == null)
                return;
            // Make sure it is a Ethernet packet
            Packet packet = Packet.ParsePacket(e.Device.LinkType, e.Packet.Data);
            if (packet is not EthernetPacket)
                Trace.WriteLine("Error ethernet");

            // Get Ethernet info
            EthernetPacket ep = (EthernetPacket)packet;
            string EthernetHwSourceAddr = ep.SourceHwAddress.ToString();
            string EthernetHwDestinationAddr = ep.DestinationHwAddress.ToString();

            // Number
            packetsCount++;

            // Time
            arrivalRelativeTime = double.Parse(e.Packet.Timeval.ToString().Replace("s",""));
            //if (arrivalRelativeTime is null)
            //    Trace.WriteLine("Error arrival");
            if (startTime < 0)
                startTime = arrivalRelativeTime;
            arrivalRelativeTime -= startTime;

            // Length
            int length = e.Packet.Data.Length;

            // Protocol, Source, Destination, Info
            /* source, destination and information is depended on protocol */
            string protocol = "", source = "", destination = "", info = "";
            var arp = (ARPPacket)ep.Extract(typeof(ARPPacket));

            if (arp != null) // ARP
            {
                protocol = "ARP";
                source = arp.SenderHardwareAddress.ToString();
                destination = arp.TargetHardwareAddress.ToString();
                if (arp.Operation is ARPOperation.Request)
                    info = "Who has " + arp.TargetProtocolAddress.ToString() + "?" + " Tell " + arp.SenderProtocolAddress.ToString();
                else
                    info = arp.SenderProtocolAddress.ToString() + "is at " + arp.SenderHardwareAddress.ToString();
            }
            else //IP
            {
                // Internet Layer
                IpPacket ip = (IpPacket)ep.Extract(typeof(IpPacket));
                if (ip.Version == IpVersion.IPv4)
                {
                    //Trace.WriteLine(ip.Version.ToString());
                }
                else if (ip.Version == IpVersion.IPv6)
                {
                    //Trace.WriteLine(ip.Version.ToString());
                }
                else
                {
                    Trace.WriteLine("Error not ip");
                    return;
                }

                // Transmission Layer
                var tcp = (TcpPacket)ep.Extract(typeof(TcpPacket));
                var icmpv4 = (ICMPv4Packet)ep.Extract(typeof(ICMPv4Packet));
                var icmpv6 = (ICMPv6Packet)ep.Extract(typeof(ICMPv6Packet));
                var udp = (UdpPacket)ep.Extract(typeof(UdpPacket));
                if (tcp != null)
                {
                    source = ip.SourceAddress.ToString();
                    destination = ip.DestinationAddress.ToString();
                    // Maybe http
                    var httpPayload = Encoding.ASCII.GetString(tcp.PayloadData);
                    var httpHeaders = httpPayload.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
                    if (httpHeaders.Length > 1 && httpHeaders[0].Contains("HTTP/")) 
                    {
                        //Trace.WriteLine("HTTP!");
                        // Set protocol
                        protocol = "HTTP";
                        // Extract information from the HTTP headers
                        var userAgent = Utils.GetHeaderValue(httpHeaders, "User-Agent");
                        var host = Utils.GetHeaderValue(httpHeaders, "Host");
                        var referer = Utils.GetHeaderValue(httpHeaders, "Referer");

                        // Print the extracted information
                        //Trace.WriteLine("User-Agent: {0}", userAgent);
                        //Trace.WriteLine("Host: {0}", host);
                        //Trace.WriteLine("Referer: {0}", referer);
                    }
                    if (protocol == "")
                    {
                        protocol = "TCP";
                        info = tcp.SourcePort.ToString() + " -> " + tcp.DestinationPort.ToString();
                    }
                }
                else if (icmpv4 != null)
                {
                    protocol = "ICMPv4";
                    source = ip.SourceAddress.ToString();
                    destination = ip.DestinationAddress.ToString();
                    info = "icmpv4";
                }
                else if (icmpv6 != null)
                {
                    protocol = "ICMPv6";
                    source = ip.SourceAddress.ToString();
                    destination = ip.DestinationAddress.ToString();
                    info = "icmpv6";
                }
                else if(udp != null)
                {
                    protocol = "UDP";
                    source = ip.SourceAddress.ToString();
                    destination= ip.DestinationAddress.ToString();
                    info = "UDP";
                }
            }
            DataRow packet_row = packets.NewRow();
            packet_row["number"] = packetsCount.ToString();
            packet_row["time"] = arrivalRelativeTime.ToString();
            packet_row["source"] = source;
            packet_row["destination"] = destination;
            packet_row["protocol"] = protocol;
            packet_row["length"] = length.ToString();
            packet_row["info"] = info;
            lock (packets_lock)
            {
                packets.Rows.Add(packet_row);
            }
            // Refresh UI
            Refresh_Datagrid(this.dg_packets);
        }


        private void Refresh_Datagrid(DataGrid dg)
        {
            new Thread(() => {
                this.Dispatcher.Invoke(() => {
                    dg.Items.Refresh();
                });
            }).Start();
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            device.StopCapture();
            device.Close();
            MainWindow mainWindow = new MainWindow();
            mainWindow.Show();
        }
    }
}
