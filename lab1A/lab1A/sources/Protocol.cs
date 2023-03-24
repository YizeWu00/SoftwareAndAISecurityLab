using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace lab1A.sources
{
    public class Protocol
    {
        public string type { get; set; }
        public string version { get; set; }
        /// <summary>
        /// Trackable or not
        /// </summary>
        public bool IsFollowable;
    }
    public class FollowableProtocol : Protocol
    {
        public int stream_id;
        public FollowableProtocol() 
        {
            this.IsFollowable = true;
        }
    }
    public class UnfollowableProtocol : Protocol
    {
        public int stream_id;
        public UnfollowableProtocol()
        {
            this.IsFollowable = false;
        }
    }

    // HTTP info
    public class HTTPInfo : FollowableProtocol
    {
        public HTTPInfo()
        {
            this.type = "http";
        }
    }

    // TCP info
    public class TCPInfo : FollowableProtocol
    {
        // normal
        public UInt16 src_port, dst_port;
        public UInt32 seq_num, ack_num;
        public int data_offset;
        public byte flag;
        public bool urg, ack, psh, rst, syn, fin, ECN, CWR;
        public uint window_size;
        // util
        public IPAddress src_ip_addr, dst_ip_addr;
        public TCPInfo(TcpPacket packet, IPAddress src_ip_addr, IPAddress dst_ip_addr)
        {
            this.type = "tcp";
            this.src_port = (UInt16)(packet.SourcePort);
            this.dst_port = (UInt16)(packet.DestinationPort);
            this.seq_num = packet.SequenceNumber;
            this.ack_num = packet.AcknowledgmentNumber;
            this.data_offset = packet.DataOffset;
            this.flag = packet.AllFlags;
            this.urg = packet.Urg; this.ack = packet.Ack; this.psh = packet.Psh; this.rst = packet.Rst; this.syn = packet.Syn; this.fin = packet.Fin; this.ECN = packet.ECN; this.CWR = packet.CWR; 
            this.window_size = packet.WindowSize;

            this.src_ip_addr = src_ip_addr;
            this.dst_ip_addr = dst_ip_addr;
        }
    }

    // IP info
    public class IPInfo : UnfollowableProtocol
    {
        public IPAddress src_addr, dst_addr;
        public IPInfo(IpPacket packet)
        {
            this.type = "ip";
            this.version = packet.Version.ToString();
            this.src_addr = packet.SourceAddress;
            this.dst_addr = packet.DestinationAddress;
        }
    }

    // ARP info
    public class ARPInfo : UnfollowableProtocol
    {
        public EthernetPacketType protocol_addr_type;
        public ARPOperation opcode;
        public IPAddress src_ip_addr, dst_ip_addr;
        public PhysicalAddress src_hw_addr, dst_hw_addr;
        public ARPInfo(ARPPacket packet) 
        {
            this.type = "arp";
            this.protocol_addr_type = packet.ProtocolAddressType;
            this.opcode = packet.Operation;
            this.src_ip_addr = packet.SenderProtocolAddress; this.dst_ip_addr = packet.TargetProtocolAddress;
            this.src_hw_addr = packet.SenderHardwareAddress; this.dst_hw_addr= packet.TargetHardwareAddress;
        }
    } 
    // icmp info
    public class ICMPInfo : UnfollowableProtocol
    {
        public ICMPInfo(ICMPv4Packet packet)
        {
            this.type = "icmp";
            this.version = "v4";
        }
        public ICMPInfo(ICMPv6Packet packet)
        {
            this.type = "icmp";
            this.version = "v6";
        }
    }
    // udp info
    public class UDPInfo : FollowableProtocol
    {
        public int src_port, dst_port;
        public UDPInfo(UdpPacket packet)
        {
            this.type = "udp";
            this.src_port = packet.SourcePort;
            this.dst_port = packet.DestinationPort;
        }
    }
}
