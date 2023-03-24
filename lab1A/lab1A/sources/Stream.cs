using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection.Metadata;
using System.Text;
using System.Threading.Tasks;

namespace lab1A.sources
{
    public class Stream
    {
        public string? type;
        public int id;
        public List<int> packet_nums;
        public object mylock;
        public Stream() 
        {
            this.packet_nums = new List<int>();
            this.mylock = new object();
        }
        // add payload to flow (single thread)
        public virtual int CompareAndAddPacketToStream(Protocol protocol, int packet_num) { return -1; }
    }

    // stream list
    public class StreamList
    {
        public string? type;
        public List<Stream> stream_list;
        public volatile int idCount;
        public object mylock;
        private object idCountLock;
        public StreamList()
        {
            this.stream_list = new List<Stream>();
            this.mylock= new object();
            this.idCount = 0;
            this.idCountLock = new object();
        }
        public int CompareAndAddPacketToStreamListSync(Protocol protocol, int packet_num)
        {
            int id = -1;
            lock (this.mylock)
            {
                foreach (Stream stream in this.stream_list)
                {
                    if ((id = stream.CompareAndAddPacketToStream(protocol, packet_num)) >= 0)
                        break;
                }
            }
            return id;
        }
        private int GetNewId()
        {
            int id;
            lock (this.idCountLock)
            {
                id = idCount++;
            }
            return id;
        }
        /// <summary>
        /// return id of this stream
        /// </summary>
        /// <param name="stream"></param>
        /// <returns></returns>
        public int AddStreamToStreamListSync(Stream stream)
        {
            int id = GetNewId();
            lock (this.mylock)
            {
                stream.id = id;
                this.stream_list.Add(stream);
            }
            return id;
        }
    }

    public class TCPStream : Stream 
    {
        // pend list
        public UInt16 client_port, server_port;
        public IPAddress client_ip_addr, server_ip_addr;
        public List<Direction> directions;
        public TCPStream(UInt16 client_port, UInt16 server_port, IPAddress client_ip_addr, IPAddress server_ip_addr)
        {
            this.type = "tcp";
            this.client_port = client_port;
            this.server_port = server_port; 
            this.client_ip_addr = client_ip_addr;
            this.server_ip_addr = server_ip_addr;
            this.directions = new List<Direction>();
        }
        // tcp connection status
        public enum TCP_Status
        {
            NONE,
            SYNC_CLIENT,
            SYNC_SERVER,
            ESTABLISHED,
            FIN_CLIENT,
            ACKFIN_SERVER,                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      
            FINACK_SERVER,
            CLOSED
        }
        public enum Direction
        {
            ToClient,
            ToServer,
        }
        /// <summary>
        /// 同步，添加成功返回stream id，失败返回-1
        /// </summary>
        /// <param name="info"></param>
        /// <param name="num"></param>
        /// <returns></returns>
        public override int CompareAndAddPacketToStream(Protocol protocol, int packet_num)
        {
            TCPInfo info = (TCPInfo)protocol;
            //Trace.WriteLine("client port:" + this.client_port.ToString());
            //Trace.WriteLine("server port:" + this.server_port.ToString());
            //Trace.WriteLine("client ip:" + this.client_ip_addr.ToString());
            //Trace.WriteLine("server ip:" + this.server_ip_addr.ToString());
            //Trace.WriteLine("info src port:" + info.src_port.ToString());
            //Trace.WriteLine("info dst port:" + info.dst_port.ToString());
            //Trace.WriteLine("info src ip:" + info.src_ip_addr.ToString());
            //Trace.WriteLine("info dst ip:" + info.dst_ip_addr.ToString());
            //Trace.WriteLine(IPAddress.Equals(info.src_ip_addr, this.client_ip_addr));
            //Trace.WriteLine(IPAddress.Equals(info.dst_ip_addr, this.server_ip_addr));
            //Trace.WriteLine(info.src_port == this.client_port);
            //Trace.WriteLine(info.dst_port == this.server_port);

            if (IPAddress.Equals(info.src_ip_addr, this.client_ip_addr) && IPAddress.Equals(info.dst_ip_addr, this.server_ip_addr) && info.src_port == this.client_port && info.dst_port == this.server_port)
            {
                packet_nums.Add(packet_num);
                directions.Add(Direction.ToServer);
                return this.id;
            }
            else if (IPAddress.Equals(info.src_ip_addr, this.server_ip_addr) && IPAddress.Equals(info.dst_ip_addr, this.client_ip_addr) && info.src_port == this.server_port && info.dst_port != this.client_port)
            {
                packet_nums.Add(packet_num);
                directions.Add(Direction.ToClient);
                return this.id;
            }
            else
            {
                return -1;
            }
            
        }
    }

    // http stream
    public class HTTPStream : TCPStream
    {
        public HTTPStream(UInt16 client_port, UInt16 server_port, IPAddress client_ip_addr, IPAddress server_ip_addr) :
            base (client_port, server_port, client_ip_addr, server_ip_addr)
        {
            this.type = "http";
        }
    }

    // tcp stream list
    public class TCPStreamList : StreamList
    {
        public TCPStreamList()
        {
            this.type= "tcp";
        }
    }
    // http stream list
    public class HTTPStreamList : StreamList
    {
        public HTTPStreamList()
        {
            this.type = "http";
        }
    }
}
