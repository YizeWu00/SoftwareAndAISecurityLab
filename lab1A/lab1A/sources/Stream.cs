using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace lab1A.sources
{
    public class Stream
    {
        public string? type;
        public List<byte[]> payloads;
        private object mylock;
        public Stream() 
        {
            this.payloads = new List<byte[]>();
            this.mylock = new object();
        }
        // Payload status
        public enum Payload_status
        {
            SUCCESS = 0,
            LATE = 1,
            PEND = 2,
        }
        // add payload to flow (single thread)
        private Payload_status Add_to_Flow(uint start, byte[] payload)
        {
            return Payload_status.SUCCESS;
            //uint end = start + (uint)payload.Length;
            //if (end <= this.payload.Length)
            //    return Payload_status.LATE;
            //else if (this.payload.Length < start)
            //{
            //    // add packet to pend list
            //    Add_to_Pend_List(start, payload);
            //    return Payload_status.PEND;
            //}
            //else
            //{
            //    // at least 1 byte should be added to the flow
            //    byte[] add = new byte[(end - this.payload.Length)];
            //    payload.CopyTo(add, this.payload.Length - start);
            //    this.payload = (byte[])this.payload.Concat(add);
            //    // check if any pended item can be removed
            //    Check_Pend_List_and_Add_to_Flow();
            //    return Payload_status.SUCCESS;
            //}
        }
        // add payload to pend list (single thread)
        //private void Add_to_Pend_List(uint start, byte[] payload)
        //{
        //    PendListItem pend_list_item = new PendListItem(start, payload);
        //    this.pend_list.Add(pend_list_item);
        //}
        //// check and add
        //private void Check_Pend_List_and_Add_to_Flow()
        //{
        //    foreach (PendListItem pend_item in this.pend_list)
        //    {
                
        //    }
        //}
    }

    public class TCPStream : Stream 
    {
        // pend list
        public UInt16 client_port, server_port;
        public IPAddress client_ip_addr, server_ip_addr;
        public TCPStream(UInt16 client_port, UInt16 server_port, IPAddress client_ip_addr, IPAddress server_ip_addr)
        {
            this.type = "tcp";
            this.client_port = client_port;
            this.server_port = server_port; 
            this.client_ip_addr = client_ip_addr;
            this.server_ip_addr = server_ip_addr;
        }
        
    }
}
