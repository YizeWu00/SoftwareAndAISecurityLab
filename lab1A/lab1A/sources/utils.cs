using SharpPcap;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace lab1A.sources
{
    class Utils
    {
        public static string dev2name(ICaptureDevice dev)
        {
            if (dev == null) return null;
            string[] devinfo = dev.ToString().Split("\n");
            foreach (string devinfo_item in devinfo)
                if (devinfo_item.StartsWith("FriendlyName")) 
                   return devinfo_item.Replace("FriendlyName: ", "");
            return null;
        }

        public static string GetHeaderValue(string[] headers, string name)
        {
            foreach (var header in headers)
            {
                var parts = header.Split(": " , 2);
                if (parts.Length == 2 && parts[0] == name)
                    return parts[1];
            }
            return null;
        }
    }
}
