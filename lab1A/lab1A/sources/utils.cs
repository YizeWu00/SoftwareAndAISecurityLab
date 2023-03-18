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
    }
}
