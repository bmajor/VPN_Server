using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MyFuctions
{
    class Help
    {
        //returns buf1 || buf2
        public static byte[] combine(byte[] buf1, byte[] buf2)
        {
            byte[] combined = new byte[buf1.Length + buf2.Length];
            Buffer.BlockCopy(buf1, 0, combined, 0, buf1.Length);
            Buffer.BlockCopy(buf2, 0, combined, buf1.Length, buf2.Length);
            return combined;
        }
    }
}
