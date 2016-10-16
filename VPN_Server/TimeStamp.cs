using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace timeStamp
{
    class TimeStamp
    {
        public static long createTimeStamp()
        {
            return DateTime.UtcNow.ToBinary();
        }

        public static bool isTimeStampValid(long timestamp, long timeAllowedInSeconds)
        {

            var stamp = new DateTime(timestamp);
            var difference = DateTime.UtcNow - stamp;
            if (difference.TotalSeconds >= 0 && difference.TotalSeconds <= timeAllowedInSeconds)
            {
                return true;
            }
            return false;
        }
    }
}
