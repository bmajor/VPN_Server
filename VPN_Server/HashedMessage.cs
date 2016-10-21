using System;
using System.Text;
using System.Security.Cryptography;

namespace TCPcrypt
{
    class HashedMessage
    {
        public string Message = "";
        public string Hash = "";
        public string Error = "";
        public bool hashMatched;

        private const int HASH_LENGTH_64 = 28;

        public HashedMessage()
        {
            hashMatched = false;
        }

        public HashedMessage(string unparsed)
        {
            if (unparsed.Length < HASH_LENGTH_64)
            {
                hashMatched = false;
                Error = "Message too small";
                return;
            }
            Hash = unparsed.Substring(0, HASH_LENGTH_64);
            Message = unparsed.Substring(HASH_LENGTH_64);
            var computedHash = HashMessage(Message);
            if (Hash != computedHash)
            {
                hashMatched = false;
                Error = "Hash does not match: Computed Hash:" + computedHash + " Recieved Hash:" + Hash;
            }
            else
                hashMatched = true;
        }

        public static string FormMessage(string text)
        {
            return HashMessage(text) + text;
        }

        private static string HashMessage(string Message)
        {
            UTF8Encoding encoder = new UTF8Encoding();
            SHA1CryptoServiceProvider hashProvider = new SHA1CryptoServiceProvider();
            return Convert.ToBase64String(hashProvider.ComputeHash(encoder.GetBytes(Message)));
        }
    }
}
