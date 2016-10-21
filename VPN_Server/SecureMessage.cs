using System;

namespace TCPcrypt
{
    class SecureMessage : HashedMessage
    {
        public ulong Count = 0;
        public bool isSecure = false;

        protected const int COUNTER_LENGTH = 12; //string
        protected const string SERVER_ID = "server";
        protected const string CLIENT_ID = "client";
        protected const int ID_LENGTH = 6;

        public SecureMessage(string errorMessage)
        {
            Error = errorMessage;
        }

        public SecureMessage(string unparsed, ulong currentCount, bool fromClient)
            : base(unparsed)
        {
            if (Message.Length < COUNTER_LENGTH + ID_LENGTH)
            {
                Error = "Message too small";
                return;
            }
            var ID = Message.Substring(0, ID_LENGTH);
            var textCount = Message.Substring(ID_LENGTH, COUNTER_LENGTH);
            Count = BitConverter.ToUInt64(Convert.FromBase64String(textCount), 0);
            Message = Message.Substring(ID_LENGTH + COUNTER_LENGTH);
            if (!hashMatched)
            {
                return;
            }
            else if (Count <= currentCount)
            {
                Error = "MessageCount Error: Possible Replay Attack";
                return;
            }
            else if (ID != SERVER_ID && ID != CLIENT_ID)
            {
                Error = "Unrecognized ID: " + ID;
                return;
            }
            else if ((ID == CLIENT_ID && !fromClient) || (ID == SERVER_ID && fromClient))
            {
                Error = "Incorrect ID used : Possible Replay Attack";
                return;
            }
            else
            {
                isSecure = true;
            }
        }

        // format: 27 char: hash, 6 char: ID, 12 char: count, rest for message;
        public static string FormMessage(ulong messageNumber, string text, bool isServer)
        {

            var toHash = (isServer ? SERVER_ID : CLIENT_ID)
                + Convert.ToBase64String(BitConverter.GetBytes(messageNumber))
                + text;
            return HashedMessage.FormMessage(toHash);
        }
    }
}
