using System;
using System.Threading;
using TCPcrypt;

namespace VPN_Server
{
    class VPN
    {
        #region variables
        private string IP;
        private int port;
        private bool verbose;
        private bool isServer;
        private string password;
        private Thread readThread;
        encryptedTCP2 cryptTCP;
        #endregion

        #region Constants
        private const int DEFAULT_PORT = 10245;				//Default port to listen on if one isn't declared
        private const string DEFAULT_IP = "127.0.0.1";
        private const string SALT = "~ÆL4|3G.";
        #endregion

        #region Constructors
        public VPN()
        {
            getSettings();
        }
        
        public VPN(string[] args)
        {
            if (args.Length == 0)
            {
                getSettings();
            }
            else
            {
                verbose = false;
                IP = DEFAULT_IP;
                port = DEFAULT_PORT;
                string[] formatedArgs = new string[args.Length];
                int i = 0;
                foreach (string s in args)
                {
                    formatedArgs[i] = s.Trim().ToLower();
                    i++;
                }
                bool isGood = false;
                foreach (string s in args)
                {
                    if (s == "-v")
                    {
                        verbose = true;
                    }
                    i++;
                }
                foreach (string s in args)
                {
                    if (s == "-s" || s == "-c")
                    {
                        isServer = s == "-s";
                        isGood = true;
                    }
                }
                if (isGood)
                {
                    getPassword();
                }
                else
                {
                    Console.WriteLine("Must enter -s or -c");
                }
            }
        }
        #endregion

        #region Settings
        private void getPassword()
        {
            Console.WriteLine("Enter Password:");
            password = Console.ReadLine();
        }

        private void getSettings()
        {
            verbose = false;
            getPassword();
            string s;
            Console.WriteLine();
            Console.WriteLine("Verbose? (y/n):");
            char c = Console.ReadKey().KeyChar;
            if (c == 'y' || c == 'Y') // use default IP and port
            {
                verbose = true;
            }
            Console.WriteLine("\nUse default IP and port of " + DEFAULT_IP + ":" + DEFAULT_PORT + " (y/n):");
            c = Console.ReadKey().KeyChar;
            if (c == 'y' || c == 'Y') // use default IP and port
            {
                this.IP = DEFAULT_IP;
                port = DEFAULT_PORT;
            }
            else
            {
                bool parsed = false;
                var _ip = System.Net.IPAddress.Parse(DEFAULT_IP);
                do
                {
                    Console.WriteLine("Enter IP (XXX.XXX.XXX.XXX)");
                    parsed = System.Net.IPAddress.TryParse(Console.ReadLine().Trim(), out _ip);
                } while (!parsed);
                this.IP = _ip.ToString();
                do
                {
                    Console.WriteLine("Enter Port:");
                    parsed = Int32.TryParse(Console.ReadLine().Trim(), out this.port);
                } while (!parsed);

            }
            do
            {
                Console.WriteLine("\nClient or Server (c/s):");
                s = Console.ReadLine();
                s = s.ToLower();
            } while (s != "c" && s != "s");
            isServer = s == "s";

        }
        #endregion

        private void dropConnection()
        {
            try
            {
                Console.WriteLine("Dropping Connection");
                cryptTCP.dropConnection();
                return;
            }
            catch (Exception) { }
        }

        public void start()
        {
            cryptTCP = new encryptedTCP2(isServer, password, SALT, verbose);
            if (isServer)
                cryptTCP.Listen(port);
            else
                cryptTCP.Connect(System.Net.IPAddress.Parse(IP), port);

            if (cryptTCP.SetupEncryption())
            {
                Console.WriteLine("Connected and Encrypted");

                readThread = new Thread(new ThreadStart(recieve));
                readThread.Start();
                send();
            }
            else
            {
                Console.WriteLine("failed");
            }
            dropConnection();
            Console.ReadKey();
        }

        private void send()
        {
            while (true)
            {
                string toWrite = Console.ReadLine().Trim();
                if (toWrite != "")
                    cryptTCP.Write(toWrite);
            }
        }

        private void recieve()
        {
            try
            {
                while (true)
                {
                    SecureMessage m = cryptTCP.Read();
                    if (m.isSecure)
                    {
                        Console.WriteLine("Recieved Secure Message: " + m.Message);
                    }
                    else
                    {
                        Console.WriteLine("INSECURE MESSAGE. ERROR: " + m.Error);
                    }
                }
            }
            catch (Exception)
            {
                dropConnection();
            }
        }
        
        static void Main(string[] args)
        {
            VPN vpn = new VPN(args);
            vpn.start();
        }

        
    }
}
