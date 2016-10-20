using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VPN_Server
{
    class VPN
    {
        private string IP;
        private int port;									//Port to connect to
        private int readTimeout;                            //read timeout for the readStream


        private const int DEFAULT_PORT = 10245;				//Default port to listen on if one isn't declared
        private const string DEFAULT_IP = "127.0.0.1";
        private const int PASSWORD_TIMEOUT = 22000;         //22 second
        private const int NORMAL_TIMEOUT = 1200000;         //20 minutes
        private const int RECONNECT_TIME = 7000;            //7 seconds
        private const string SALT = "~Æ";                  //string to salt the sha hashes with
        private const int RSA_KEY_SIZE = 2048;

        public void startServer()
        {
            try
            {
                Console.WriteLine("Listening on port " + port);
            }
            catch (Exception)
            {
                //Console.WriteLine(ex);
                dropConnection();
            }
        }

        private void dropConnection()
        {
            try
            {
                Console.WriteLine("Dropping Connection");
                Console.ResetColor();
                //cryptListener.dropConnection();
                return;
            }
            catch (Exception) { }
        }

        private void start()
        {
            Console.WriteLine("Enter Password:");
            string password = Console.ReadLine();

            string s;
            Console.WriteLine("Use default IP and port of " + DEFAULT_IP + ":" + DEFAULT_PORT + " (y/n):");
            char c = Console.ReadKey().KeyChar;
            if (c == 'y' || c == 'Y') // use default IP and port
            {
                this.IP = DEFAULT_IP;
                port = DEFAULT_PORT;
            }
            else
            {
                Console.WriteLine("Enter IP (XXX.XXX.XXX.XXX)");

            }
            do
            {
                Console.WriteLine("Client or Server (c/s):");
                s = Console.ReadLine();
                s = s.ToLower();
            } while (s != "c" && s != "s");
            encryptedTCP2 crypt = new encryptedTCP2(s == "s", password);
            if (s == "s")
                crypt.Listen(port);
            else
                crypt.Connect(System.Net.IPAddress.Parse(IP), port);
            if (crypt.SetupEncryption())
            {
                Console.WriteLine("Connected and Encrypted");
            }
            Console.WriteLine("failed");
            Console.ReadLine();
        }

        public void testing()
        {
            string password = "hello";
            encryptedTCP2 client = new encryptedTCP2(false, password);
            encryptedTCP2 server = new encryptedTCP2(true, password);
            server.Listen(DEFAULT_PORT);
        }

        static void Main(string[] args)
        {
            VPN vpn = new VPN();
            vpn.start();
        }

        
    }
}
