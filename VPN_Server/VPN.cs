using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using encryptedTCP;

namespace VPN_Server
{
    class VPN
    {
        private string IP;
        private int port;									//Port to connect to
        private int readTimeout;                            //read timeout for the readStream
        private encryptedTCPListener cryptListener;


        private const int DEFAULT_PORT = 10245;				//Default port to listen on if one isn't declared
        private const string DEFAULT_PASS =
            "b7MDJCUgceqoRIg943Zf/hPel6AGHnFmbNgC8kkcAdq5wVttZyVQj+e29a2FUrZOlECTOANVzN0vEYO6WXgAyA==";	    //subaru
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
                cryptListener = new encryptedTCPListener();
                cryptListener.Listen(port);
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
                cryptListener.dropConnection();
                return;
            }
            catch (Exception) { }
        }

        static void main(string[] args)
        {
        }
    }
}
