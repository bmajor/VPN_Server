using System;
//using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Security.Cryptography;
using sAES;


namespace VPN_Server
{
    class encryptedTCP2
    {
        private TcpListener listener;
        private TcpClient client;
        private Socket sock;
        private IPAddress ip_;
        private int port_;
        private StreamReader streamReader;
        private StreamWriter streamWriter;
        private Stream networkStream;
        private RSACryptoServiceProvider rsa;
        private SimpleAES sessionAES;
        private SimpleAES passAES;
        private int rsaKeySize;
        private int aesKeySize;
        private string sessionId_;
        private UTF8Encoding encoder = new UTF8Encoding();
        private bool isServer;

        


        #region Constants
        private const int DEFAULT_RSA_KEY_SIZE = 2048;
        private const int DEFAULT_AES_KEY_SIZE = 256;
        private const int DEFAULT_AES_BLOCK_SIZE = 128;
        private const int HASH_ITERATIONS = 1009;
        private const string SALT = "~ÆL433G.";

        //remove these
        private const string MESSAGE1 = "Confirm yes please how are you hello";//trollolol
        private const string MESSAGE2 = "yes";
        #endregion

        public encryptedTCP2(bool isServer, string password)
        {
            this.isServer = isServer;
            aesKeySize = DEFAULT_AES_KEY_SIZE;
            rsaKeySize = DEFAULT_RSA_KEY_SIZE;
            var key = new Rfc2898DeriveBytes(encoder.GetBytes(password), encoder.GetBytes(SALT), HASH_ITERATIONS);
            var AESKey = key.GetBytes(DEFAULT_AES_KEY_SIZE / 8);
            var AESIV = key.GetBytes(DEFAULT_AES_BLOCK_SIZE / 8);
        }

        public void Listen(int port)
        {
            port_ = port;
            listener = new TcpListener(port);
            listener.Start();
            sock = listener.AcceptSocket();
            networkStream = new NetworkStream(sock);
            streamReader = new StreamReader(networkStream);
            streamWriter = new StreamWriter(networkStream);
        }

        public bool Connect(IPAddress ip, int port)
        {
            try
            {
                ip_ = ip;
                port_ = port;
                client = new TcpClient();
                client.Connect(ip, port);
                networkStream = client.GetStream();
                streamReader = new StreamReader(networkStream);
                streamWriter = new StreamWriter(networkStream);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        #region Read/Write
        /// <summary>
        /// Read and decrypts a string from the NetworkStream.
        /// </summary>
        /// <returns>The dycrypted string.</returns>
        public string Read()
        {
            return sessionAES.Decrypt(streamReader.ReadLine());
        }
        /// <summary>
        /// Encrypts and writes a string to the NetworkStream.
        /// </summary>
        /// <param name="str">The string to encrypt and send</param>
        public void Write(string str)
        {
            streamWriter.WriteLine(sessionAES.Encrypt(str));
            streamWriter.Flush();
        }
        #endregion



        public bool SetupEncryption()
        {
            try
            {
                exchangeKeys(true);
                //handshake
                if (handshake(false))
                {
                    return true;
                }
                return false;
            }
            catch (Exception)
            {
                return false;
            }
        }
        public void exchangeKeys(bool sendRSA)
        {
            if (sendRSA)
            {
                streamWriter.WriteLine(rsa.ToXmlString(false)); //<--1
                streamWriter.Flush();
                byte[] key = rsa.Decrypt(Convert.FromBase64String(streamReader.ReadLine()), true);//<--2
                byte[] IV = rsa.Decrypt(Convert.FromBase64String(streamReader.ReadLine()), true);//<--3
                sessionAES = new SimpleAES(key, IV);

            }
            else
            {
                rsa.FromXmlString(streamReader.ReadLine());//<--1
                streamWriter.WriteLine(Convert.ToBase64String(rsa.Encrypt(sessionAES.key, true)));//<--2
                streamWriter.Flush();
                streamWriter.WriteLine(Convert.ToBase64String(rsa.Encrypt(sessionAES.IV, true)));//<--3
                streamWriter.Flush();
            }
        }

        public bool handshake(bool sendFirst)
        {
            try
            {
                if (sendFirst)
                {
                    Write(MESSAGE1);
                    if (Read() == MESSAGE2)
                    {
                        return true;
                    }
                    else
                        return false;
                }
                else
                {
                    if (Read() == MESSAGE1)
                    {
                        Write(MESSAGE2);
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
            }
            catch (Exception) { return false; }
        }

    }
}
