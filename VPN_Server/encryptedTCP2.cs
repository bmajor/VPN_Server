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
        //private RSACryptoServiceProvider rsa;
        private SimpleAES sessionAES;
        private SimpleAES passAES;
        private int rsaKeySize;
        private int aesKeySize;
        private string sessionId_;
        private string others_sessionID;
        private UTF8Encoding encoder = new UTF8Encoding();
        private bool isServer;
        private SHA1CryptoServiceProvider hashProvider = new SHA1CryptoServiceProvider();



        #region Constants
        private const int DEFAULT_RSA_KEY_SIZE = 1024;//2048;
        private const int DEFAULT_AES_KEY_SIZE = 128;
        private const int DEFAULT_AES_BLOCK_SIZE = 128;
        private const int HASH_ITERATIONS = 1009;
        private const string SALT = "~ÆL433G."; // move to main program
        private const string SERVER = "server";
        private const string CLIENT = "client";
        private const int RANDOM_SIZE_BYTES = 9;
        private const int RANDOM_SIZE_BASE64 = 12;
        private readonly int SESSION_ID_LENGTH = SERVER.Length + RANDOM_SIZE_BASE64;
        
        #endregion

        public encryptedTCP2(bool isServer, string password)
        {
            this.isServer = isServer;
            aesKeySize = DEFAULT_AES_KEY_SIZE;
            rsaKeySize = DEFAULT_RSA_KEY_SIZE;
            var key = new Rfc2898DeriveBytes(encoder.GetBytes(password), encoder.GetBytes(SALT), HASH_ITERATIONS);
            var AESKey = key.GetBytes(DEFAULT_AES_KEY_SIZE / 8);
            var AESIV = key.GetBytes(DEFAULT_AES_BLOCK_SIZE / 8);
            passAES = new SimpleAES(AESKey, AESIV);
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
                sessionId_ = generateSessionId();
                if (exchangeKeys())
                {
                    //handshake
                    if (handshake(isServer))
                    {
                        return true;
                    }
                }
                return false;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Client: 
        /// 1) send: ID_client||R1
        /// 2) recieve R2 || E(ID_server || R1, K_pass)
        ///     2.1 check R1
        ///     2.2 check ID_server for "server" and size
        /// 3) send E(ID_client || R2 || RSA_public, k_pass)
        /// 4) recieve E(ID_server || E(Key_session || IV_session, RSA_public), k_pass)
        /// </summary>
        public bool exchangeKeys()
        {
            if (isServer)
            {
                string messageRecieved = streamReader.ReadLine(); //1
                others_sessionID = messageRecieved.Substring(0, SESSION_ID_LENGTH);
                string random1 = messageRecieved.Substring(SESSION_ID_LENGTH);
                if (random1.Length != RANDOM_SIZE_BASE64)
                    return false;
                if (others_sessionID.Substring(0, CLIENT.Length) != CLIENT)
                    return false;

                string random2 = generateRandomString(RANDOM_SIZE_BYTES);
                string messageEncrypted = passAES.Encrypt(sessionId_ + random1);
                streamWriter.WriteLine(random2 + messageEncrypted); //2
                streamWriter.Flush();

                messageRecieved = passAES.Decrypt(streamReader.ReadLine()); //3
                if (messageRecieved.Substring(0, SESSION_ID_LENGTH) != others_sessionID)
                    return false;
                string receivedRandom2 = messageRecieved.Substring(SESSION_ID_LENGTH, RANDOM_SIZE_BASE64);
                if (random2 != receivedRandom2)
                    return false;
                string rsaPublic = messageRecieved.Substring(SESSION_ID_LENGTH + RANDOM_SIZE_BASE64);
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(rsaPublic);

                sessionAES = new SimpleAES(aesKeySize);
                byte[] toEncrypt = new byte [sessionAES.key.Length + sessionAES.IV.Length];
                Buffer.BlockCopy(sessionAES.key, 0, toEncrypt, 0, sessionAES.key.Length);
                Buffer.BlockCopy(sessionAES.IV, 0, toEncrypt, sessionAES.key.Length, sessionAES.IV.Length);
                string encryptedPart = Convert.ToBase64String(rsa.Encrypt(toEncrypt, true));
                streamWriter.WriteLine(passAES.Encrypt(sessionId_ + encryptedPart)); //4
                streamWriter.Flush();

                Console.WriteLine(Convert.ToBase64String(sessionAES.key));
                Console.WriteLine(Convert.ToBase64String(sessionAES.IV));

                //streamWriter.WriteLine(rsa.ToXmlString(false)); //<--1
                //streamWriter.Flush();
                //byte[] key = rsa.Decrypt(Convert.FromBase64String(streamReader.ReadLine()), true);//<--2
                //byte[] IV = rsa.Decrypt(Convert.FromBase64String(streamReader.ReadLine()), true);//<--3
                //sessionAES = new SimpleAES(key, IV);

            }
            else ///client
            {
                string random1 = generateRandomString(RANDOM_SIZE_BYTES);
                streamWriter.WriteLine(sessionId_ + random1);  // 1
                streamWriter.Flush();

                string messageRecieved = streamReader.ReadLine(); //2
                string random2 = messageRecieved.Substring(0, RANDOM_SIZE_BASE64);
                string messageEncrypted = messageRecieved.Substring(RANDOM_SIZE_BASE64);
                messageRecieved = passAES.Decrypt(messageEncrypted); // ID_server || R1
                others_sessionID = messageRecieved.Substring(0, SESSION_ID_LENGTH);
                if (others_sessionID.Substring(0, SERVER.Length) != SERVER) //2.2
                    return false;
                string recievedRandom1 = messageRecieved.Substring(SESSION_ID_LENGTH);
                if (recievedRandom1 != random1) // 2.1
                    return false;

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(rsaKeySize);
                string publicKey = rsa.ToXmlString(false);
                string message = sessionId_ + random2 + publicKey;
                streamWriter.WriteLine(passAES.Encrypt(message)); // 3
                streamWriter.Flush();

                messageRecieved = passAES.Decrypt(streamReader.ReadLine()); //4
                if (messageRecieved.Substring(0, SESSION_ID_LENGTH) != others_sessionID)
                    return false;
                string restOfMessage = messageRecieved.Substring(SESSION_ID_LENGTH);
                byte[] AES_info = rsa.Decrypt(Convert.FromBase64String(restOfMessage), true);
                byte[] sessionKey = new byte[aesKeySize/8];
                byte[] sessionIV = new byte[DEFAULT_AES_BLOCK_SIZE / 8];
                Buffer.BlockCopy(AES_info, 0, sessionKey, 0, sessionKey.Length);
                Buffer.BlockCopy(AES_info, sessionKey.Length, sessionIV, 0, sessionIV.Length);
                sessionAES = new SimpleAES(sessionKey, sessionIV);

                Console.WriteLine(Convert.ToBase64String(sessionAES.key));
                Console.WriteLine(Convert.ToBase64String(sessionAES.IV));
            }
            return true;
        }


        /// <summary>
        /// send random number R1 recieve R1||R2 send R2
        /// </summary>
        /// <param name="sendFirst"></param>
        /// <returns></returns>
        public bool handshake(bool sendFirst)
        {
            try
            {
                string random1;
                string random2;
                string messageRecieved;
                if (sendFirst)
                {
                    random1 = generateRandomString(RANDOM_SIZE_BYTES);
                    Write(random1);
                    messageRecieved = Read();
                    if (messageRecieved.Substring(0,RANDOM_SIZE_BASE64) == random1)
                    {
                        random2 = messageRecieved.Substring(RANDOM_SIZE_BASE64);
                        Write(random2);
                        return true;
                    }
                    return false;
                }
                else // recieve random number R1 send R1||R2 recieve R2
                {
                    random1 = Read(); //recieve R1 //causes exception
                    if (random1.Length == RANDOM_SIZE_BASE64)
                    {
                        random2 = generateRandomString(RANDOM_SIZE_BYTES);
                        Write(random1 + random2); //send R1||R2
                        messageRecieved = Read(); //recieve R2
                        if (messageRecieved == random2)
                        {
                            return true;
                        }
                    }
                    return false;
                }
            }
            catch (Exception e)
            { Console.WriteLine(e); return false; }
        }

        private static string generateRandomString(int size_bytes)
        {
            var random = new RNGCryptoServiceProvider();
            byte[] buf = new byte[size_bytes];
            random.GetBytes(buf);
            return Convert.ToBase64String(buf);
        }
        private string generateSessionId()
        {
            string random = generateRandomString(RANDOM_SIZE_BYTES);
            return isServer ? SERVER + random : CLIENT + random;
        }

        private byte[] HashMessage(string Message)
        {
            return hashProvider.ComputeHash(encoder.GetBytes(Message));
        }

    }
}
