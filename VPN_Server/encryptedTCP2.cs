﻿using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Security.Cryptography;
using sAES;


namespace TCPcrypt
{
    class encryptedTCP2
    {
        #region Variables
        private TcpListener listener;
        private TcpClient client;
        private Socket sock;
        private IPAddress ip_;
        private int port_;
        private StreamReader streamReader;
        private StreamWriter streamWriter;
        private Stream networkStream;
        private SimpleAES sessionAES;
        private SimpleAES passAES;
        private int rsaKeySize;
        private int aesKeySize;
        private string sessionId_;
        private UTF8Encoding encoder = new UTF8Encoding();
        private bool isServer;
        private bool verbose;
        private ulong messageCount = 0;
        private ulong othersMessageCount = 0;
        #endregion

        #region Constants
        private const int DEFAULT_RSA_KEY_SIZE = 2048;//2048;
        private const int DEFAULT_AES_KEY_SIZE = 256;
        private const int DEFAULT_AES_BLOCK_SIZE = 128;
        private const int HASH_ITERATIONS = 1009;
        private const string SERVER = "server";
        private const string CLIENT = "client";
        private const int RANDOM_SIZE_BYTES = 9;
        private const int RANDOM_SIZE_BASE64 = 12;
        private readonly int SESSION_ID_LENGTH = SERVER.Length;
        
        #endregion

        public encryptedTCP2(bool isServer, string password, string salt, bool verbose = false)
        {
            this.verbose = verbose;
            this.isServer = isServer;
            aesKeySize = DEFAULT_AES_KEY_SIZE;
            rsaKeySize = DEFAULT_RSA_KEY_SIZE;
            var key = new Rfc2898DeriveBytes(encoder.GetBytes(password), encoder.GetBytes(salt), HASH_ITERATIONS);
            var AESKey = key.GetBytes(DEFAULT_AES_KEY_SIZE / 8);
            if (verbose)
                Console.WriteLine("Password Generated Key: " + Convert.ToBase64String(AESKey));
            passAES = new SimpleAES(AESKey);
            passAES.verbose = verbose;
        }

        #region Listen/Connect/Drop
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

        /// <summary>
        /// Drops the connection and disposes the streams.
        /// </summary>
        public void dropConnection()
        {
            try
            {
                streamReader.Dispose();
            }
            catch (Exception) { }
            try
            {
                streamWriter.Dispose();
            }
            catch (Exception) { }
            try
            {
                networkStream.Dispose();
            }
            catch (Exception) { }
            try
            {
                sock.Close();
            }
            catch (Exception) { }
            try
            {
                listener.Stop();
            }
            catch (Exception) { }
        }

        #endregion

        #region Read/Write
        /// <summary>
        /// Read and decrypts a string from the NetworkStream.
        /// </summary>
        /// <returns>The dycrypted string.</returns>
        public SecureMessage Read()
        {
            string encrypted = streamReader.ReadLine();
            string unparsed = "";
            try
            {
                unparsed = sessionAES.Decrypt(encrypted);
            } catch (Exception) {
                return new SecureMessage("Decript Exception Thrown.");
            }
            var sm = new SecureMessage(unparsed, othersMessageCount, isServer);
            if (sm.isSecure == true)
            {
                if (verbose && sm.Count - othersMessageCount > 1)
                    Console.WriteLine("Missing " + (sm.Count - othersMessageCount).ToString() + "Messages");
                othersMessageCount = sm.Count;
            }
            return sm;
        }
        /// <summary>
        /// Encrypts and writes a string to the NetworkStream.
        /// </summary>
        /// <param name="str">The string to encrypt and send</param>
        public void Write(string str)
        {
            var m = SecureMessage.FormMessage(++messageCount, str, isServer);
            streamWriter.WriteLine(sessionAES.Encrypt(m));
            streamWriter.Flush();
        }
        #endregion

        #region Encryption Setup
        public bool SetupEncryption()
        {
            try
            {
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
        /// 1) send: "client"||R1
        /// 2) recieve R2 || HE("server" || R1, K_pass)
        ///     2.1 check R1
        ///     2.2 check ID_server for "server" and size
        /// 3) send HE("client" || R2 || RSA_public, k_pass)
        /// 4) recieve HE("server" || E(Key_session || IV_session, RSA_public), k_pass)
        /// 
        /// HE(x||y, k) --> E(H(x||y)||x||y, k)
        /// 
        /// </summary>
        /// <returns>true if key exchange is succssesful</returns>
        public bool exchangeKeys()
        {
            sessionId_ = isServer ? SERVER : CLIENT;
            if (isServer)
            {
                string messageRecieved = streamReader.ReadLine(); //1
                var others_sessionID = messageRecieved.Substring(0, SESSION_ID_LENGTH);
                string random1 = messageRecieved.Substring(SESSION_ID_LENGTH);
                if (random1.Length != RANDOM_SIZE_BASE64)
                    return false;
                if (others_sessionID != CLIENT)
                    return false;

                string random2 = generateRandomString(RANDOM_SIZE_BYTES);
                string messageEncrypted = passAES.Encrypt(HashedMessage.FormMessage(sessionId_ + random1));
                streamWriter.WriteLine(random2 + messageEncrypted); //2
                streamWriter.Flush();

                var hashedMessage = new HashedMessage(passAES.Decrypt(streamReader.ReadLine())); //3
                messageRecieved = hashedMessage.Message;
                if (!hashedMessage.hashMatched)
                    return false;
                if (messageRecieved.Substring(0, SESSION_ID_LENGTH) != others_sessionID)
                    return false;
                string receivedRandom2 = messageRecieved.Substring(SESSION_ID_LENGTH, RANDOM_SIZE_BASE64);
                if (random2 != receivedRandom2)
                    return false;
                string rsaPublic = messageRecieved.Substring(SESSION_ID_LENGTH + RANDOM_SIZE_BASE64);
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(rsaPublic);
                if (verbose)
                    Console.WriteLine("RSA Public Key: " + rsaPublic + "\n");

                sessionAES = new SimpleAES(aesKeySize);
                sessionAES.verbose = verbose;
                string encryptedPart = Convert.ToBase64String(rsa.Encrypt(sessionAES.key, true));
                streamWriter.WriteLine(passAES.Encrypt(HashedMessage.FormMessage(sessionId_ + encryptedPart))); //4
                streamWriter.Flush();

                if (verbose)
                    Console.WriteLine("SessionKey: " + Convert.ToBase64String(sessionAES.key));

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
                var hashedMessage = new HashedMessage(messageRecieved);
                messageRecieved = hashedMessage.Message;
                if (!hashedMessage.hashMatched)
                    return false;
                var others_sessionID = messageRecieved.Substring(0, SESSION_ID_LENGTH);
                if (others_sessionID != SERVER) //2.2
                    return false;
                string recievedRandom1 = messageRecieved.Substring(SESSION_ID_LENGTH);
                if (recievedRandom1 != random1) // 2.1
                    return false;

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(rsaKeySize);
                string publicKey = rsa.ToXmlString(false);
                if (verbose)
                    Console.WriteLine("RSA Public Key: " + publicKey + "\n");
                string message = sessionId_ + random2 + publicKey;
                streamWriter.WriteLine(passAES.Encrypt(HashedMessage.FormMessage(message))); // 3
                streamWriter.Flush();

                hashedMessage = new HashedMessage(passAES.Decrypt(streamReader.ReadLine()));//4
                messageRecieved = hashedMessage.Message; //4
                if (messageRecieved.Substring(0, SESSION_ID_LENGTH) != others_sessionID)
                    return false;
                string restOfMessage = messageRecieved.Substring(SESSION_ID_LENGTH);
                byte[] sessionKey = rsa.Decrypt(Convert.FromBase64String(restOfMessage), true);
                sessionAES = new SimpleAES(sessionKey);
                sessionAES.verbose = verbose;

                if(verbose)
                    Console.WriteLine("SessionKey: " + Convert.ToBase64String(sessionAES.key));
            }
            return true;
        }


        /// <summary>
        /// send random number R1 recieve R1||R2 send R2
        /// </summary>
        /// <param name="sendFirst">Bool to determin if you will send first or recieve first</param>
        /// <returns></returns>
        public bool handshake(bool sendFirst)
        {
            try
            {
                string random1;
                string random2;
                SecureMessage messageRecieved;
                if (sendFirst)
                {
                    random1 = generateRandomString(RANDOM_SIZE_BYTES);
                    Write(random1);
                    messageRecieved = Read();
                    if (messageRecieved.isSecure == true && messageRecieved.Message.Substring(0,RANDOM_SIZE_BASE64) == random1)
                    {
                        random2 = messageRecieved.Message.Substring(RANDOM_SIZE_BASE64);
                        Write(random2);
                        return true;
                    }
                }
                else // recieve random number R1 send R1||R2 recieve R2
                {
                    messageRecieved = Read();
                    random1 = messageRecieved.Message;
                    if (messageRecieved.isSecure && random1.Length == RANDOM_SIZE_BASE64)
                    {
                        random2 = generateRandomString(RANDOM_SIZE_BYTES);
                        Write(random1 + random2); //send R1||R2
                        messageRecieved = Read(); //recieve R2
                        if (messageRecieved.isSecure && messageRecieved.Message == random2)
                        {
                            return true;
                        }
                    }
                }
                if (verbose)
                    Console.WriteLine("Handshake Failed: " + messageRecieved.Error);

                return false;
            }
            catch (Exception e)
            { Console.WriteLine(e); return false; }
        }
        #endregion

        #region Helpers
        private static string generateRandomString(int size_bytes)
        {
            var random = new RNGCryptoServiceProvider();
            byte[] buf = new byte[size_bytes];
            random.GetBytes(buf);
            return Convert.ToBase64String(buf);
        }
        #endregion
    }

}
