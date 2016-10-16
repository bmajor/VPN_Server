//encryptedTCPL
//created by s3r83rus
//last updated 2015-04-17


using System;
//using System.Collections.Generic;
//using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Security.Cryptography;
using sAES;

namespace encryptedTCPL
{
    /// <summary>
    /// A class to simply manage an encrypted TCP listener.
    /// Call constructor then Listen(port) then SetUpEncryption().
    /// </summary>
    class encryptedTCPListener
    {
        #region Private Variables

        private TcpListener listener;
        private Socket sock;
        private int port_;
        private StreamReader streamReader;
        private StreamWriter streamWriter;
        private Stream networkStream;
        private RSACryptoServiceProvider rsa;
        private SimpleAES simpleAES;
        private int rsaKeySize;
        private int aesKeySize;

        #endregion

        #region Constants
        private const int DEFAULT_RSA_KEY_SIZE = 2048;
        private const int DEFAULT_AES_KEY_SIZE = 128;
        private const string MESSAGE1 = "Confirm yes please how are you hello";//trollolol
        private const string MESSAGE2 = "yes";
        #endregion

        #region Constructiors
        public encryptedTCPListener()
        {
            aesKeySize = DEFAULT_AES_KEY_SIZE;
            rsaKeySize = DEFAULT_RSA_KEY_SIZE;
            rsa = new RSACryptoServiceProvider(rsaKeySize);
            simpleAES = new SimpleAES(aesKeySize);
        }
        public encryptedTCPListener(int RSAKeySize, int AESKeySize)
        {
            rsaKeySize = RSAKeySize;
            aesKeySize = AESKeySize;
            rsa = new RSACryptoServiceProvider(rsaKeySize);
            simpleAES = new SimpleAES(aesKeySize);
        }

        /// <summary>
        /// Creates a encryptedTCPlistener with the AES key and IV of another.
        /// Does not require calling SetupEncryption
        /// </summary>
        /// <param name="other">The encryptedTCPListener</param>
        public encryptedTCPListener(encryptedTCPListener other)
        {
            rsaKeySize = -1;
            simpleAES = new SimpleAES(other.AESkey, other.AESIV);
        }
        #endregion

        #region Accessors
        /// <summary>
        /// Gets the port.
        /// </summary>
        public int Port
        {
            get { return port_; }
        }

        public EndPoint RemoteEndPoint
        {
            get { return sock.RemoteEndPoint; }
        }

        public byte[] AESkey
        {
            get { return simpleAES.key; }
        }

        public byte[] AESIV
        {
            get { return simpleAES.IV; }
        }
        #endregion

        #region NetworkStreamTimeout
        /// <summary>
        /// Sets the NetworkStream ReadTimeout
        /// </summary>
        /// <param name="timeout">Time in milliseconds.</param>
        public int ReadTimeout
        {
            set { networkStream.ReadTimeout = value; }
        }
        /// <summary>
        /// Sets the NetworkStream WriteTimeout.
        /// </summary>
        /// <param name="timeout">Time in milliseconds.</param>
        public int WriteTimeout
        {
            set { networkStream.WriteTimeout = value; }
        }
        #endregion


        /// <summary>
        /// Listens for the client to make connection at the specified port
        /// and sets up streams.
        /// </summary>
        /// <param name="port">The port to listen on.</param>
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

        /// <summary>
        /// Sets up the encryption by transfering the AES key and IV by RSA
        /// and preforms a simple handshake to confirm encryption.
        /// </summary>
        /// <returns>True if the encryption and handshake was successfull.</returns>
        public bool SetupEncryption()
        {
            try
            {
                exchangeKeys(false);
                //handshake
                if (handshake(true))
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

        /// <summary>
        /// Preforms a simple handshake to confirm encryption.
        /// </summary>
        /// <param name="sendFirst">True to send then receive. False to receive then send.</param>
        /// <returns>True if the handshake was successfull</returns>
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


        #region Unencrypted Read/Write
        public string UnencryptedRead()
        {
            return streamReader.ReadLine();
        }
        public void UnencryptedWrite(string str)
        {
            streamWriter.WriteLine(str);
            streamWriter.Flush();
        }
        #endregion

        #region Read/Write
        /// <summary>
        /// Read and decrypts a string from the NetworkStream.
        /// </summary>
        /// <returns>The dycrypted string.</returns>
        public string Read()
        {
            return simpleAES.Decrypt(streamReader.ReadLine());
        }
        /// <summary>
        /// Encrypts and writes a string to the NetworkStream.
        /// </summary>
        /// <param name="str">The string to encrypt and send</param>
        public void Write(string str)
        {
            streamWriter.WriteLine(simpleAES.Encrypt(str));
            streamWriter.Flush();
        }
        #endregion

        #region Read/Write Bytes
        public void WriteBytes(byte[] data)
        {
            byte[] cryptData = simpleAES.Encrypt(data);
            int size = cryptData.Length;
            Write(size.ToString());
            if (Read() == "ok")
            {
                networkStream.Write(cryptData, 0, cryptData.GetLength(0));
                networkStream.Flush();
            }
        }
        public byte[] ReadBytes()
        {
            int size = int.Parse(Read());
            Write("ok");
            int thisRead = 0;
            int blockSize = 1024;
            byte[] dataByte = new byte[blockSize];
            var ms = new MemoryStream();
            long count = 0;
            while (count < size)
            {
                thisRead = networkStream.Read(dataByte, 0, blockSize);
                ms.Write(dataByte, 0, thisRead);
                if (thisRead == 0) break;
                count += thisRead;
            }
            return simpleAES.Decrypt(ToByteArray(ms));
        }
        #endregion

        #region Helpers
        private void exchangeKeys(bool sendRSA)
        {
            if (sendRSA)
            {
                streamWriter.WriteLine(rsa.ToXmlString(false)); //<--1
                streamWriter.Flush();
                byte[] key = rsa.Decrypt(Convert.FromBase64String(streamReader.ReadLine()), true);//<--2
                byte[] IV = rsa.Decrypt(Convert.FromBase64String(streamReader.ReadLine()), true);//<--3
                simpleAES = new SimpleAES(key, IV);

            }
            else
            {
                rsa.FromXmlString(streamReader.ReadLine());//<--1
                streamWriter.WriteLine(Convert.ToBase64String(rsa.Encrypt(simpleAES.key, true)));//<--2
                streamWriter.Flush();
                streamWriter.WriteLine(Convert.ToBase64String(rsa.Encrypt(simpleAES.IV, true)));//<--3
                streamWriter.Flush();
            }
        }

        private static byte[] ToByteArray(Stream stream)
        {
            stream.Position = 0;
            byte[] buffer = new byte[stream.Length];
            for (int totalBytesCopied = 0; totalBytesCopied < stream.Length; )
                totalBytesCopied += stream.Read(buffer, totalBytesCopied, Convert.ToInt32(stream.Length) - totalBytesCopied);
            return buffer;
        }
        #endregion
        
        // new stuff
        
    }
}
