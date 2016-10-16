//encryptedTCP
//created by s3r83rus
//last updated 2014-03-25

using System;
//using System.Collections.Generic;
//using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Security.Cryptography;
using sAES;

//may need to make SetupEncryption more reliable rsa key is problem
//could add a 3rd helper class to reduce the amount of repeated code between client and listener.

namespace encryptedTCP
{
    /////////////////////////////////////////////////////////
    //Client
    /////////////////////////////////////////////////////////
    #region Client
    /// <summary>
    /// A class to simply manage an encrypted TCP client.
    /// Call constructor then Connect(IP, port) then SetUpEncryption().
    /// </summary>
    class encryptedTCPClient
    {
        #region Private Variables
        private IPAddress ip_;
        private int port_;
        private TcpClient client;
        private Helper help;
        #endregion

        #region Constructiors
        public encryptedTCPClient()
        {
            help = new Helper();
        }
        public encryptedTCPClient(int RSAKeySize, int AESKeySize)
        {
            help = new Helper(RSAKeySize, AESKeySize);
        }

        /// <summary>
        /// Creates a encryptedTCPlistener with the AES key and IV of another.
        /// Does not require calling SetupEncryption
        /// </summary>
        /// <param name="other">The encryptedTCPListener</param>
        //public encryptedTCPClient(encryptedTCPListener other)
        //{
        //    help = new Helper(other);
        //}
        /// <summary>
        /// Creates a encryptedTCPListener with the AES key and IV of another.
        /// Does not require calling SetupEncryption
        /// </summary>
        /// <param name="other">The encryptedTCPClient</param>
        public encryptedTCPClient(encryptedTCPClient other)
        {
            help = new Helper(other);
        }
        #endregion

        #region Accessors
        /// <summary>
        /// Gets the IPAddress.
        /// </summary>
        public IPAddress IP
        {
            get { return ip_; }
        }
        /// <summary>
        /// Gets the port.
        /// </summary>
        public int Port
        {
            get { return port_; }
        }

        public byte[] AESkey
        {
            get { return help.simpleAES.key; }
        }

        public byte[] AESIV
        {
            get { return help.simpleAES.IV; }
        }
        #endregion

        #region NetworkStreamTimeout
        /// <summary>
        /// Sets the NetworkStream ReadTimeout
        /// </summary>
        /// <param name="timeout">Time in milliseconds.</param>
        public int ReadTimeout
        {
            set { help.networkStream.ReadTimeout = value; }
        }
        /// <summary>
        /// Sets the NetworkStream WriteTimeout.
        /// </summary>
        /// <param name="timeout">Time in milliseconds.</param>
        public int WriteTimeout
        {
            set { help.networkStream.WriteTimeout = value; }
        }
        #endregion

        /// <summary>
        /// Connects to the specified IpAddress and port
        /// and sets up the streams.
        /// </summary>
        /// <param name="ip">The IpAddress of the destination</param>
        /// <param name="port">The port of the destination</param>
        /// <returns>True if the connection was successfull</returns>
        public bool Connect(IPAddress ip, int port)
        {
            try
            {
                ip_ = ip;
                port_ = port;
                client = new TcpClient();
                client.Connect(ip, port);
                help.networkStream = client.GetStream();
                help.streamReader = new StreamReader(help.networkStream);
                help.streamWriter = new StreamWriter(help.networkStream);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
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
                help.exchangeKeys(true);
                //handshake
                if (help.handshake(false))
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
            return help.handshake(sendFirst);
        }


        #region Unencrypted Read/Write

        public string UnencryptedRead()
        {
            return help.UnencryptedRead();
        }
        public void UnencryptedWrite(string str)
        {
            help.UnencryptedWrite(str);
        }
        #endregion

        #region Read/Write
        /// <summary>
        /// Read and decrypts a string from the NetworkStream.
        /// </summary>
        /// <returns>The dycrypted string.</returns>
        public string Read()
        {
            return help.Read();
        }
        /// <summary>
        /// Encrypts and writes a string to the NetworkStream.
        /// </summary>
        /// <param name="str">The string to encrypt and send</param>
        public void Write(string str)
        {
            help.Write(str);
        }
        #endregion

        #region Read/Write Bytes
        public void WriteBytes(byte[] data)
        {
            help.writeBytes(data);
        }
        public byte[] ReadBytes()
        {
            return help.readBytes();
        }
        #endregion

        /// <summary>
        /// Drops the connection and disposes the streams.
        /// </summary>
        public void dropConnection()
        {
            try
            {
                help.DropConnection();
            }
            catch (Exception) { }
            try
            {
                client.Close();
            }
            catch (Exception) { }
        }


        #region Helper Functions
        private static byte[] ToByteArray(Stream stream)
        {
            stream.Position = 0;
            byte[] buffer = new byte[stream.Length];
            for (int totalBytesCopied = 0; totalBytesCopied < stream.Length; )
                totalBytesCopied += stream.Read(buffer, totalBytesCopied, Convert.ToInt32(stream.Length) - totalBytesCopied);
            return buffer;
        }
        #endregion
    }
    #endregion

    /////////////////////////////////////////////////////////
    //Listener Commented out becuase of antivirus
    /////////////////////////////////////////////////////////
    #region Listener
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
        private Helper help;

        #endregion


        #region Constructiors
        public encryptedTCPListener()
        {
            help = new Helper();
        }
        public encryptedTCPListener(int RSAKeySize, int AESKeySize)
        {
            help = new Helper(RSAKeySize, AESKeySize);
        }

        /// <summary>
        /// Creates a encryptedTCPlistener with the AES key and IV of another.
        /// Does not require calling SetupEncryption
        /// </summary>
        /// <param name="other">The encryptedTCPListener</param>
        public encryptedTCPListener(encryptedTCPListener other)
        {
            help = new Helper(other);
        }
        /// <summary>
        /// Creates a encryptedTCPListener with the AES key and IV of another.
        /// Does not require calling SetupEncryption
        /// </summary>
        /// <param name="other">The encryptedTCPClient</param>
        public encryptedTCPListener(encryptedTCPClient other)
        {
            help = new Helper(other);
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
            get { return help.simpleAES.key; }
        }

        public byte[] AESIV
        {
            get { return help.simpleAES.IV; }
        }
        #endregion

        #region NetworkStreamTimeout
        /// <summary>
        /// Sets the NetworkStream ReadTimeout
        /// </summary>
        /// <param name="timeout">Time in milliseconds.</param>
        public int ReadTimeout
        {
            set { help.networkStream.ReadTimeout = value; }
        }
        /// <summary>
        /// Sets the NetworkStream WriteTimeout.
        /// </summary>
        /// <param name="timeout">Time in milliseconds.</param>
        public int WriteTimeout
        {
            set { help.networkStream.WriteTimeout = value; }
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
            help.networkStream = new NetworkStream(sock);
            help.streamReader = new StreamReader(help.networkStream);
            help.streamWriter = new StreamWriter(help.networkStream);
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
                help.exchangeKeys(false);
                //handshake
                if (help.handshake(true))
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
            return help.handshake(sendFirst);
        }

        #region Unencrypted Read/Write

        public string UnencryptedRead()
        {
            return help.UnencryptedRead();
        }
        public void UnencryptedWrite(string str)
        {
            help.UnencryptedWrite(str);
        }
        #endregion

        #region Read/Write
        /// <summary>
        /// Read and decrypts a string from the NetworkStream.
        /// </summary>
        /// <returns>The dycrypted string.</returns>
        public string Read()
        {
            return help.Read();
        }
        /// <summary>
        /// Encrypts and writes a string to the NetworkStream.
        /// </summary>
        /// <param name="str">The string to encrypt and send</param>
        public void Write(string str)
        {
            help.Write(str);
        }
        #endregion

        #region Read/Write Bytes
        public void WriteBytes(byte[] data)
        {
            help.writeBytes(data);
        }
        public byte[] ReadBytes()
        {
            return help.readBytes();
        }
        #endregion


        /// <summary>
        /// Drops the connection and disposes the streams.
        /// </summary>
        public void dropConnection()
        {
            try
            {
                help.DropConnection();
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


    }
    #endregion

    ////////////////////////////////////////////////////////
    //Helper
    ////////////////////////////////////////////////////////
    #region Helper class

    class Helper
    {
        #region Public Variables

        public StreamReader streamReader;
        public StreamWriter streamWriter;
        public Stream networkStream;
        public RSACryptoServiceProvider rsa;
        public SimpleAES simpleAES;
        public int rsaKeySize;
        public int aesKeySize;

        #endregion

        #region Constants
        private const int DEFAULT_RSA_KEY_SIZE = 2048;
        private const int DEFAULT_AES_KEY_SIZE = 128;
        private const string MESSAGE1 = "Confirm yes please how are you hello";//trollolol
        private const string MESSAGE2 = "yes";
        #endregion

        #region Constructors

        public Helper() 
        {
            aesKeySize = DEFAULT_AES_KEY_SIZE;
            rsaKeySize = DEFAULT_RSA_KEY_SIZE;
            rsa = new RSACryptoServiceProvider(rsaKeySize);
            simpleAES = new SimpleAES(aesKeySize);
        }
        public Helper(int RSAKeySize, int AESKeySize)
        {
            rsaKeySize = RSAKeySize;
            aesKeySize = AESKeySize;
            rsa = new RSACryptoServiceProvider(rsaKeySize);
            simpleAES = new SimpleAES(aesKeySize);
        }
        public Helper(encryptedTCPClient other)
        {
            rsaKeySize = -1;
            simpleAES = new SimpleAES(other.AESkey, other.AESIV);
        }
        public Helper(encryptedTCPListener other)
        {
            rsaKeySize = -1;
            simpleAES = new SimpleAES(other.AESkey, other.AESIV);
        }

        #endregion

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
        public void writeBytes(byte[] data)
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
        public byte[] readBytes()
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

        public void exchangeKeys(bool sendRSA)
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

        public void DropConnection()
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
        }

        #region Helper Functions
        private static byte[] ToByteArray(Stream stream)
        {
            stream.Position = 0;
            byte[] buffer = new byte[stream.Length];
            for (int totalBytesCopied = 0; totalBytesCopied < stream.Length; )
                totalBytesCopied += stream.Read(buffer, totalBytesCopied, Convert.ToInt32(stream.Length) - totalBytesCopied);
            return buffer;
        }
        #endregion		

    }

    #endregion
}
