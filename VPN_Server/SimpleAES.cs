using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace sAES 
{
    public class SimpleAES
    {
        #region Variables
        private UTF8Encoding encoder;
        RijndaelManaged rm;
        public bool verbose = false;

        public byte[] key
        {
            get { return rm.Key; }
        }
        public byte[] IV
        {
            get { return rm.IV; }
            set { rm.IV = value; }
        }
        public int BlockSizeBytes
        {
            get { return rm.BlockSize / 8; }
        }
        #endregion

        #region Constructors
        public SimpleAES()
        {
            rm = new RijndaelManaged(); // default to mode CBC
            rm.Mode = CipherMode.CBC;
            rm.GenerateKey();
            encoder = new UTF8Encoding();
        }
        public SimpleAES(int keySize)
        {
            rm = new RijndaelManaged();
            rm.Mode = CipherMode.CBC;
            rm.KeySize = keySize;
            rm.GenerateKey();
            encoder = new UTF8Encoding();
        }
        public SimpleAES(byte[] key1)
        {
            rm = new RijndaelManaged();
            rm.Mode = CipherMode.CBC;
            rm.Key = key1;
            encoder = new UTF8Encoding();
        }
        #endregion

        #region String Encrypt/Decrypt
        public string Encrypt(string unencrypted)
        {
            return Convert.ToBase64String(Encrypt(encoder.GetBytes(unencrypted)));
        }

        public string Decrypt(string encrypted)
        {
            return encoder.GetString(Decrypt(Convert.FromBase64String(encrypted)));
        }
        #endregion

        #region Byte[] Encrypte/Decrypt
        public byte[] Encrypt(byte[] buf)
        {
            rm.GenerateIV();
            if (verbose)
                Console.WriteLine("Encrypt: IV=" + Convert.ToBase64String(IV));
            var encryptor = rm.CreateEncryptor();
            var encrypted = Transform(buf, encryptor);
            return combine(IV, encrypted);
        }

        public byte[] Decrypt(byte[] buf)
        {
            byte[] temp = new byte[BlockSizeBytes];
            Buffer.BlockCopy(buf, 0, temp, 0, BlockSizeBytes); //read in IV
            IV = temp;
            if (verbose)
            {
                Console.WriteLine("Decrypt: IV=" + Convert.ToBase64String(IV));
            }
            var message = new byte[buf.Length - BlockSizeBytes];
            Buffer.BlockCopy(buf, IV.Length, message, 0, message.Length);
            var decryptor = rm.CreateDecryptor();
            return Transform(message, decryptor);
        }
        #endregion

        #region Help
        protected byte[] Transform(byte[] buffer, ICryptoTransform transform)
        {
            MemoryStream ms = new MemoryStream();
            using (CryptoStream cs = new CryptoStream(ms, transform, CryptoStreamMode.Write))
            {
                cs.Write(buffer, 0, buffer.Length);
            }
            return ms.ToArray();
        }
        
        private static byte[] combine(byte[] buf1, byte[] buf2)
        {
            byte[] combined = new byte[buf1.Length + buf2.Length];
            Buffer.BlockCopy(buf1, 0, combined, 0, buf1.Length);
            Buffer.BlockCopy(buf2, 0, combined, buf1.Length, buf2.Length);
            return combined;
        }
        #endregion 
    }
}
