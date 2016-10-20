using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using MyFuctions;

namespace sAES 
{
    public class SimpleAES
    {
        private UTF8Encoding encoder;
        RijndaelManaged rm;
        public bool verbose = true;
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

        public string Encrypt(string unencrypted)
        {
            return Convert.ToBase64String(Encrypt(encoder.GetBytes(unencrypted)));
        }

        public string Decrypt(string encrypted)
        {
            return encoder.GetString(Decrypt(Convert.FromBase64String(encrypted)));
        }

        public byte[] Encrypt(byte[] buf)
        {
            rm.GenerateIV();
            if (verbose)
                Console.WriteLine("Encrypt: IV=" + Convert.ToBase64String(IV));
            var encryptor = rm.CreateEncryptor();
            var encrypted = Transform(buf, encryptor);
            return Help.combine(IV, encrypted);
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

        protected byte[] Transform(byte[] buffer, ICryptoTransform transform)
        {
            MemoryStream ms = new MemoryStream();
            using (CryptoStream cs = new CryptoStream(ms, transform, CryptoStreamMode.Write))
            {
                cs.Write(buffer, 0, buffer.Length);
            }
            return ms.ToArray();
        }

    }
}
