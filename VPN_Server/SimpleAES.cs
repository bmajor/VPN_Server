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
        private ICryptoTransform encryptor, decryptor;
        private UTF8Encoding encoder;
        public byte[] key;
        public byte[] IV;

        public SimpleAES()
        {
            RijndaelManaged rm = new RijndaelManaged(); // default to mode CBC
            rm.GenerateKey();
            rm.GenerateIV();
            key = rm.Key;
            IV = rm.IV;
            encryptor = rm.CreateEncryptor(key, IV);
            decryptor = rm.CreateDecryptor(key, IV);
            encoder = new UTF8Encoding();
        }
        public SimpleAES(int keySize)
        {
            RijndaelManaged rm = new RijndaelManaged();
            rm.KeySize = keySize;
            rm.GenerateKey();
            rm.GenerateIV();
            key = rm.Key;
            IV = rm.IV;
            encryptor = rm.CreateEncryptor(key, IV);
            decryptor = rm.CreateDecryptor(key, IV);
            encoder = new UTF8Encoding();
        }
        public SimpleAES(byte[] key1, byte[] IV1)
        {
            RijndaelManaged rm = new RijndaelManaged();
            key = key1;
            IV = IV1;
            encryptor = rm.CreateEncryptor(key1, IV1);
            decryptor = rm.CreateDecryptor(key1, IV1);
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
            return Transform(buf, encryptor);
        }

        public byte[] Decrypt(byte[] buf)
        {
            return Transform(buf, decryptor);
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
