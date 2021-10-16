using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Business
{
    public class Aes_Algorithm
    {
        AesCryptoServiceProvider cryptoServiceProvider;
        public int BlockSize { get; set; }
        public int KeySize { get; set; }
        public byte[] IV { get; set; }
        public byte[] Key{ get; set; }
        public CipherMode Mode{ get; set; }
        public PaddingMode Padding { get; set; }

        public void FillArguments()
        {
            cryptoServiceProvider = new AesCryptoServiceProvider();

            //cryptoServiceProvider.BlockSize = BlockSize;
            cryptoServiceProvider.KeySize = KeySize;
            cryptoServiceProvider.IV = IV;
            cryptoServiceProvider.Key = Key;
            cryptoServiceProvider.Mode = Mode;
            cryptoServiceProvider.Padding = Padding;
        }

        public String Encrypt(String clearText)
        {
            ICryptoTransform cryptoTransform = cryptoServiceProvider.CreateEncryptor();

            byte[] encryptedBytes = cryptoTransform.TransformFinalBlock(ASCIIEncoding.ASCII.GetBytes(clearText), 0, clearText.Length);
            string result = Convert.ToBase64String(encryptedBytes);

            return result;
        }

        public String Decrypt(String cipherText)
        {
            ICryptoTransform cryptoTransform = cryptoServiceProvider.CreateDecryptor();

            byte[] encryptedBytes = Convert.FromBase64String(cipherText);
            byte[] decryptedBytes = cryptoTransform.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

            string result = ASCIIEncoding.ASCII.GetString(decryptedBytes);

            return result;
        }
    }
}
