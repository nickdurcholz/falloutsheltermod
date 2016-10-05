using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using MiniJSON;

namespace foo
{
    internal class Program
    {
        private static byte[] m_cachedVectorBytes;
        private static readonly Dictionary<string, byte[]> m_cachedPassphraseBytes = new Dictionary<string, byte[]>();
        private static string _passPhrase;

        private static void Main(string[] args)
        {
            // location => /sdcard/Android/data/com.bethsoft.falloutshelter/files/Vault1.sav
            // adb push C:\Users\nick.durcholz\Desktop\Vault1_hacked.sav /sdcard/Android/data/com.bethsoft.falloutshelter/files/Vault1.sav
            _passPhrase = StringCipher.GeneratePassPhrase("PlayerData");
            //var fileName = @"C:\Users\nick.durcholz\Desktop\Vault1.sav";
            //var saveData = GetHackedVaultData(fileName);
            SaveJsonVaultData(
                File.ReadAllText(@"S:\foo\foo\vault1.json"),
                @"C:\Users\nick.durcholz\Desktop\Vault1_hacked.sav");
        }

        private static void SaveJsonVaultData(string json, string outLocation)
        {
            var dictionary = PersistenceManager.DeserializeData(json);
            var serialized = SerializeData(dictionary);
            var encrypted = Encrypt(serialized, serialized.Length);
            File.WriteAllBytes(outLocation, encrypted);
        }

        private static VaultData GetHackedVaultData(string fileName)
        {
            var json = File.ReadAllText(@"S:\foo\foo\vault1.json");
            return VaultDataFromJsonString(json, fileName);
        }

        public static VaultData GetVaultDataFromBytes(byte[] textBytes, string fileName)
        {
            if (textBytes.Length == 0)
                return null;

            string data1 = new UTF8Encoding().GetString(textBytes);
            string data2 = Decrypt(data1);
            if (data2 == null)
                return null;
            return VaultDataFromJsonString(fileName, data2);
        }

        public static byte[] Encrypt(byte[] data, int inputDataLenght)
        {
            UTF8Encoding utF8Encoding = new UTF8Encoding();
            string str = StringCipher.Encrypt(data, inputDataLenght, _passPhrase);
            return utF8Encoding.GetBytes(str);
        }

        public static byte[] SerializeData(Dictionary<string, object> data)
        {
            if (data == null)
                return null;
            UTF8Encoding utF8Encoding = new UTF8Encoding();
            string str = SerializeDictionary(data);
            return utF8Encoding.GetBytes(str);
        }

        public static string SerializeDictionary(Dictionary<string, object> dict)
        {
            return Json.Serialize(dict);
        }

        private static VaultData VaultDataFromJsonString(string fileName, string data2)
        {
            Dictionary<string, object> dictionary = PersistenceManager.DeserializeData(data2);
            if ((dictionary == null) || (dictionary.Count == 0))
                return null;
            VaultData vaultData = new VaultData(string.Empty, EVaultMode.Normal);
            vaultData.Data = dictionary;
            vaultData.FileName = fileName;
            if (vaultData.Data.ContainsKey("timeMgr"))
            {
                long ticks = SerializeHelper.TryGetValue(
                    vaultData.Data["timeMgr"] as Dictionary<string, object>,
                    "timeSaveDate",
                    DateTime.Now.Ticks);
                vaultData.ModifiedDate = new DateTime(ticks);
            }
            return vaultData;
        }

        public static string Decrypt(string data)
        {
            return Decrypt(data, _passPhrase);
        }

        public static string Decrypt(string cipherText, string passPhrase)
        {
            byte[] vectorBytes = GetVectorBytes();
            byte[] buffer = Convert.FromBase64String(cipherText);
            byte[] passphraseBytes = GetPassphraseBytes(passPhrase, vectorBytes);
            RijndaelManaged rijndaelManaged = new RijndaelManaged();
            rijndaelManaged.Mode = CipherMode.CBC;
            ICryptoTransform decryptor = rijndaelManaged.CreateDecryptor(passphraseBytes, vectorBytes);
            MemoryStream memoryStream = new MemoryStream(buffer);
            CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            byte[] numArray = new byte[buffer.Length];
            int count = cryptoStream.Read(numArray, 0, numArray.Length);
            memoryStream.Close();
            cryptoStream.Close();
            return Encoding.UTF8.GetString(numArray, 0, count);
        }

        private static byte[] GetVectorBytes()
        {
            if (m_cachedVectorBytes == null)
                m_cachedVectorBytes = Encoding.UTF8.GetBytes("tu89geji340t89u2");
            return m_cachedVectorBytes;
        }

        private static byte[] GetPassphraseBytes(string passphrase, byte[] initVectorBytes)
        {
            if (!m_cachedPassphraseBytes.ContainsKey(passphrase))
            {
                Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passphrase, initVectorBytes);
                m_cachedPassphraseBytes.Add(passphrase, rfc2898DeriveBytes.GetBytes(32));
            }
            return m_cachedPassphraseBytes[passphrase];
        }
    }
}