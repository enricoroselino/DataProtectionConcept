using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers;

public class AESCipherSettings
{
    public const string Section = nameof(AESCipherSettings);
    public string Key { get; set; }
    public string IV { get; set; }
}

public class AESCipherCBCMode : ICipher
{
    private readonly byte[] _key;
    private readonly byte[] _iv;
    private const int KeySize = 256;

    public AESCipherCBCMode(IOptions<AESCipherSettings> options)
    {
        var key = options.Value.Key;
        var iv = options.Value.IV;
        
        if (string.IsNullOrEmpty(key) || string.IsNullOrEmpty(iv))
        {
            throw new InvalidOperationException("Encryption key and IV must be set in environment variables.");
        }

        _key = Encoding.UTF8.GetBytes(key);
        _iv = Encoding.UTF8.GetBytes(iv);

        if (_key.Length != 32 || _iv.Length != 16)
        {
            throw new InvalidOperationException("Key must be 32 bytes long or IV must be 16 bytes long for AES-256.");
        }
    }

    public string Encrypt(string plainText)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;
        aes.KeySize = KeySize;
        aes.Mode = CipherMode.CBC;
        
        var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

        using var ms = new MemoryStream();
        using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
        using (var sw = new StreamWriter(cs))
        {
            sw.Write(plainText);
        }

        return Convert.ToBase64String(ms.ToArray());
    }

    public string Decrypt(string cipherText)
    {
        var buffer = Convert.FromBase64String(cipherText);

        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;
        aes.KeySize = KeySize;
        aes.Mode = CipherMode.CBC;
        
        var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

        using var ms = new MemoryStream(buffer);
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var sr = new StreamReader(cs);
        return sr.ReadToEnd();
    }
}