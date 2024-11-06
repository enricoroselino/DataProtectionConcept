using System.Text;
using DataProtection.Server.Ciphers.AESCiphers;
using DataProtection.Server.Ciphers.Interfaces;
using Microsoft.Extensions.Options;
using NeoSmart.Utils;

namespace DataProtection.Server.Ciphers;

/// <summary>
/// Database cipher using AES ECB mode.
/// </summary>
public sealed class TextCipher : ITextCipher
{
    private const AesCipherMode CipherMode = AesCipherMode.ECB;
    private readonly IOptions<CipherSettings> _cipherOptions;

    public TextCipher(IOptions<CipherSettings> cipherOptions)
    {
        _cipherOptions = cipherOptions;
    }

    public async Task<string> Encrypt(string plainText)
    {
        await using var cipher = AesCipherFactory.Create(CipherMode, _cipherOptions);
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var encrypted = await cipher.Encrypt(plainBytes);
        return UrlBase64.Encode(encrypted);
    }

    public async Task<string> Decrypt(string encryptedText)
    {
        var buffer = UrlBase64.Decode(encryptedText);
        await using var cipher = AesCipherFactory.Create(CipherMode, _cipherOptions);
        var decrypted = await cipher.Decrypt(buffer);
        return Encoding.UTF8.GetString(decrypted);
    }
}