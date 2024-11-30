using System.Text;
using DataProtection.Server.Ciphers.Algorithms.Aes;
using DataProtection.Server.Ciphers.Algorithms.Aes.Modes;
using Microsoft.Extensions.Options;
using NeoSmart.Utils;

namespace DataProtection.Server.Ciphers;

public sealed class TextCipher : ITextCipher
{
    private readonly IOptions<AesCipherSettings> _options;
    private IAesCipher CipherDefined => new AesEcbImplementation(_options);

    public TextCipher(IOptions<AesCipherSettings> options)
    {
        _options = options;
    }

    public async Task<string> EncryptAsync(string plainText, CancellationToken cancellationToken = default)
    {
        var bytes = Encoding.UTF8.GetBytes(plainText);
        await using var inputStream = new MemoryStream(bytes, writable: false);

        await using var cipher = CipherDefined;
        await using var result = (await cipher.Encrypt(inputStream, cancellationToken)).Value;
        if (!result.TryGetBuffer(out var buffer)) throw new ApplicationException("Failed to get buffer");
        return UrlBase64.Encode(buffer);
    }

    public async Task<string> DecryptAsync(string cipherText, CancellationToken cancellationToken = default)
    {
        var bytes = UrlBase64.Decode(cipherText);
        await using var inputStream = new MemoryStream(bytes, writable: false);

        await using var cipher = CipherDefined;
        await using var result = (await cipher.Decrypt(inputStream, cancellationToken)).Value;
        if (!result.TryGetBuffer(out var buffer)) throw new ApplicationException("Failed to get buffer");
        return Encoding.UTF8.GetString(buffer);
    }

    public string Encrypt(string plainText)
    {
        return EncryptAsync(plainText).GetAwaiter().GetResult();
    }

    public string Decrypt(string cipherText)
    {
        return DecryptAsync(cipherText).GetAwaiter().GetResult();
    }
}