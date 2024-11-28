using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers.Algorithms.Aes;

public sealed class AesEcbImplementation : AesBase, IAesCipher
{
    private readonly SymmetricAlgorithm _baseCipher;

    public AesEcbImplementation(IOptions<AesCipherSettings> options) : base(options)
    {
        _baseCipher = System.Security.Cryptography.Aes.Create();
        _baseCipher.Padding = PaddingMode.PKCS7;
        _baseCipher.KeySize = 256;
        _baseCipher.Mode = CipherMode.ECB;
        _baseCipher.Key = Key;
    }

    public async Task<MemoryStream> Encrypt(Stream request, CancellationToken cancellationToken = default)
    {
        request.Position = 0;

        // ECB doesnt need to generate IV
        var encryptedStream = new MemoryStream();
        using var encryptor = _baseCipher.CreateEncryptor(_baseCipher.Key, _baseCipher.IV);
        await using var cryptoStream = new CryptoStream(encryptedStream, encryptor, CryptoStreamMode.Write);
        await request.CopyToAsync(cryptoStream, cancellationToken);
        await cryptoStream.FlushFinalBlockAsync(cancellationToken);
        return encryptedStream;
    }

    public async Task<MemoryStream> Decrypt(Stream request, CancellationToken cancellationToken = default)
    {
        request.Position = 0;

        // ECB doesnt need IV to decrypt
        var decryptedStream = new MemoryStream();
        using var decryptor = _baseCipher.CreateDecryptor(_baseCipher.Key, _baseCipher.IV);
        await using var cryptoStream = new CryptoStream(request, decryptor, CryptoStreamMode.Read);
        await cryptoStream.CopyToAsync(decryptedStream, cancellationToken);
        return decryptedStream;
    }

    protected override void Dispose(bool disposing)
    {
        if (IsDisposed) return;

        if (disposing)
        {
            // Dispose managed resources here
            _baseCipher.Dispose();
        }

        base.Dispose(disposing);
    }
}