using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers.AESCiphers.Modes;

public abstract class AesBaseCipher : IDisposable, IAsyncDisposable
{
    protected readonly SymmetricAlgorithm AesCipher;
    private const int KeyDefinedLength = 32;

    protected byte[] Key
    {
        get => AesCipher.Key;
        private init => AesCipher.Key = value;
    }

    protected AesBaseCipher(IOptions<CipherSettings> options)
    {
        var saltedKey = CipherHelper.ApplySalt(
            options.Value.Key,
            options.Value.Salt,
            KeyDefinedLength,
            options.Value.Iterations
        );

        ArgumentOutOfRangeException.ThrowIfNotEqual(saltedKey.Length, KeyDefinedLength);

        AesCipher = Aes.Create();
        AesCipher.Padding = PaddingMode.PKCS7;
        AesCipher.KeySize = 256;
        Key = saltedKey;
    }

    public void Dispose()
    {
        AesCipher.Dispose();
        GC.SuppressFinalize(this);
    }

    public async ValueTask DisposeAsync()
    {
        await Task.FromResult(Dispose);
    }
}