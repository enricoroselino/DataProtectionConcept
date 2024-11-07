using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers.AESCiphers.Modes;

public abstract class AesBaseCipher : IDisposable, IAsyncDisposable
{
    protected readonly Aes AesConcrete;
    private const int KeyDefinedLength = 32;

    protected byte[] Key
    {
        get => AesConcrete.Key;
        private init => AesConcrete.Key = value;
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

        AesConcrete = Aes.Create();
        AesConcrete.Padding = PaddingMode.PKCS7;
        AesConcrete.KeySize = 256;
        Key = saltedKey;
    }

    public void Dispose()
    {
        AesConcrete.Dispose();
        GC.SuppressFinalize(this);
    }

    public async ValueTask DisposeAsync()
    {
        await Task.FromResult(Dispose);
    }
}