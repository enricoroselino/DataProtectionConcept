using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers.AESCiphers.Modes;

public abstract class AesBaseCipher : IDisposable, IAsyncDisposable
{
    protected readonly SymmetricAlgorithm AesCipher;
    private const int KeyDefinedLength = 32;
    private bool _disposed;

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

    protected async Task<byte[]> TransformToCipherData(
        byte[] plainData,
        CancellationToken cancellationToken = default)
    {
        using var encryptor = AesCipher.CreateEncryptor(AesCipher.Key, AesCipher.IV);

        // encrypt in one shot to save resources, not using CryptoStream if possible
        if (encryptor.CanTransformMultipleBlocks)
            return encryptor.TransformFinalBlock(plainData, 0, plainData.Length);

        using var ms = new MemoryStream();
        await using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
        await cs.WriteAsync(plainData, cancellationToken);
        await cs.FlushFinalBlockAsync(cancellationToken);
        return ms.ToArray();
    }

    protected async Task<byte[]> TransformToPlainText(byte[] cipherText, CancellationToken cancellationToken = default)
    {
        using var decryptor = AesCipher.CreateDecryptor(AesCipher.Key, AesCipher.IV);

        // idk if decrypt can use the same way like encrypting, just leave using CryptoStream
        using var ms = new MemoryStream(cipherText);
        await using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);

        using var decryptedStream = new MemoryStream();
        await cs.CopyToAsync(decryptedStream, cancellationToken);
        return decryptedStream.ToArray();
    }

    // Synchronous Dispose
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    // Asynchronous Dispose
    public async ValueTask DisposeAsync()
    {
        Dispose(true); // Use synchronous dispose method as there's no async disposal needed
        GC.SuppressFinalize(this);
        await ValueTask.CompletedTask; // Satisfy async method requirements
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        if (disposing)
        {
            // Dispose managed resources here
            AesCipher.Dispose();
        }

        _disposed = true;
    }

    // Finalizer
    ~AesBaseCipher()
    {
        Dispose(false);
    }
}