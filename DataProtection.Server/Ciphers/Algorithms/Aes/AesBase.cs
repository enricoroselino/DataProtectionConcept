using System.Security.Cryptography;
using DataProtection.Server.Ciphers.Models;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers.Algorithms.Aes;

public abstract class AesBase : IDisposable, IAsyncDisposable
{
    private const int KeySize = AesSizeConstant.KeySize;
    protected readonly byte[] Key;
    protected readonly SymmetricAlgorithm BaseCipher;

    protected bool IsDisposed;

    protected AesBase(IOptions<AesCipherSettings> options)
    {
        BaseCipher = System.Security.Cryptography.Aes.Create();
        BaseCipher.Padding = PaddingMode.PKCS7;
        BaseCipher.KeySize = 256;

        var saltedKey = CryptoHelper.DerivationKey(options.Value.Key, options.Value.Salt, KeySize);
        Key = saltedKey;
        BaseCipher.Key = saltedKey;
    }

    protected virtual async Task EncryptData(
        InputStream request,
        OutputStream result,
        CancellationToken cancellationToken = default)
    {
        using var encryptor = BaseCipher.CreateEncryptor(BaseCipher.Key, BaseCipher.IV);

        // LEAVE OPEN THE CRYPTO STREAM
        var cryptoStream = new CryptoStream(result.Value, encryptor, CryptoStreamMode.Write, leaveOpen: true);
        await request.Value.CopyToAsync(cryptoStream, cancellationToken);
        await cryptoStream.FlushFinalBlockAsync(cancellationToken);
    }

    protected virtual async Task DecryptData(
        InputStream request,
        OutputStream result,
        CancellationToken cancellationToken = default)
    {
        using var decryptor = BaseCipher.CreateDecryptor(BaseCipher.Key, BaseCipher.IV);

        // LEAVE OPEN THE CRYPTO STREAM
        var cryptoStream = new CryptoStream(request.Value, decryptor, CryptoStreamMode.Read, leaveOpen: true);
        await cryptoStream.CopyToAsync(result.Value, cancellationToken);
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
        Dispose(true);
        GC.SuppressFinalize(this);
        await ValueTask.CompletedTask;
    }

    protected virtual void Dispose(bool disposing)
    {
        if (IsDisposed) return;

        if (disposing)
        {
            // Dispose managed resources here
            BaseCipher.Dispose();
        }

        IsDisposed = true;
    }

    // Finalizer
    ~AesBase()
    {
        Dispose(false);
    }
}