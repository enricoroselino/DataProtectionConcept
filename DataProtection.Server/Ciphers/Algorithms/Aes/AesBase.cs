using System.Buffers;
using System.Security.Cryptography;
using DataProtection.Server.Ciphers.Models;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers.Algorithms.Aes;

public abstract class AesBase : IDisposable, IAsyncDisposable
{
    private const int KeySize = AesSizeConstant.KeySize;
    protected readonly byte[] Key;
    protected readonly SymmetricAlgorithm BaseCipher;

    private bool _isDisposed;

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
        const CryptoStreamMode mode = CryptoStreamMode.Write;
        await using var cryptoStream = new CryptoStream(result.Value, encryptor, mode, leaveOpen: true);

        var chunkSize = ChunkSizeFactory.Get(request.Value.Length);
        var buffer = ArrayPool<byte>.Shared.Rent(chunkSize);

        try
        {
            int bytesRead;
            while ((bytesRead = await request.Value.ReadAsync(buffer, cancellationToken)) > 0)
            {
                // don't use buffer.AsMemory
                await cryptoStream.WriteAsync(buffer, 0, bytesRead, cancellationToken);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        await cryptoStream.FlushFinalBlockAsync(cancellationToken);
    }

    protected virtual async Task DecryptData(
        InputStream request,
        OutputStream result,
        CancellationToken cancellationToken = default)
    {
        using var decryptor = BaseCipher.CreateDecryptor(BaseCipher.Key, BaseCipher.IV);
        const CryptoStreamMode mode = CryptoStreamMode.Read;
        await using var cryptoStream = new CryptoStream(request.Value, decryptor, mode, leaveOpen: true);

        var chunkSize = ChunkSizeFactory.Get(request.Value.Length);
        var buffer = ArrayPool<byte>.Shared.Rent(chunkSize);

        try
        {
            int bytesRead;
            while ((bytesRead = await cryptoStream.ReadAsync(buffer, cancellationToken)) > 0)
            {
                // don't use buffer.AsMemory
                await result.Value.WriteAsync(buffer, 0, bytesRead, cancellationToken);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
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
        if (_isDisposed) return;

        if (disposing)
        {
            // Dispose managed resources here
            BaseCipher.Dispose();
        }

        _isDisposed = true;
    }

    // Finalizer
    ~AesBase()
    {
        Dispose(false);
    }
}