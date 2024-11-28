using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers.Algorithms.Aes;

public abstract class AesBase : IDisposable, IAsyncDisposable
{
    private const int KeySize = AesSizeConstant.KeySize;
    protected byte[] Key { get; init; }
    protected bool IsDisposed;

    protected AesBase(IOptions<AesCipherSettings> options)
    {
        var saltedKey = CryptoHelper.DerivationKey(options.Value.Key, options.Value.Salt, KeySize);
        ArgumentOutOfRangeException.ThrowIfNotEqual(saltedKey.Length, KeySize);
        Key = saltedKey;
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
        }

        IsDisposed = true;
    }

    // Finalizer
    ~AesBase()
    {
        Dispose(false);
    }
}