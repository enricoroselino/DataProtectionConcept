using DataProtection.Server.Ciphers.Models;

namespace DataProtection.Server.Ciphers.Algorithms.Aes;

public interface IAesCipher : IDisposable, IAsyncDisposable
{
    public Task<OutputStream> Encrypt(MemoryStream request, CancellationToken cancellationToken = default);
    public Task<OutputStream> Decrypt(MemoryStream request, CancellationToken cancellationToken = default);
}