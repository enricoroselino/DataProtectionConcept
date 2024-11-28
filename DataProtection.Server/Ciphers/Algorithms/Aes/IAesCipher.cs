using DataProtection.Server.Ciphers.Models;

namespace DataProtection.Server.Ciphers.Algorithms.Aes;

public interface IAesCipher : IDisposable, IAsyncDisposable
{
    public Task<OutputStream> Encrypt(Stream request, CancellationToken cancellationToken = default);
    public Task<OutputStream> Decrypt(Stream request, CancellationToken cancellationToken = default);
}