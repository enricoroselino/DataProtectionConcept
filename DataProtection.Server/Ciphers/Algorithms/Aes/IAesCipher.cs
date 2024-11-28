namespace DataProtection.Server.Ciphers.Algorithms.Aes;

public interface IAesCipher : IDisposable, IAsyncDisposable
{
    public Task<MemoryStream> Encrypt(Stream request, CancellationToken cancellationToken = default);
    public Task<MemoryStream> Decrypt(Stream request, CancellationToken cancellationToken = default);
}