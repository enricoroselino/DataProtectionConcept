namespace DataProtection.Server.Ciphers.Interfaces;

public interface ICipher : IDisposable, IAsyncDisposable
{
    public Task<byte[]> Encrypt(byte[] plainData, CancellationToken cancellationToken = default);

    public Task<byte[]> Decrypt(byte[] encryptedData, CancellationToken cancellationToken = default);
}