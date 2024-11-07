namespace DataProtection.Server.Ciphers.Interfaces;

public interface ICipher : IDisposable, IAsyncDisposable
{
    public Task<byte[]> Encrypt(byte[] plainDataBytes, CancellationToken cancellationToken = default);

    public Task<byte[]> Decrypt(byte[] encryptedDataBytes, CancellationToken cancellationToken = default);
}