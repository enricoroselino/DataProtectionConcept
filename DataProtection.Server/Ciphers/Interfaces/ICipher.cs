namespace DataProtection.Server.Ciphers.Interfaces;

public interface ICipher : IDisposable, IAsyncDisposable
{
    public Task<byte[]> Encrypt(byte[] plainDataBytes);
    public Task<byte[]> Decrypt(byte[] encryptedDataBytes);
}