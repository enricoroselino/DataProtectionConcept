namespace DataProtection.Server.Ciphers.Interfaces;

public interface IFileCipher
{
    public string Suffix { get; }
    public Task<byte[]> Encrypt(IFormFile file, CancellationToken cancellationToken = default);
    public Task<byte[]> Decrypt(byte[] data, CancellationToken cancellationToken = default);
}