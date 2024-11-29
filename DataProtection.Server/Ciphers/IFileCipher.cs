namespace DataProtection.Server.Ciphers;

public interface IFileCipher
{
    public Task<MemoryStream> Encrypt(MemoryStream input, CancellationToken cancellationToken = default);
    public Task<MemoryStream> Decrypt(MemoryStream input, CancellationToken cancellationToken = default);
}