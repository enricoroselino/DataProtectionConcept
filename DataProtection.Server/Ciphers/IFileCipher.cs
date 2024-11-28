namespace DataProtection.Server.Ciphers;

public interface IFileCipher
{
    public Task<MemoryStream> Encrypt(Stream input, CancellationToken cancellationToken = default);
    public Task<MemoryStream> Decrypt(Stream input, CancellationToken cancellationToken = default);
}