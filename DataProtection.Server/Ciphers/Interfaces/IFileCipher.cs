namespace DataProtection.Server.Ciphers.Interfaces;

public interface IFileCipher
{
    public Task<byte[]> Encrypt(IFormFile file);
    public Task<byte[]> Encrypt(byte[] fileBytes);
    public Task<byte[]> Decrypt(byte[] encryptedFileBytes);
}