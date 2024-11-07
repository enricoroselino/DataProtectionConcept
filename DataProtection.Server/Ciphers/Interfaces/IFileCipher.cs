namespace DataProtection.Server.Ciphers.Interfaces;

public interface IFileCipher
{
    public Task<byte[]> Encrypt(byte[] data);
    public Task<byte[]> Decrypt(byte[] data);
}