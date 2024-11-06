namespace DataProtection.Server.Ciphers.Interfaces;

public interface ITextCipher
{
    public Task<string> Encrypt(string plainText);
    public Task<string> Decrypt(string encryptedText);
}