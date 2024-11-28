namespace DataProtection.Server.Ciphers;

public interface ITextCipher
{
    public Task<string> EncryptAsync(string plainText, CancellationToken cancellationToken = default);
    public Task<string> DecryptAsync(string cipherText, CancellationToken cancellationToken = default);
    public string Encrypt(string plainText);
    public string Decrypt(string cipherText);
}