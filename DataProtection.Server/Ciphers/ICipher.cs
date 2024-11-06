namespace DataProtection.Server.Ciphers;

public interface ICipher
{
    public string Encrypt(string plainText);
    public string Decrypt(string cipherText);
}