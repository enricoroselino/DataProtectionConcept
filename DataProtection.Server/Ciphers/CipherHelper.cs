using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace DataProtection.Server.Ciphers;

public static class CipherHelper
{
    public static byte[] ApplySalt(string key, string salt, int bytesRequested)
    {
        var saltedKey = KeyDerivation.Pbkdf2(
            password: key,
            salt: Encoding.UTF8.GetBytes(salt),
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 1000,
            numBytesRequested: bytesRequested
        );

        ArgumentOutOfRangeException.ThrowIfNotEqual(saltedKey.Length, bytesRequested);
        return saltedKey;
    }

    public static byte[] GenerateRandomBytes(int bytesRequested)
    {
        return RandomNumberGenerator.GetBytes(bytesRequested);
    }
}