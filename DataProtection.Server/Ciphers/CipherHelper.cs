using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace DataProtection.Server.Ciphers;

public static class CipherHelper
{
    public static byte[] ApplySalt(string password, string salt, int bytesRequested, int iterations)
    {
        var saltedKey = KeyDerivation.Pbkdf2(
            password: password,
            salt: Encoding.UTF8.GetBytes(salt),
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: iterations,
            numBytesRequested: bytesRequested
        );

        ArgumentOutOfRangeException.ThrowIfNotEqual(saltedKey.Length, bytesRequested);
        return saltedKey;
    }

    public static byte[] GenerateRandomBytes(int bytesRequested)
    {
        return RandomNumberGenerator.GetBytes(bytesRequested);
    }

    public static byte[] GenerateHmac256(byte[] data, byte[] key)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(data);
    }
}