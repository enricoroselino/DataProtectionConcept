using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace DataProtection.Server.Ciphers;

public static class CryptoHelper
{
    public static byte[] DerivationKey(string key, string salt, int bytesLength)
    {
        var saltedKey = KeyDerivation.Pbkdf2(
            password: key,
            salt: Encoding.UTF8.GetBytes(salt),
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 10000,
            numBytesRequested: bytesLength
        );

        return saltedKey;
    }

    public static async Task<byte[]> ComputeHash(
        Stream request,
        byte[] key,
        CancellationToken cancellationToken = default)
    {
        using var hmac = new HMACSHA256(key);
        var computedHash = await hmac.ComputeHashAsync(request, cancellationToken);
        return computedHash;
    }
}