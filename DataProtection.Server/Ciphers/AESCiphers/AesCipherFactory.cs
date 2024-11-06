using DataProtection.Server.Ciphers.AESCiphers.Modes;
using DataProtection.Server.Ciphers.Interfaces;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers.AESCiphers;

public static class AesCipherFactory
{
    public static ICipher Create(AesCipherMode mode, IOptions<CipherSettings> cipherOptions)
    {
        return mode switch
        {
            AesCipherMode.CBC => new AesCbcCipher(cipherOptions),
            AesCipherMode.ECB => new AesEcbCipher(cipherOptions),
            AesCipherMode.GCM => new AesGcmCipher(cipherOptions),
            _ => throw new NotSupportedException("Cipher mode not supported")
        };
    }
}