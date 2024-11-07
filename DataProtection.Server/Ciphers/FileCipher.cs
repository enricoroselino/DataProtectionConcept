using DataProtection.Server.Ciphers.AESCiphers;
using DataProtection.Server.Ciphers.Interfaces;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers;

/// <summary>
/// File cipher using AES256 GCM mode.
/// </summary>
public class FileCipher : IFileCipher
{
    private readonly IOptions<CipherSettings> _cipherOptions;
    private const AesCipherMode CipherMode = AesCipherMode.GCM;

    public FileCipher(IOptions<CipherSettings> cipherOptions)
    {
        _cipherOptions = cipherOptions;
    }

    public async Task<byte[]> Encrypt(byte[] data)
    {
        await using var cipher = AesCipherFactory.Create(CipherMode, _cipherOptions);
        return await cipher.Encrypt(data);
    }

    public async Task<byte[]> Decrypt(byte[] data)
    {
        await using var cipher = AesCipherFactory.Create(CipherMode, _cipherOptions);
        return await cipher.Decrypt(data);
    }
}