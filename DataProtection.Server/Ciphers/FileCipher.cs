using DataProtection.Server.Ciphers.AESCiphers;
using DataProtection.Server.Ciphers.Interfaces;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers;

public class FileCipher : IFileCipher
{
    private readonly IOptions<CipherSettings> _cipherOptions;
    private const AesCipherMode CipherMode = AesCipherMode.CBC;

    public FileCipher(IOptions<CipherSettings> cipherOptions)
    {
        _cipherOptions = cipherOptions;
    }

    public async Task<byte[]> Encrypt(IFormFile file)
    {
        using var fs = new MemoryStream();
        await file.CopyToAsync(fs);
        return await Encrypt(fs.ToArray());
    }

    public async Task<byte[]> Encrypt(byte[] fileBytes)
    {
        await using var cipher = AesCipherFactory.Create(CipherMode, _cipherOptions);
        return await cipher.Encrypt(fileBytes);
    }

    public async Task<byte[]> Decrypt(byte[] encryptedFileBytes)
    {
        await using var cipher = AesCipherFactory.Create(CipherMode, _cipherOptions);
        return await cipher.Decrypt(encryptedFileBytes);
    }
}