using DataProtection.Server.Ciphers.AESCiphers;
using DataProtection.Server.Ciphers.Interfaces;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers;

public class FileCipher : IFileCipher
{
    private readonly IOptions<CipherSettings> _cipherOptions;
    private const AesCipherMode CipherMode = AesCipherMode.GCM;

    public FileCipher(IOptions<CipherSettings> cipherOptions)
    {
        _cipherOptions = cipherOptions;
    }

    public string Suffix => $".aes-{CipherMode.ToString().ToLower()}.enc";

    public async Task<byte[]> Encrypt(IFormFile file, CancellationToken cancellationToken = default)
    {
        return await Task.Run(EncryptFileAction, cancellationToken);

        async Task<byte[]> EncryptFileAction()
        {
            await using var ms = new MemoryStream();
            await using var cipher = AesCipherFactory.Create(CipherMode, _cipherOptions);
            await file.CopyToAsync(ms, cancellationToken);
            return await cipher.Encrypt(ms.ToArray(), cancellationToken);
        }
    }

    public async Task<byte[]> Decrypt(byte[] data, CancellationToken cancellationToken = default)
    {
        return await Task.Run(DecryptFileAction, cancellationToken);

        async Task<byte[]> DecryptFileAction()
        {
            await using var cipher = AesCipherFactory.Create(CipherMode, _cipherOptions);
            return await cipher.Decrypt(data, cancellationToken);
        }
    }
}