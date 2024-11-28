using DataProtection.Server.Ciphers.Algorithms.Aes;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers;

public sealed class FileCipher : IFileCipher
{
    private readonly IOptions<AesCipherSettings> _options;
    private IAesCipher CipherDefined => new AesCbcImplementation(_options);

    public FileCipher(IOptions<AesCipherSettings> options)
    {
        _options = options;
    }

    public async Task<byte[]> Encrypt(Stream input, CancellationToken cancellationToken = default)
    {
        await using var cipher = CipherDefined;
        await using var encrypted = await cipher.Encrypt(input, cancellationToken);
        return encrypted.ToArray();
    }

    public async Task<byte[]> Decrypt(Stream input, CancellationToken cancellationToken = default)
    {
        await using var cipher = CipherDefined;
        await using var decrypted = await cipher.Decrypt(input, cancellationToken);
        return decrypted.ToArray();
    }
}