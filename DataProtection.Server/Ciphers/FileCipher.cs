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

    public async Task<MemoryStream> Encrypt(Stream input, CancellationToken cancellationToken = default)
    {
        await using var cipher = CipherDefined;
        var result = await cipher.Encrypt(input, cancellationToken);
        return result.Value;
    }

    public async Task<MemoryStream> Decrypt(Stream input, CancellationToken cancellationToken = default)
    {
        await using var cipher = CipherDefined;
        var result = await cipher.Decrypt(input, cancellationToken);
        return result.Value;
    }
}