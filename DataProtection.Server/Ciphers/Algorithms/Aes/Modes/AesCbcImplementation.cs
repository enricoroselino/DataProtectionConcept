using System.Security.Cryptography;
using DataProtection.Server.Ciphers.Models;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers.Algorithms.Aes.Modes;

public sealed class AesCbcImplementation : AesBase, IAesCipher
{
    private const int IvSize = AesSizeConstant.IvSize;
    private const int TagSize = AesSizeConstant.KeySize;

    public AesCbcImplementation(IOptions<AesCipherSettings> options) : base(options)
    {
        BaseCipher.Mode = CipherMode.CBC;
    }

    public async Task<OutputStream> Encrypt(Stream request, CancellationToken cancellationToken = default)
    {
        var inputStream = new InputStream(request.ToMemoryStream());
        var outputStream = new OutputStream(new MemoryStream());

        await GenerateIv(outputStream, cancellationToken);
        await EncryptData(inputStream, outputStream, cancellationToken);
        await GenerateAuthTag(outputStream, cancellationToken);

        outputStream.Value.Seek(0, SeekOrigin.Begin);
        return outputStream;
    }

    protected override Task EncryptData(
        InputStream request,
        OutputStream result,
        CancellationToken cancellationToken = default)
    {
        result.Value.Position = IvSize;
        return base.EncryptData(request, result, cancellationToken);
    }

    public async Task<OutputStream> Decrypt(Stream request, CancellationToken cancellationToken = default)
    {
        var inputStream = new InputStream(request.ToMemoryStream());
        var outputStream = new OutputStream(new MemoryStream());

        await ValidateAuthTag(inputStream, cancellationToken);
        await ExtractIv(inputStream, cancellationToken);
        await DecryptData(inputStream, outputStream, cancellationToken);

        outputStream.Value.Seek(0, SeekOrigin.Begin);
        return outputStream;
    }

    protected override Task DecryptData(
        InputStream request,
        OutputStream result,
        CancellationToken cancellationToken = default)
    {
        request.Value.Position = IvSize;
        return base.DecryptData(request, result, cancellationToken);
    }

    private async Task GenerateAuthTag(OutputStream result, CancellationToken cancellationToken = default)
    {
        result.Value.Seek(0, SeekOrigin.Begin);
        var tag = await CryptoHelper.ComputeHash(result.Value, Key, cancellationToken);

        result.Value.Seek(0, SeekOrigin.End);
        await result.Value.WriteAsync(tag, cancellationToken);
    }

    private async Task ValidateAuthTag(InputStream request, CancellationToken cancellationToken = default)
    {
        var sizeWithoutTag = request.Value.Length - TagSize;

        var fileTag = new byte[TagSize];
        request.Value.Position = sizeWithoutTag;
        await request.Value.ReadExactlyAsync(fileTag, cancellationToken);

        request.Value.Seek(0, SeekOrigin.Begin);
        request.Value.SetLength(sizeWithoutTag);
        var computedTag = await CryptoHelper.ComputeHash(request.Value, Key, cancellationToken);

        if (!fileTag.SequenceEqual(computedTag))
            throw new InvalidDataException("Invalid authentication tag, data is tampered");
    }

    private async Task GenerateIv(OutputStream result, CancellationToken cancellationToken = default)
    {
        result.Value.Seek(0, SeekOrigin.Begin);

        BaseCipher.GenerateIV();
        await result.Value.WriteAsync(BaseCipher.IV, cancellationToken);
    }

    private async Task ExtractIv(InputStream request, CancellationToken cancellationToken = default)
    {
        request.Value.Seek(0, SeekOrigin.Begin);

        var ivBuffer = new byte[IvSize];
        await request.Value.ReadExactlyAsync(ivBuffer, cancellationToken);
        BaseCipher.IV = ivBuffer;
    }
}