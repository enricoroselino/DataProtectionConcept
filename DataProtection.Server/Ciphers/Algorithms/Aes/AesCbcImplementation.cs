using System.Security.Cryptography;
using DataProtection.Server.Ciphers.Models;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers.Algorithms.Aes;

public sealed class AesCbcImplementation : AesBase, IAesCipher
{
    private readonly SymmetricAlgorithm _baseCipher;
    private const int IvSize = AesSizeConstant.IvSize;

    public AesCbcImplementation(IOptions<AesCipherSettings> options) : base(options)
    {
        _baseCipher = System.Security.Cryptography.Aes.Create();
        _baseCipher.Padding = PaddingMode.PKCS7;
        _baseCipher.KeySize = 256;
        _baseCipher.Mode = CipherMode.CBC;
        _baseCipher.Key = Key;
    }

    public async Task<OutputStream> Encrypt(Stream request, CancellationToken cancellationToken = default)
    {
        if (!request.CanSeek) throw new IOException("Stream must be seekable");
        request.Seek(0, SeekOrigin.Begin);

        var inputStream = new InputStream(request);
        var outputStream = new OutputStream(new MemoryStream());

        await GenerateIv(outputStream, cancellationToken);
        await EncryptData(inputStream, outputStream, cancellationToken);

        outputStream.Value.Seek(0, SeekOrigin.Begin);
        return outputStream;
    }

    private async Task EncryptData(
        InputStream request,
        OutputStream encryptedStream,
        CancellationToken cancellationToken = default)
    {
        using var encryptor = _baseCipher.CreateEncryptor(_baseCipher.Key, _baseCipher.IV);

        // LEAVE OPEN THE CRYPTO STREAM
        var cryptoStream = new CryptoStream(encryptedStream.Value, encryptor, CryptoStreamMode.Write, leaveOpen: true);
        await request.Value.CopyToAsync(cryptoStream, cancellationToken);
        await cryptoStream.FlushFinalBlockAsync(cancellationToken);
    }

    public async Task<OutputStream> Decrypt(Stream request, CancellationToken cancellationToken = default)
    {
        if (!request.CanSeek) throw new IOException("Stream must be seekable");
        request.Seek(0, SeekOrigin.Begin);

        var inputStream = new InputStream(request);
        var outputStream = new OutputStream(new MemoryStream());
        
        await ExtractIv(inputStream, cancellationToken);
        await DecryptData(inputStream, outputStream, cancellationToken);

        outputStream.Value.Seek(0, SeekOrigin.Begin);
        return outputStream;
    }

    private async Task DecryptData(
        InputStream request,
        OutputStream result,
        CancellationToken cancellationToken = default)
    {
        using var decryptor = _baseCipher.CreateDecryptor(_baseCipher.Key, _baseCipher.IV);

        // LEAVE OPEN THE CRYPTO STREAM
        var cryptoStream = new CryptoStream(request.Value, decryptor, CryptoStreamMode.Read, leaveOpen: true);
        await cryptoStream.CopyToAsync(result.Value, cancellationToken);
    }

    private async Task GenerateIv(OutputStream encryptedStream, CancellationToken cancellationToken = default)
    {
        _baseCipher.GenerateIV();
        ArgumentOutOfRangeException.ThrowIfNotEqual(_baseCipher.IV.Length, IvSize);
        await encryptedStream.Value.WriteAsync(_baseCipher.IV, cancellationToken);
    }

    private async Task ExtractIv(InputStream request, CancellationToken cancellationToken = default)
    {
        var ivBuffer = new byte[IvSize];
        await request.Value.ReadExactlyAsync(ivBuffer, cancellationToken);
        _baseCipher.IV = ivBuffer;

        request.Value.Position = IvSize;
    }

    protected override void Dispose(bool disposing)
    {
        if (IsDisposed) return;

        if (disposing)
        {
            // Dispose managed resources here
            _baseCipher.Dispose();
        }

        base.Dispose(disposing);
    }
}