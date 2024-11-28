using System.Security.Cryptography;
using DataProtection.Server.Ciphers.Models;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers.Algorithms.Aes;

public sealed class AesEcbImplementation : AesBase, IAesCipher
{
    private readonly SymmetricAlgorithm _baseCipher;

    public AesEcbImplementation(IOptions<AesCipherSettings> options) : base(options)
    {
        _baseCipher = System.Security.Cryptography.Aes.Create();
        _baseCipher.Padding = PaddingMode.PKCS7;
        _baseCipher.KeySize = 256;
        _baseCipher.Mode = CipherMode.ECB;
        _baseCipher.Key = Key;
    }

    public async Task<OutputStream> Encrypt(Stream request, CancellationToken cancellationToken = default)
    {
        if (!request.CanSeek) throw new IOException("Stream must be seekable");
        request.Seek(0, SeekOrigin.Begin);

        var inputStream = new InputStream(request);
        var outputStream = new OutputStream(new MemoryStream());

        // ECB doesnt need to generate IV
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

        // ECB doesnt need IV to decrypt
        await DecryptData(inputStream, outputStream, cancellationToken);

        outputStream.Value.Seek(0, SeekOrigin.Begin);
        return outputStream;
    }

    private async Task DecryptData(
        InputStream request,
        OutputStream decryptedStream,
        CancellationToken cancellationToken = default)
    {
        using var decryptor = _baseCipher.CreateDecryptor(_baseCipher.Key, _baseCipher.IV);

        // LEAVE OPEN THE CRYPTO STREAM
        var cryptoStream = new CryptoStream(request.Value, decryptor, CryptoStreamMode.Read, leaveOpen: true);
        await cryptoStream.CopyToAsync(decryptedStream.Value, cancellationToken);
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