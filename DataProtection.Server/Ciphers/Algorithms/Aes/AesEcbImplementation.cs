﻿using System.Security.Cryptography;
using DataProtection.Server.Ciphers.Models;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers.Algorithms.Aes;

public sealed class AesEcbImplementation : AesBase, IAesCipher
{
    public AesEcbImplementation(IOptions<AesCipherSettings> options) : base(options)
    {
        BaseCipher.Mode = CipherMode.ECB;
    }

    public async Task<OutputStream> Encrypt(Stream request, CancellationToken cancellationToken = default)
    {
        var inputStream = new InputStream(request.ToMemoryStream());
        var outputStream = new OutputStream(new MemoryStream());

        // ECB doesnt need to generate IV
        await EncryptData(inputStream, outputStream, cancellationToken);

        outputStream.Value.Seek(0, SeekOrigin.Begin);
        return outputStream;
    }


    public async Task<OutputStream> Decrypt(Stream request, CancellationToken cancellationToken = default)
    {
        var inputStream = new InputStream(request.ToMemoryStream());
        var outputStream = new OutputStream(new MemoryStream());

        // ECB doesnt need IV to decrypt
        await DecryptData(inputStream, outputStream, cancellationToken);

        outputStream.Value.Seek(0, SeekOrigin.Begin);
        return outputStream;
    }


    protected override void Dispose(bool disposing)
    {
        if (IsDisposed) return;

        if (disposing)
        {
            // Dispose managed resources here
        }

        base.Dispose(disposing);
    }
}