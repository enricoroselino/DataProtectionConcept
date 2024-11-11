﻿using System.Security.Cryptography;
using DataProtection.Server.Ciphers.AESCiphers.Metadata;
using DataProtection.Server.Ciphers.Interfaces;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers.AESCiphers.Modes;

/// <summary>
/// AES GCM cipher mode. The data is prepended with nonce and appended with tag.
/// </summary>
public sealed class AesGcmCipher : ICipher
{
    private bool _disposed;
    private readonly AesGcm _aesGcm;

    private const int KeyDefinedLength = 32;
    private const int TagDefinedLength = 32;
    private const int NonceDefinedLength = 12;

    public AesGcmCipher(IOptions<CipherSettings> options)
    {
        var saltedKey = CipherHelper.ApplySalt(
            options.Value.Key,
            options.Value.Salt,
            KeyDefinedLength,
            options.Value.Iterations
        );

        ArgumentOutOfRangeException.ThrowIfNotEqual(saltedKey.Length, KeyDefinedLength);
        _aesGcm = new AesGcm(saltedKey, TagDefinedLength);
    }

    public async Task<byte[]> Encrypt(byte[] plainDataBytes, CancellationToken cancellationToken = default)
    {
        return await Task.Run(EncryptAction, cancellationToken);

        byte[] EncryptAction()
        {
            // nonce should be unique every encryption
            var nonce = CipherHelper.GenerateRandomBytes(NonceDefinedLength);
            // tag is autogenerated every .Encrypt invoked
            var tag = new byte[TagDefinedLength];

            var encryptedData = new byte[plainDataBytes.Length];
            _aesGcm.Encrypt(nonce, plainDataBytes, encryptedData, tag);

            var metadata = new GcmMetadata(nonce, tag);
            var combinedData = CombineData(metadata, encryptedData);
            return combinedData;
        }
    }

    private static byte[] CombineData(GcmMetadata metadata, byte[] encryptedData)
    {
        // prepend nonce and append tag
        // [nonce, EncryptedData, tag]
        var combinedData = new byte[encryptedData.Length + TagDefinedLength + NonceDefinedLength];

        // save the nonce
        Array.Copy(
            sourceArray: metadata.Nonce,
            sourceIndex: 0,
            destinationArray: combinedData,
            destinationIndex: 0,
            NonceDefinedLength
        );

        // save the data
        Array.Copy(
            sourceArray: encryptedData,
            sourceIndex: 0,
            destinationArray: combinedData,
            destinationIndex: NonceDefinedLength,
            encryptedData.Length
        );

        // save the tag
        Array.Copy(
            sourceArray: metadata.Tag,
            sourceIndex: 0,
            destinationArray: combinedData,
            destinationIndex: NonceDefinedLength + encryptedData.Length,
            TagDefinedLength
        );

        return combinedData;
    }

    public async Task<byte[]> Decrypt(byte[] encryptedData, CancellationToken cancellationToken = default)
    {
        return await Task.Run(DecryptAction, cancellationToken);

        byte[] DecryptAction()
        {
            var metadata = ExtractMetadata(encryptedData);
            var cipherData = ExtractCipherData(encryptedData);

            var decryptedData = new byte[cipherData.Length];
            _aesGcm.Decrypt(metadata.Nonce, cipherData, metadata.Tag, decryptedData);
            return decryptedData;
        }
    }

    private static GcmMetadata ExtractMetadata(byte[] combinedData)
    {
        var nonce = new byte[NonceDefinedLength];
        Array.Copy(
            sourceArray: combinedData,
            sourceIndex: 0,
            destinationArray: nonce,
            destinationIndex: 0,
            NonceDefinedLength
        );

        var tag = new byte[TagDefinedLength];
        Array.Copy(
            sourceArray: combinedData,
            sourceIndex: combinedData.Length - TagDefinedLength,
            destinationArray: tag,
            destinationIndex: 0,
            TagDefinedLength
        );

        ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, NonceDefinedLength);
        ArgumentOutOfRangeException.ThrowIfNotEqual(tag.Length, TagDefinedLength);

        var metadata = new GcmMetadata(nonce, tag);
        return metadata;
    }

    private static byte[] ExtractCipherData(byte[] combinedData)
    {
        var cipherDataLength = combinedData.Length - NonceDefinedLength - TagDefinedLength;
        var cipherData = new byte[cipherDataLength];
        Array.Copy(
            sourceArray: combinedData,
            sourceIndex: NonceDefinedLength,
            destinationArray: cipherData,
            destinationIndex: 0,
            cipherDataLength
        );

        return cipherData;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    // Asynchronous Dispose
    public async ValueTask DisposeAsync()
    {
        Dispose(true); // Use synchronous dispose method as there's no async disposal needed
        GC.SuppressFinalize(this);
        await ValueTask.CompletedTask; // Satisfy async method requirements
    }

    private void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        if (disposing)
        {
            // Dispose managed resources here
            _aesGcm.Dispose();
        }

        _disposed = true;
    }

    // Finalizer
    ~AesGcmCipher()
    {
        Dispose(false);
    }
}