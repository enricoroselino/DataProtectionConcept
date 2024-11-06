using System.Security.Cryptography;
using DataProtection.Server.Ciphers.Interfaces;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers.AESCiphers.Modes;

/// <summary>
/// AES GCM cipher mode. The data is prepended along with the nonce and tag.
/// </summary>
public sealed class AesGcmCipher : ICipher
{
    private readonly AesGcm _aesGcm;

    private const int KeyDefinedLength = 32;
    private const int TagDefinedLength = 16;
    private const int NonceDefinedLength = 12;

    public AesGcmCipher(IOptions<CipherSettings> options)
    {
        var saltedKey = CipherHelper.ApplySalt(
            options.Value.Key,
            options.Value.Salt,
            KeyDefinedLength
        );

        ArgumentOutOfRangeException.ThrowIfNotEqual(saltedKey.Length, KeyDefinedLength);

        _aesGcm = new AesGcm(saltedKey, TagDefinedLength);
    }

    public async Task<byte[]> Encrypt(byte[] plainDataBytes)
    {
        // nonce should be unique every encryption
        var nonce = CipherHelper.GenerateRandomBytes(NonceDefinedLength);
        var tag = new byte[TagDefinedLength];

        var encryptedData = new byte[plainDataBytes.Length];
        _aesGcm.Encrypt(nonce, plainDataBytes, encryptedData, tag);

        var combinedData = CombineData(nonce, encryptedData, tag);
        return await Task.FromResult(combinedData);
    }

    private static byte[] CombineData(byte[] nonce, byte[] encryptedData, byte[] tag)
    {
        // prepend nonce and append tag
        // [nonce, EncryptedData, tag]
        var combinedData = new byte[encryptedData.Length + TagDefinedLength + NonceDefinedLength];

        // save the nonce
        Array.Copy(
            sourceArray: nonce,
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
            sourceArray: tag,
            sourceIndex: 0,
            destinationArray: combinedData,
            destinationIndex: NonceDefinedLength + encryptedData.Length,
            TagDefinedLength
        );

        return combinedData;
    }

    public async Task<byte[]> Decrypt(byte[] encryptedDataBytes)
    {
        var (nonce, cipherData, tag) = ExtractData(encryptedDataBytes);
        var decryptedData = new byte[cipherData.Length];

        _aesGcm.Decrypt(nonce, cipherData, tag, decryptedData);
        return await Task.FromResult(decryptedData);
    }

    private static (byte[], byte[], byte[]) ExtractData(byte[] combinedData)
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

        var cipherDataLength = combinedData.Length - NonceDefinedLength - TagDefinedLength;
        var cipherData = new byte[cipherDataLength];
        Array.Copy(
            sourceArray: combinedData,
            sourceIndex: NonceDefinedLength,
            destinationArray: cipherData,
            destinationIndex: 0,
            cipherDataLength
        );

        ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, NonceDefinedLength);
        ArgumentOutOfRangeException.ThrowIfNotEqual(tag.Length, TagDefinedLength);
        return (nonce, cipherData, tag);
    }

    public void Dispose()
    {
        _aesGcm.Dispose();
        GC.SuppressFinalize(this);
    }

    public async ValueTask DisposeAsync()
    {
        await Task.FromResult(Dispose);
    }
}