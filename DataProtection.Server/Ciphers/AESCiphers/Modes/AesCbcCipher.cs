using System.Security.Cryptography;
using DataProtection.Server.Ciphers.Interfaces;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers.AESCiphers.Modes;

/// <summary>
/// AES CBC cipher mode. The data is prepended along with the IV.
/// </summary>
public sealed class AesCbcCipher : AesBaseCipher, ICipher
{
    private const int IvDefinedLength = 16;
    private const int TagDefinedLength = 32; // 256-bit HMAC

    private byte[] IV
    {
        get => AesCipher.IV;
        set => AesCipher.IV = value;
    }

    public AesCbcCipher(IOptions<CipherSettings> options) : base(options)
    {
        AesCipher.Mode = CipherMode.CBC;
    }

    public async Task<byte[]> Encrypt(byte[] plainDataBytes, CancellationToken cancellationToken = default)
    {
        return await Task.Run(EncryptAction, cancellationToken);

        async Task<byte[]> EncryptAction()
        {
            GenerateIv();
            var cipherData = await TransformToCipherData(plainDataBytes, cancellationToken);
            var tag = CipherHelper.GenerateHmac256(cipherData, Key);
            return CombineData(cipherData, tag);
        }
    }

    private byte[] CombineData(byte[] encryptedData, byte[] tag)
    {
        // prepend the IV with the encrypted data
        // [IV, EncryptedData, Tag]
        var combinedData = new byte[IV.Length + encryptedData.Length + tag.Length];

        // save the IV
        Array.Copy(
            sourceArray: IV,
            sourceIndex: 0,
            destinationArray: combinedData,
            destinationIndex: 0,
            IvDefinedLength
        );

        // save the data
        Array.Copy(
            sourceArray: encryptedData,
            sourceIndex: 0,
            destinationArray: combinedData,
            destinationIndex: IvDefinedLength,
            encryptedData.Length
        );

        // save the tag
        Array.Copy(
            sourceArray: tag,
            sourceIndex: 0,
            destinationArray: combinedData,
            destinationIndex: encryptedData.Length + IvDefinedLength,
            tag.Length
        );

        return combinedData;
    }


    public async Task<byte[]> Decrypt(byte[] encryptedData, CancellationToken cancellationToken = default)
    {
        return await Task.Run(DecryptAction, cancellationToken);

        async Task<byte[]> DecryptAction()
        {
            ExtractMetaData(encryptedData);
            var cipherData = ExtractCipherData(encryptedData);
            var plainData = await TransformToPlainText(cipherData, cancellationToken);
            return plainData;
        }
    }

    private void ExtractMetaData(byte[] combinedData)
    {
        // incoming data is consist of IV and encrypted data
        // [IV, EncryptedData, Tag]

        // Extract the saved IV
        var iv = new byte[IvDefinedLength];
        Array.Copy(
            sourceArray: combinedData,
            sourceIndex: 0,
            destinationArray: iv,
            destinationIndex: 0,
            IvDefinedLength
        );

        IV = iv;

        ArgumentOutOfRangeException.ThrowIfNotEqual(IV.Length, IvDefinedLength);
    }

    private byte[] ExtractCipherData(byte[] combinedData)
    {
        // incoming data is consist of IV and encrypted data
        // [IV, EncryptedData, Tag]

        // Extract the real encrypted data (w/o IV dan Tag)
        var cipherData = new byte[combinedData.Length - IvDefinedLength - TagDefinedLength];
        Array.Copy(
            sourceArray: combinedData,
            sourceIndex: IvDefinedLength,
            destinationArray: cipherData,
            destinationIndex: 0,
            cipherData.Length
        );

        var tag = new byte[TagDefinedLength];
        Array.Copy(
            sourceArray: combinedData,
            sourceIndex: combinedData.Length - TagDefinedLength,
            destinationArray: tag,
            destinationIndex: 0,
            TagDefinedLength
        );

        ArgumentOutOfRangeException.ThrowIfNotEqual(tag.Length, TagDefinedLength);

        var expectedTag = CipherHelper.GenerateHmac256(cipherData, Key);
        if (!expectedTag.SequenceEqual(tag)) throw new CryptographicException("HMAC verification failed.");
        return cipherData;
    }

    private void GenerateIv()
    {
        IV = CipherHelper.GenerateRandomBytes(IvDefinedLength);
        ArgumentOutOfRangeException.ThrowIfNotEqual(IV.Length, IvDefinedLength);
    }
}