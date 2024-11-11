﻿using System.Security.Cryptography;
using DataProtection.Server.Ciphers.Interfaces;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers.AESCiphers.Modes;

/// <summary>
/// AES CBC cipher mode. The data is prepended along with the IV.
/// </summary>
public sealed class AesCbcCipher : AesBaseCipher, ICipher
{
    private const int IvDefinedLength = 16;

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
            var combinedData = CombineData(cipherData);
            return combinedData;
        }
    }

    public async Task<byte[]> Decrypt(byte[] encryptedData, CancellationToken cancellationToken = default)
    {
        return await Task.Run(DecryptAction, cancellationToken);

        async Task<byte[]> DecryptAction()
        {
            var cipherData = ExtractCipherData(encryptedData);
            var plainData = await TransformToPlainText(cipherData, cancellationToken);
            return plainData;
        }
    }

    private byte[] CombineData(byte[] encryptedData)
    {
        // prepend the IV with the encrypted data
        // [IV, EncryptedData]
        var combinedData = new byte[this.IV.Length + encryptedData.Length];

        // save the IV
        Array.Copy(
            sourceArray: this.IV,
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

        return combinedData;
    }

    private byte[] ExtractCipherData(byte[] combinedData)
    {
        // incoming data is consist of IV and encrypted data
        // [IV, EncryptedData]

        // Extract the saved IV
        var iv = new byte[IvDefinedLength];
        Array.Copy(
            sourceArray: combinedData,
            sourceIndex: 0,
            destinationArray: iv,
            destinationIndex: 0,
            IvDefinedLength
        );
        this.IV = iv;

        // Extract the real encrypted data (w/o IV)
        var cipherData = new byte[combinedData.Length - IvDefinedLength];
        Array.Copy(
            sourceArray: combinedData,
            sourceIndex: IvDefinedLength,
            destinationArray: cipherData,
            destinationIndex: 0,
            cipherData.Length
        );

        ArgumentOutOfRangeException.ThrowIfNotEqual(this.IV.Length, IvDefinedLength);
        return cipherData;
    }

    private void GenerateIv()
    {
        this.IV = CipherHelper.GenerateRandomBytes(IvDefinedLength);
        ArgumentOutOfRangeException.ThrowIfNotEqual(this.IV.Length, IvDefinedLength);
    }
}