using System.Security.Cryptography;
using DataProtection.Server.Ciphers.Interfaces;
using Microsoft.Extensions.Options;

namespace DataProtection.Server.Ciphers.AESCiphers.Modes;

/// <summary>
/// AES EBC cipher mode.
/// </summary>
public class AesEcbCipher : AesBaseCipher, ICipher
{
    public AesEcbCipher(IOptions<CipherSettings> options) : base(options)
    {
        AesCipher.Mode = CipherMode.ECB;
    }

    public async Task<byte[]> Encrypt(byte[] plainDataBytes, CancellationToken cancellationToken = default)
    {
        return await Task.Run(EncryptAction, cancellationToken);

        // async Task<byte[]> EncryptAction()
        // {
        //     var encryptor = AesCipher.CreateEncryptor(this.Key, null);
        //
        //     using var ms = new MemoryStream();
        //     await using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
        //     await cs.WriteAsync(plainDataBytes, cancellationToken);
        //     await cs.FlushFinalBlockAsync(cancellationToken);
        //     return ms.ToArray();
        // }

        async Task<byte[]> EncryptAction()
        {
            var cipherData = await TransformToCipherData(plainDataBytes, cancellationToken);
            return cipherData;
        }
    }

    public async Task<byte[]> Decrypt(byte[] encryptedData, CancellationToken cancellationToken = default)
    {
        return await Task.Run(DecryptAction, cancellationToken);

        // async Task<byte[]> DecryptAction()
        // {
        //     var decryptor = AesCipher.CreateDecryptor(this.Key, null);
        //
        //     using var ms = new MemoryStream(encryptedDataBytes);
        //     await using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        //
        //     using var decryptedStream = new MemoryStream();
        //     await cs.CopyToAsync(decryptedStream, cancellationToken);
        //     return decryptedStream.ToArray();
        // }

        async Task<byte[]> DecryptAction()
        {
            var plainData = await TransformToPlainText(encryptedData, cancellationToken);
            return plainData;
        }
    }
}