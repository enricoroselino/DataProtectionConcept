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

        async Task<byte[]> EncryptAction()
        {
            var cipherData = await TransformToCipherData(plainDataBytes, cancellationToken);
            return cipherData;
        }
    }

    public async Task<byte[]> Decrypt(byte[] encryptedData, CancellationToken cancellationToken = default)
    {
        return await Task.Run(DecryptAction, cancellationToken);

        async Task<byte[]> DecryptAction()
        {
            var plainData = await TransformToPlainText(encryptedData, cancellationToken);
            return plainData;
        }
    }
}