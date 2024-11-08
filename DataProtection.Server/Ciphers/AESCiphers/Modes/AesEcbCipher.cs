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
        AesConcrete.Mode = CipherMode.ECB;
    }

    public async Task<byte[]> Encrypt(byte[] plainDataBytes, CancellationToken cancellationToken = default)
    {
        return await Task.Run(EncryptAction, cancellationToken);

        async Task<byte[]> EncryptAction()
        {
            var encryptor = AesConcrete.CreateEncryptor(this.Key, null);

            using var ms = new MemoryStream();
            await using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
            await cs.WriteAsync(plainDataBytes, cancellationToken);
            await cs.FlushFinalBlockAsync(cancellationToken);
            return ms.ToArray();
        }
    }

    public async Task<byte[]> Decrypt(byte[] encryptedDataBytes, CancellationToken cancellationToken = default)
    {
        return await Task.Run(Function, cancellationToken);

        async Task<byte[]> Function()
        {
            var decryptor = AesConcrete.CreateDecryptor(this.Key, null);

            using var ms = new MemoryStream(encryptedDataBytes);
            await using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);

            using var decryptedStream = new MemoryStream();
            await cs.CopyToAsync(decryptedStream, cancellationToken);
            return decryptedStream.ToArray();
        }
    }
}