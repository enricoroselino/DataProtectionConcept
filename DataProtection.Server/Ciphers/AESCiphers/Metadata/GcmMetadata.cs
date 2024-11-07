namespace DataProtection.Server.Ciphers.AESCiphers.Metadata;

internal record GcmMetadata(byte[] Nonce, byte[] Tag);