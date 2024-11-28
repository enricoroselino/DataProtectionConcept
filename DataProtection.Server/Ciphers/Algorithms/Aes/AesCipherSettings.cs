namespace DataProtection.Server.Ciphers.Algorithms.Aes;

public class AesCipherSettings
{
    public const string Section = nameof(AesCipherSettings);
    public string Key { get; init; } = default!;
    public string Salt { get; init; } = default!;
}