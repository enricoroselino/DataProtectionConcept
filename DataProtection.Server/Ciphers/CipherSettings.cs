namespace DataProtection.Server.Ciphers;

public class CipherSettings
{
    public const string Section = nameof(CipherSettings);
    public string Key { get; init; }
    public string Salt { get; init; }
}