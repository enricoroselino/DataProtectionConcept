using System.ComponentModel.DataAnnotations;

namespace DataProtection.Server.Ciphers.Algorithms.Aes;

public class AesCipherSettings
{
    public const string Section = nameof(AesCipherSettings);
    [Required] public string Key { get; init; } = default!;
    [Required] public string Salt { get; init; } = default!;
}