using System.ComponentModel.DataAnnotations;

namespace DataProtection.Server.Ciphers.Algorithms.Aes;

public class AesCipherSettings
{
    public const string Section = nameof(AesCipherSettings);
    [Required] [StringLength(32)] public string Key { get; init; } = default!;
    [Required] [StringLength(16)] public string Salt { get; init; } = default!;
}