using DataProtection.Server.Ciphers.Algorithms.Aes;

namespace DataProtection.Server.Ciphers;

public static class CipherConfiguration
{
    public static IServiceCollection AddCiphers(this IServiceCollection services)
    {
        services
            .AddTransient<ITextCipher, TextCipher>()
            .AddTransient<IFileCipher, FileCipher>()
            .AddOptions<AesCipherSettings>()
            .BindConfiguration(AesCipherSettings.Section);

        return services;
    }
}