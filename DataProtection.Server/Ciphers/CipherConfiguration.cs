using DataProtection.Server.Ciphers.Algorithms.Aes;
using DataProtection.Server.FileHandlers;

namespace DataProtection.Server.Ciphers;

public static class CipherConfiguration
{
    public static IServiceCollection AddCiphers(this IServiceCollection services)
    {
        services
            .AddOptions<AesCipherSettings>()
            .BindConfiguration(AesCipherSettings.Section)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services
            .AddScoped<ITextCipher, TextCipher>()
            .AddScoped<IFileCipher, FileCipher>()
            .AddScoped<IFileHandler, LocalFileHandler>();

        return services;
    }
}