using DataProtection.Server.Ciphers;

namespace DataProtection.Server.FileHandlers;

public class LocalFileHandler : IFileHandler
{
    private readonly IFileCipher _fileCipher;

    public LocalFileHandler(IFileCipher fileCipher)
    {
        _fileCipher = fileCipher;
    }

    public async Task Save(IFormFile file, CancellationToken cancellationToken = default)
    {
        var filename = file.FileName + ".enc";

        await using var fileStream = file.OpenReadStream();
        var encrypted = await _fileCipher.Encrypt(fileStream, cancellationToken);
        await File.WriteAllBytesAsync(filename, encrypted, cancellationToken);
    }

    public async Task<byte[]> Load(string filePath, CancellationToken cancellationToken = default)
    {
        var filename = Path.TrimEndingDirectorySeparator(filePath) + ".enc";
        await using var fileStream = File.OpenRead(filename);
        var decrypted = await _fileCipher.Decrypt(fileStream, cancellationToken);
        return decrypted;
    }
}