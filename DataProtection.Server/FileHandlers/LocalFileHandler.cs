using DataProtection.Server.Ciphers.Interfaces;

namespace DataProtection.Server.FileHandlers;

public class LocalFileHandler : IFileHandler
{
    private readonly IFileCipher _fileCipher;

    public LocalFileHandler(IFileCipher fileCipher)
    {
        _fileCipher = fileCipher;
    }

    public async Task Save(IFormFile file, string path, CancellationToken cancellationToken = default)
    {
        var filename = Path.Combine(path, file.FileName) + _fileCipher.Suffix;
        var encrypted = await _fileCipher.Encrypt(file, cancellationToken);
        await File.WriteAllBytesAsync(filename, encrypted, cancellationToken);
    }

    public async Task<byte[]> Load(string path, CancellationToken cancellationToken = default)
    {
        var filePath = Path.TrimEndingDirectorySeparator(path) + _fileCipher.Suffix;
        var data = await File.ReadAllBytesAsync(filePath, cancellationToken);
        return await _fileCipher.Decrypt(data, cancellationToken);
    }
}