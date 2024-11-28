using DataProtection.Server.Ciphers;

namespace DataProtection.Server.FileHandlers;

public sealed class LocalFileHandler : IFileHandler
{
    private readonly IFileCipher _fileCipher;
    private const string EncryptedExtension = ".enc";

    public LocalFileHandler(IFileCipher fileCipher)
    {
        _fileCipher = fileCipher;
    }

    public async Task Save(Stream fileStream, string filePath, CancellationToken cancellationToken = default)
    {
        var savePath = ProcessFilename(filePath);
        await using var encrypted = await _fileCipher.Encrypt(fileStream, cancellationToken);
        await File.WriteAllBytesAsync(savePath, encrypted.ToArray(), cancellationToken);
    }

    public async Task<MemoryStream> Load(string filePath, CancellationToken cancellationToken = default)
    {
        var filename = ProcessFilename(filePath);
        await using var fileStream = File.OpenRead(filename);
        return await _fileCipher.Decrypt(fileStream, cancellationToken);
    }

    private static string ProcessFilename(string path)
    {
        return !path.Contains(EncryptedExtension) ? Path.TrimEndingDirectorySeparator(path) + EncryptedExtension : path;
    }
}