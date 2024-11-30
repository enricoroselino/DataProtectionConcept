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

    public async Task Save(MemoryStream inputStream, string filePath, CancellationToken cancellationToken = default)
    {
        var savePath = ProcessFilename(filePath);

        await using var encrypted = await _fileCipher.Encrypt(inputStream, cancellationToken);
        await using var fileStream = File.Create(savePath);
        await encrypted.CopyToAsync(fileStream, cancellationToken);
        await fileStream.FlushAsync(cancellationToken);
    }

    public async Task<MemoryStream> Load(string filePath, CancellationToken cancellationToken = default)
    {
        var filename = ProcessFilename(filePath);

        await using var fileStream = File.OpenRead(filename);
        await using var convertedStream = fileStream.ToMemoryStream();
        return await _fileCipher.Decrypt(convertedStream, cancellationToken);
    }

    private static string ProcessFilename(string path)
    {
        return !path.Contains(EncryptedExtension) ? Path.TrimEndingDirectorySeparator(path) + EncryptedExtension : path;
    }
}