using DataProtection.Server.Ciphers.Interfaces;

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
        var filename = file.GetFileName() + _fileCipher.Suffix;
        var encrypted = await _fileCipher.Encrypt(file, cancellationToken);
        await File.WriteAllBytesAsync(filename, encrypted, cancellationToken);
    }

    public async Task<byte[]> Load(string path, CancellationToken cancellationToken = default)
    {
        var data = await File.ReadAllBytesAsync(path + _fileCipher.Suffix, cancellationToken);
        return await _fileCipher.Decrypt(data, cancellationToken);
    }
}