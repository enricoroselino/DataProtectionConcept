namespace DataProtection.Server.FileHandlers;

public interface IFileHandler
{
    public Task Save(IFormFile file, CancellationToken cancellationToken = default);
    public Task<byte[]> Load(string filePath, CancellationToken cancellationToken = default);
}