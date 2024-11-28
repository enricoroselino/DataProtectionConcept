namespace DataProtection.Server.FileHandlers;

public interface IFileHandler
{
    public Task Save(Stream inputStream, string filePath, CancellationToken cancellationToken = default);
    public Task<MemoryStream> Load(string filePath, CancellationToken cancellationToken = default);
}