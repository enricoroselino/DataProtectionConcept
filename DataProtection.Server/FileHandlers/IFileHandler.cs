namespace DataProtection.Server.FileHandlers;

public interface IFileHandler
{
    public Task Save(IFormFile file, string path, CancellationToken cancellationToken = default);
    public Task<byte[]> Load(string path, CancellationToken cancellationToken = default);
}