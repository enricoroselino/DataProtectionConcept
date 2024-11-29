namespace DataProtection.Server.Ciphers;

public static class ChunkSizeFactory
{
    public static int Get(long fileSize)
    {
        const long megaBytes = 1024 * 1024;

        return fileSize switch
        {
            < 1 * megaBytes => ChunkConstant.Small,
            < 10 * megaBytes => ChunkConstant.Medium,
            < 100 * megaBytes => ChunkConstant.Large,
            < 1 * 1024 * megaBytes => ChunkConstant.ExtraLarge,
            _ => ChunkConstant.Massive
        };
    }
}