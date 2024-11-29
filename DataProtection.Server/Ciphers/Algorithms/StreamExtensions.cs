namespace DataProtection.Server.Ciphers.Algorithms;

public static class StreamExtensions
{
    public static MemoryStream ToMemoryStream(this Stream stream)
    {
        if (stream is MemoryStream memoryStream) return memoryStream;

        var convertedStream = new MemoryStream();
        stream.Seek(0, SeekOrigin.Begin);
        stream.CopyTo(convertedStream);

        convertedStream.Seek(0, SeekOrigin.Begin);
        return convertedStream;
    }

    public static void SetPosition(this MemoryStream stream, long position)
    {
        stream.Position = position;
    }
}