using Microsoft.Net.Http.Headers;

namespace DataProtection.Server;

public static class FormFileExtensions
{
    public static string GetFileName(this IFormFile f)
    {
        return ContentDispositionHeaderValue.Parse(f.ContentDisposition).FileName.ToString();
    }
}