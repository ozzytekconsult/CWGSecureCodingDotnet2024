using System.Text.RegularExpressions;

namespace CWG.SecureCoding.Core.Security;

/// <summary>
/// Provides security validation for document operations
/// </summary>
public static class DocumentSecurityValidator
{
    private static readonly string[] AllowedFileExtensions = new[] 
    { 
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", 
        ".txt", ".csv", ".jpg", ".jpeg", ".png" 
    };

    private static readonly string[] AllowedMimeTypes = new[]
    {
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "text/plain",
        "text/csv",
        "image/jpeg",
        "image/png"
    };

    private static readonly long MaxFileSize = 104857600; // 100MB

    public static bool IsValidFileName(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName)) return false;
        
        // Check for valid characters
        if (!Regex.IsMatch(fileName, @"^[\w\-. ]+$")) return false;
        
        // Check extension
        var extension = Path.GetExtension(fileName).ToLowerInvariant();
        return AllowedFileExtensions.Contains(extension);
    }

    public static bool IsValidContentType(string contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType)) return false;
        return AllowedMimeTypes.Contains(contentType.ToLowerInvariant());
    }

    public static bool IsValidFileSize(long fileSize)
    {
        return fileSize > 0 && fileSize <= MaxFileSize;
    }

    public static bool IsValidMetadata(IDictionary<string, string> metadata)
    {
        if (metadata == null) return true;
        
        foreach (var kvp in metadata)
        {
            // Check key
            if (string.IsNullOrWhiteSpace(kvp.Key) || kvp.Key.Length > 50) return false;
            if (!Regex.IsMatch(kvp.Key, @"^[\w\-. ]+$")) return false;

            // Check value
            if (kvp.Value != null && kvp.Value.Length > 500) return false;
            if (!string.IsNullOrEmpty(kvp.Value) && !Regex.IsMatch(kvp.Value, @"^[\w\-.,;: ]+$"))
                return false;
        }

        return true;
    }

    public static async Task<string> CalculateFileHash(Stream stream)
    {
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        stream.Position = 0;
        var hash = await sha256.ComputeHashAsync(stream);
        stream.Position = 0;
        return Convert.ToBase64String(hash);
    }

    public static bool ValidateFileSignature(Stream stream, string contentType)
    {
        if (stream == null || stream.Length < 4) return false;

        stream.Position = 0;
        var buffer = new byte[4];
        stream.Read(buffer, 0, buffer.Length);
        stream.Position = 0;

        switch (contentType.ToLowerInvariant())
        {
            case "application/pdf":
                return buffer[0] == 0x25 && buffer[1] == 0x50 && buffer[2] == 0x44 && buffer[3] == 0x46;
            case "image/jpeg":
                return buffer[0] == 0xFF && buffer[1] == 0xD8;
            case "image/png":
                return buffer[0] == 0x89 && buffer[1] == 0x50 && buffer[2] == 0x4E && buffer[3] == 0x47;
            // Add more signature checks as needed
            default:
                return true; // For other types, rely on content type validation
        }
    }
}
