using System.Text.RegularExpressions;

namespace CWG.SecureCoding.Core.Security;

/// <summary>
/// Input validation utilities for secure controllers
/// </summary>
public static class InputValidator
{
    private static readonly Regex EmailRegex = new(
        @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex SafeStringRegex = new(
        @"^[\w\s-'.()]{1,200}$",
        RegexOptions.Compiled);

    private static readonly Regex SafeFileNameRegex = new(
        @"^[\w\s-'.()]{1,200}\.[a-zA-Z0-9]{1,10}$",
        RegexOptions.Compiled);

    public static bool IsValidEmail(string email)
        => !string.IsNullOrEmpty(email) && EmailRegex.IsMatch(email);

    public static bool IsValidFileName(string fileName)
        => !string.IsNullOrEmpty(fileName) && SafeFileNameRegex.IsMatch(fileName);

    public static bool IsValidSafeString(string input)
        => !string.IsNullOrEmpty(input) && SafeStringRegex.IsMatch(input);

    public static bool IsValidFileSize(long size, long maxSize)
        => size > 0 && size <= maxSize;

    public static bool IsValidContentType(string contentType, string[] allowedTypes)
        => !string.IsNullOrEmpty(contentType) 
           && allowedTypes.Contains(contentType.ToLower());
}
