using System.Text.RegularExpressions;

namespace CWG.SecureCoding.Core.Services.Common.Security;

/// <summary>
/// Provides validation and security checks for audit logging
/// Ensures audit trail integrity and prevents log injection
/// </summary>
public class AuditValidator
{
    // Maximum field lengths
    private const int MaxEventNameLength = 100;
    private const int MaxDetailsLength = 2000;
    private const int MaxIpAddressLength = 45; // IPv6 length

    // Safe pattern for event names
    private static readonly Regex _eventNameRegex = new(
        @"^[a-zA-Z0-9\-_\.]+$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant
    );

    // IP address patterns
    private static readonly Regex _ipv4Regex = new(
        @"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant
    );

    private static readonly Regex _ipv6Regex = new(
        @"^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase
    );

    public bool ValidateEventName(string eventName)
    {
        if (string.IsNullOrWhiteSpace(eventName) || 
            eventName.Length > MaxEventNameLength)
            return false;

        return _eventNameRegex.IsMatch(eventName);
    }

    public bool ValidateDetails(string details)
    {
        if (string.IsNullOrWhiteSpace(details))
            return true; // Details are optional

        if (details.Length > MaxDetailsLength)
            return false;

        // Check for potential log injection
        if (ContainsLogInjection(details))
            return false;

        return true;
    }

    public bool ValidateIpAddress(string ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress) || 
            ipAddress.Length > MaxIpAddressLength)
            return false;

        return _ipv4Regex.IsMatch(ipAddress) || _ipv6Regex.IsMatch(ipAddress);
    }

    public string SanitizeDetails(string details)
    {
        if (string.IsNullOrWhiteSpace(details))
            return details;

        // Remove control characters
        details = new string(details.Where(c => !char.IsControl(c)).ToArray());

        // Escape newlines
        details = details.Replace("\n", "\\n")
                        .Replace("\r", "\\r");

        // HTML encode special characters
        details = System.Web.HttpUtility.HtmlEncode(details);

        return details;
    }

    private bool ContainsLogInjection(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return false;

        // Check for common log injection patterns
        var injectionPatterns = new[]
        {
            "%0A", "%0D", // URL encoded newlines
            "\\n", "\\r", // Literal newlines
            "%", // Format string specifier
            "\\x", // Hex escape
            "\\u", // Unicode escape
            "script", // Script injection
            "--", // SQL comment
            "/*", "*/" // Multi-line comment
        };

        return injectionPatterns.Any(pattern => 
            input.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }

    public bool ValidateTimeRange(DateTimeOffset startTime, DateTimeOffset endTime)
    {
        // Ensure start time is not in future
        if (startTime > DateTimeOffset.UtcNow)
            return false;

        // Ensure end time is not before start time
        if (endTime < startTime)
            return false;

        // Limit query range to prevent DoS (e.g., 1 year)
        if ((endTime - startTime).TotalDays > 365)
            return false;

        return true;
    }
}
