using Microsoft.Extensions.Logging;

namespace CWG.SecureCoding.Core.Security;

/// <summary>
/// Secure audit logger for security events
/// </summary>
public class AuditLogger
{
    private readonly ILogger _logger;

    public AuditLogger(ILogger logger)
    {
        _logger = logger;
    }

    public void LogSecurityEvent(
        string userId,
        string action,
        string resource,
        bool success,
        string? details = null)
    {
        _logger.LogInformation(
            "Security Event: User={UserId} Action={Action} Resource={Resource} Success={Success} Details={Details}",
            userId,
            action,
            resource,
            success,
            details ?? "None");
    }
}
