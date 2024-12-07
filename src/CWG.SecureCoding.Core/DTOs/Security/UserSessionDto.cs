using CWG.SecureCoding.Core.DTOs.Common;
using System.ComponentModel.DataAnnotations;

namespace CWG.SecureCoding.Core.DTOs.Security;

// Response DTO
public class UserSessionDto : BaseDto
{
    public string UserId { get; set; } = default!;
    public string SessionId { get; set; } = default!;
    public string IPAddress { get; set; } = default!;
    public string UserAgent { get; set; } = default!;
    public DateTimeOffset LastActivityAt { get; set; }
    public bool IsActive { get; set; }
    public DateTimeOffset? LoggedOutAt { get; set; }
    public bool IsLocked { get; set; }
    public int FailedAccessAttempts { get; set; }
}

// Create Session DTO
public class CreateSessionDto
{
    [Required]
    public string UserId { get; set; } = default!;

    [Required]
    [MaxLength(256)]
    public string IPAddress { get; set; } = default!;

    [Required]
    [MaxLength(1000)]
    public string UserAgent { get; set; } = default!;

    [Required]
    public string DeviceId { get; set; } = default!;
}

// Update Session DTO
public class UpdateSessionDto
{
    [Required]
    public string SessionId { get; set; } = default!;

    [Required]
    public DateTimeOffset LastActivityAt { get; set; }

    [MaxLength(256)]
    public string? NewIPAddress { get; set; }
}

// Session Search DTO
public class SessionSearchDto
{
    public string? UserId { get; set; }
    public string? IPAddress { get; set; }
    public string? UserAgent { get; set; }
    public bool? IsActive { get; set; }
    public bool? IsLocked { get; set; }
    public DateTime? StartDate { get; set; }
    public DateTime? EndDate { get; set; }
    public int? MinFailedAttempts { get; set; }
    public string? SortBy { get; set; }
    public bool SortDescending { get; set; }
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 20;
}

// Session Security Event DTO
public class SessionSecurityEventDto
{
    [Required]
    public string SessionId { get; set; } = default!;

    [Required]
    public SecurityEventType EventType { get; set; }

    [Required]
    [MaxLength(256)]
    public string IPAddress { get; set; } = default!;

    [MaxLength(500)]
    public string? EventDetails { get; set; }
}

public enum SecurityEventType
{
    SuccessfulLogin,
    FailedLogin,
    PasswordChange,
    InvalidToken,
    SuspiciousActivity,
    AccountLocked,
    AccountUnlocked,
    LoggedOut
}
