using CWG.SecureCoding.Core.Models.Identity;
using System.ComponentModel.DataAnnotations;

namespace CWG.SecureCoding.Core.Models;

/// <summary>
/// Represents a user session in the system
/// </summary>
public class UserSession : BaseEntity
{
    [Required]
    public string UserId { get; set; } = default!;
    public virtual ApplicationUser User { get; set; } = default!;
    
    [Required]
    [MaxLength(128)]
    public string SessionId { get; set; } = default!;
    
    [Required]
    [MaxLength(256)]
    public string IPAddress { get; set; } = default!;

    [Required]
    [MaxLength(1000)]
    public string UserAgent { get; set; } = default!;

    [Required]
    public DateTimeOffset LastActivityAt { get; set; }

    [MaxLength(128)]
    public string? RefreshToken { get; set; }

    public DateTimeOffset? RefreshTokenExpiresAt { get; set; }
    
    [Required]
    public bool IsActive { get; set; }
    
    public DateTimeOffset? LoggedOutAt { get; set; }

    [MaxLength(500)]
    public string? LogoutReason { get; set; }

    // Security fields
    public bool IsLocked { get; set; }
    public DateTimeOffset? LockedAt { get; set; }
    public string? LockReason { get; set; }
    public int FailedAccessAttempts { get; set; }
    public DateTimeOffset? LastFailedAccessAt { get; set; }
}
