using Microsoft.AspNetCore.Identity;

namespace CWG.SecureCoding.Core.Models.Identity;

/// <summary>
/// Application role entity
/// </summary>
public class ApplicationRole : IdentityRole
{
    public string? Description { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public bool IsActive { get; set; } = true;
}
