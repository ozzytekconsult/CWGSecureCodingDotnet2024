using Microsoft.AspNetCore.Identity;

namespace CWG.SecureCoding.Core.Models.Identity;

/// <summary>
/// Application user entity
/// </summary>
public class ApplicationUser : IdentityUser
{
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public bool IsActive { get; set; } = true;
}
