using System.ComponentModel.DataAnnotations;
using CWG.SecureCoding.Core.Models.Identity;

namespace CWG.SecureCoding.Core.Models;

/// <summary>
/// Represents a payment method
/// </summary>
public class PaymentMethod : BaseEntity
{
    [Required]
    public string UserId { get; set; } = default!;
    public ApplicationUser User { get; set; } = default!;

    [Required]
    [MaxLength(50)]
    public string Type { get; set; } = default!;

    [Required]
    [MaxLength(500)]
    public string EncryptedData { get; set; } = default!;

    [Required]
    [MaxLength(32)]
    public string Salt { get; set; } = default!;

    [Required]
    [MaxLength(32)]
    public string IV { get; set; } = default!;

    [MaxLength(4)]
    public string? LastFourDigits { get; set; }

    [MaxLength(100)]
    public string? CardHolderName { get; set; }

    [MaxLength(2)]
    public string? ExpiryMonth { get; set; }

    [MaxLength(4)]
    public string? ExpiryYear { get; set; }

    public bool IsDefault { get; set; }
    public bool IsVerified { get; set; }
    public DateTimeOffset? LastVerifiedAt { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }

    [MaxLength(50)]
    public string? LastUsedFromIP { get; set; }

    public virtual ICollection<Payment> Payments { get; set; } = new List<Payment>();
}
