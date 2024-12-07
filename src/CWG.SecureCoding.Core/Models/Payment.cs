using System.ComponentModel.DataAnnotations;
using CWG.SecureCoding.Core.Models.Identity;

namespace CWG.SecureCoding.Core.Models;

/// <summary>
/// Represents a payment transaction
/// </summary>
public class Payment : BaseEntity
{
    [Required]
    public string UserId { get; set; } = default!;
    public virtual ApplicationUser User { get; set; } = default!;

    [Required]
    public int OrderId { get; set; }
    public virtual Order Order { get; set; } = default!;

    [Required]
    [Range(0.01, double.MaxValue)]
    public decimal Amount { get; set; }

    [Required]
    [RegularExpression(@"^[A-Z]{3}$")]
    public string Currency { get; set; } = "USD";

    [Required]
    [MaxLength(50)]
    public string PaymentMethod { get; set; } = default!;

    [Required]
    [MaxLength(100)]
    public string TransactionReference { get; set; } = default!;

    [MaxLength(500)]
    public string? FailureReason { get; set; }

    [Range(0, 5)]
    public int RetryCount { get; set; }

    public DateTimeOffset? LastRetryAt { get; set; }

    [Required]
    public PaymentStatus Status { get; set; } = PaymentStatus.Pending;

    public DateTimeOffset? CompletedAt { get; set; }

    public string? CompletedBy { get; set; }

    public DateTimeOffset? RefundedAt { get; set; }

    public string? RefundedBy { get; set; }

    [Required]
    [MaxLength(1000)]
    public string EncryptedDetails { get; set; } = default!;
}

public enum PaymentStatus
{
    Pending = 0,
    Processing = 1,
    Completed = 2,
    Failed = 3,
    Refunded = 4,
    Cancelled = 5
}
