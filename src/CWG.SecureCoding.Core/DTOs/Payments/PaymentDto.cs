using CWG.SecureCoding.Core.DTOs.Common;
using CWG.SecureCoding.Core.Models;
using System.ComponentModel.DataAnnotations;

namespace CWG.SecureCoding.Core.DTOs.Payments;

// Response DTO
public class PaymentDto : AuditableDto
{
    public string UserId { get; set; } = default!;
    public int OrderId { get; set; }
    public decimal Amount { get; set; }
    public string Currency { get; set; } = default!;
    public string PaymentMethod { get; set; } = default!;
    public string TransactionReference { get; set; } = default!;
    public PaymentStatus Status { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public DateTimeOffset? RefundedAt { get; set; }
}

// Process Payment DTO
public class ProcessPaymentDto
{
    [Required]
    public int OrderId { get; set; }

    [Required]
    [Range(0.01, double.MaxValue)]
    public decimal Amount { get; set; }

    [Required]
    [RegularExpression(@"^[A-Z]{3}$")]
    public string Currency { get; set; } = "USD";

    [Required]
    public string PaymentMethod { get; set; } = default!;

    [Required]
    public PaymentDetailsDto PaymentDetails { get; set; } = default!;
}

// Payment Details Base DTO
public abstract class PaymentDetailsDto
{
    [Required]
    public string PaymentType { get; set; } = default!;
}

// Credit Card Payment Details
public class CreditCardPaymentDto : PaymentDetailsDto
{
    [Required]
    [CreditCard]
    public string CardNumber { get; set; } = default!;

    [Required]
    [Range(1, 12)]
    public int ExpiryMonth { get; set; }

    [Required]
    [Range(2024, 2100)]
    public int ExpiryYear { get; set; }

    [Required]
    [RegularExpression(@"^\d{3,4}$")]
    public string CVV { get; set; } = default!;

    [Required]
    [MaxLength(100)]
    public string CardholderName { get; set; } = default!;
}

// PayPal Payment Details
public class PayPalPaymentDto : PaymentDetailsDto
{
    [Required]
    [MaxLength(100)]
    public string PayPalEmail { get; set; } = default!;

    [Required]
    public string PayPalToken { get; set; } = default!;
}

// Refund DTO
public class RefundPaymentDto
{
    [Required]
    public string PaymentId { get; set; } = default!;

    [Required]
    [Range(0.01, double.MaxValue)]
    public decimal RefundAmount { get; set; }

    [MaxLength(500)]
    public string? RefundReason { get; set; }
}

// Payment Search DTO
public class PaymentSearchDto
{
    public string? UserId { get; set; }
    public int? OrderId { get; set; }
    public string? TransactionReference { get; set; }
    public DateTime? StartDate { get; set; }
    public DateTime? EndDate { get; set; }
    public decimal? MinAmount { get; set; }
    public decimal? MaxAmount { get; set; }
    public PaymentStatus? Status { get; set; }
    public string? PaymentMethod { get; set; }
    public string? SortBy { get; set; }
    public bool SortDescending { get; set; }
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 20;
}

// Payment Summary DTO
public class PaymentSummaryDto
{
    public decimal TotalProcessed { get; set; }
    public decimal TotalRefunded { get; set; }
    public int SuccessfulTransactions { get; set; }
    public int FailedTransactions { get; set; }
    public Dictionary<string, decimal> PaymentMethodBreakdown { get; set; } = new();
    public Dictionary<string, int> FailureReasonBreakdown { get; set; } = new();
    public decimal AverageTransactionValue { get; set; }
    public List<string> TopPaymentMethods { get; set; } = new();
}
