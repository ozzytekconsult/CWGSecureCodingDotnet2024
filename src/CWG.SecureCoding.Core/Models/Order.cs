using System.ComponentModel.DataAnnotations;
using CWG.SecureCoding.Core.Models.Identity;

namespace CWG.SecureCoding.Core.Models;

/// <summary>
/// Represents an order in the system
/// </summary>
public class Order : BaseEntity
{
    [Required]
    public string UserId { get; set; } = default!;
    public virtual ApplicationUser User { get; set; } = default!;

    [Required]
    [Range(0.01, double.MaxValue)]
    public decimal TotalAmount { get; set; }

    [Required]
    [RegularExpression(@"^[A-Z]{3}$")]
    public string Currency { get; set; } = "USD";

    [Required]
    [MaxLength(500)]
    public string ShippingAddress { get; set; } = default!;

    [Required]
    [MaxLength(500)]
    public string BillingAddress { get; set; } = default!;

    [Required]
    [Range(0, double.MaxValue)]
    public decimal ShippingCost { get; set; }

    [Required]
    [Range(0, double.MaxValue)]
    public decimal TaxAmount { get; set; }

    [MaxLength(50)]
    public string? DiscountCode { get; set; }

    [Range(0, double.MaxValue)]
    public decimal DiscountAmount { get; set; }

    [Required]
    public OrderStatus Status { get; set; } = OrderStatus.Pending;

    // Navigation properties
    public virtual ICollection<OrderItem> Items { get; set; } = new List<OrderItem>();
    public virtual ICollection<Payment> Payments { get; set; } = new List<Payment>();

    // Computed total
    public decimal ComputedTotal => TotalAmount + ShippingCost + TaxAmount - DiscountAmount;
}

public enum OrderStatus
{
    Pending = 0,
    Confirmed = 1,
    Processing = 2,
    Shipped = 3,
    Delivered = 4,
    Cancelled = 5,
    Refunded = 6
}
