using System.ComponentModel.DataAnnotations;

namespace CWG.SecureCoding.Core.Models;

/// <summary>
/// Represents an item in an order
/// </summary>
public class OrderItem : BaseEntity
{
    [Required]
    public int OrderId { get; set; }
    public virtual Order Order { get; set; } = default!;

    [Required]
    public int ProductId { get; set; }
    public virtual Product Product { get; set; } = default!;

    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = default!;

    [Required]
    [Range(1, int.MaxValue)]
    public int Quantity { get; set; }

    [Required]
    [Range(0.01, double.MaxValue)]
    public decimal UnitPrice { get; set; }

    [Range(0, double.MaxValue)]
    public decimal Discount { get; set; }

    // Computed total
    public decimal Total => (UnitPrice * Quantity) - Discount;
}
