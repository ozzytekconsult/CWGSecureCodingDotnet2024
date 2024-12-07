using System.ComponentModel.DataAnnotations;

namespace CWG.SecureCoding.Core.Models;

/// <summary>
/// Represents a product in the system
/// </summary>
public class Product : BaseEntity
{
    [Required]
    [MaxLength(200)]
    [RegularExpression(@"^[\w\s-'.&()]{1,200}$", ErrorMessage = "Product name contains invalid characters")]
    public string Name { get; set; } = default!;
    
    [MaxLength(2000)]
    public string? Description { get; set; }
    
    [Required]
    [Range(0.01, 1000000)]
    [RegularExpression(@"^\d{1,8}(\.\d{1,2})?$")]
    public decimal Price { get; set; }

    [Required]
    [Range(0, int.MaxValue)]
    public int StockQuantity { get; set; }

    [Required]
    [MaxLength(50)]
    [RegularExpression(@"^[A-Z0-9-]{1,50}$")]
    public string SKU { get; set; } = default!;

    [Required]
    [MaxLength(100)]
    public string Category { get; set; } = default!;

    [MaxLength(50)]
    public string[]? Tags { get; set; }

    [Required]
    public bool IsActive { get; set; } = true;

    // Navigation properties
    public virtual ICollection<OrderItem> OrderItems { get; set; } = new List<OrderItem>();

    // Audit fields
    [MaxLength(50)]
    public string? LastModifiedBy { get; set; }
    
    public DateTimeOffset? LastModifiedAt { get; set; }
}
