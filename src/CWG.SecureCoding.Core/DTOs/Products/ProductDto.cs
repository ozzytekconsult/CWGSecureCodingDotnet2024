using CWG.SecureCoding.Core.DTOs.Common;
using System.ComponentModel.DataAnnotations;

namespace CWG.SecureCoding.Core.DTOs.Products;

public class ProductDto : AuditableDto
{
    public int Id { get; set; }
    public string Name { get; set; } = default!;
    public string Description { get; set; } = default!;
    public decimal Price { get; set; }
    public int StockQuantity { get; set; }
    public string SKU { get; set; } = default!;
    public string Category { get; set; } = default!;
    public List<string> Tags { get; set; } = new();
    public bool IsActive { get; set; }
}

public class UpsertProductDto
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = default!;

    [Required]
    [MaxLength(2000)]
    public string Description { get; set; } = default!;

    [Required]
    [Range(0.01, double.MaxValue)]
    public decimal Price { get; set; }

    [Required]
    [Range(0, int.MaxValue)]
    public int StockQuantity { get; set; }

    [Required]
    [MaxLength(50)]
    public string SKU { get; set; } = default!;

    [Required]
    [MaxLength(100)]
    public string Category { get; set; } = default!;

    public List<string> Tags { get; set; } = new();

    public bool IsActive { get; set; } = true;
}

public class ProductStockDto
{
    public int ProductId { get; set; }
    public int StockQuantity { get; set; }
    public bool IsLowStock { get; set; }
    public int MinimumStockLevel { get; set; }
    public DateTime LastStockUpdate { get; set; }
}

public class ProductSearchDto
{
    public string? SearchTerm { get; set; }
    public string? Category { get; set; }
    public List<string>? Tags { get; set; }
    public decimal? MinPrice { get; set; }
    public decimal? MaxPrice { get; set; }
    public bool? IsActive { get; set; }
    public bool? InStock { get; set; }
    public string? SortBy { get; set; }
    public bool SortDescending { get; set; }
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 20;
}

public class BulkProductOperationDto
{
    [Required]
    public List<int> ProductIds { get; set; } = new();
    
    public decimal? PriceAdjustment { get; set; }
    public bool? IsPercentage { get; set; }
    public int? StockAdjustment { get; set; }
    public bool? SetActive { get; set; }
    public string? NewCategory { get; set; }
    public List<string>? AddTags { get; set; }
    public List<string>? RemoveTags { get; set; }
}
