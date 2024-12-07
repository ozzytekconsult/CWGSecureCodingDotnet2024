using CWG.SecureCoding.Core.DTOs.Common;
using CWG.SecureCoding.Core.Models;
using System.ComponentModel.DataAnnotations;

namespace CWG.SecureCoding.Core.DTOs.Orders;

// Response DTO
public class OrderDto : AuditableDto
{
    public string UserId { get; set; } = default!;
    public decimal TotalAmount { get; set; }
    public string Currency { get; set; } = default!;
    public string ShippingAddress { get; set; } = default!;
    public string BillingAddress { get; set; } = default!;
    public decimal ShippingCost { get; set; }
    public decimal TaxAmount { get; set; }
    public string? DiscountCode { get; set; }
    public decimal DiscountAmount { get; set; }
    public OrderStatus Status { get; set; }
    public List<OrderItemDto> Items { get; set; } = new();
    public decimal ComputedTotal { get; set; }
}

// Order Item DTO
public class OrderItemDto : BaseDto
{
    public int ProductId { get; set; }
    public string Name { get; set; } = default!;
    public int Quantity { get; set; }
    public decimal UnitPrice { get; set; }
    public decimal Discount { get; set; }
    public decimal Total { get; set; }
}

// Create Order DTO
public class CreateOrderDto
{
    [Required]
    public List<CreateOrderItemDto> Items { get; set; } = new();

    [Required]
    [MaxLength(500)]
    public string ShippingAddress { get; set; } = default!;

    [Required]
    [MaxLength(500)]
    public string BillingAddress { get; set; } = default!;

    [MaxLength(50)]
    public string? DiscountCode { get; set; }

    [Required]
    [RegularExpression(@"^[A-Z]{3}$")]
    public string Currency { get; set; } = "USD";
}

// Create Order Item DTO
public class CreateOrderItemDto
{
    [Required]
    public int ProductId { get; set; }

    [Required]
    [Range(1, int.MaxValue)]
    public int Quantity { get; set; }
}

// Update Order Status DTO
public class UpdateOrderStatusDto
{
    [Required]
    public OrderStatus NewStatus { get; set; }

    [MaxLength(500)]
    public string? StatusNote { get; set; }
}

// Order Search DTO
public class OrderSearchDto
{
    public string? UserId { get; set; }
    public DateTime? StartDate { get; set; }
    public DateTime? EndDate { get; set; }
    public decimal? MinAmount { get; set; }
    public decimal? MaxAmount { get; set; }
    public OrderStatus? Status { get; set; }
    public string? DiscountCode { get; set; }
    public string? SortBy { get; set; }
    public bool SortDescending { get; set; }
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 20;
}

// Order Summary DTO
public class OrderSummaryDto
{
    public int TotalOrders { get; set; }
    public decimal TotalRevenue { get; set; }
    public Dictionary<OrderStatus, int> OrdersByStatus { get; set; } = new();
    public Dictionary<string, decimal> RevenueByProduct { get; set; } = new();
    public List<string> TopProducts { get; set; } = new();
    public List<string> TopCustomers { get; set; } = new();
}
