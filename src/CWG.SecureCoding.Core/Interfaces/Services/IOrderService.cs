using CWG.SecureCoding.Core.DTOs.Common;
using CWG.SecureCoding.Core.DTOs.Orders;
using System.Threading.Tasks;

namespace CWG.SecureCoding.Core.Interfaces.Services;

/// <summary>
/// Service interface for order management operations.
/// </summary>
public interface IOrderService
{
    // Basic CRUD
    Task<ServiceResult<OrderDto>> GetOrderByIdAsync(int orderId);
    Task<ServiceResult<OrderDto>> CreateOrderAsync(string userId, CreateOrderDto dto);
    Task<ServiceResult<OrderDto>> UpdateOrderStatusAsync(int orderId, UpdateOrderStatusDto dto);
    Task<ServiceResult<bool>> CancelOrderAsync(int orderId);

    // Advanced Operations
    Task<ServiceResult<PagedResult<OrderDto>>> SearchOrdersAsync(OrderSearchDto searchDto);
    Task<ServiceResult<OrderSummaryDto>> GetOrderSummaryAsync(string userId);
}
