using CWG.SecureCoding.Core.DTOs.Common;
using CWG.SecureCoding.Core.DTOs.Payments;
using System.Threading.Tasks;

namespace CWG.SecureCoding.Core.Interfaces.Services;

/// <summary>
/// Service interface for payment processing operations.
/// </summary>
public interface IPaymentService
{
    // Basic Operations
    Task<ServiceResult<PaymentDto>> GetPaymentByIdAsync(string paymentId);
    Task<ServiceResult<PaymentDto>> ProcessPaymentAsync(string userId, ProcessPaymentDto dto);
    Task<ServiceResult<PaymentDto>> ProcessRefundAsync(string userId, RefundPaymentDto dto);

    // Advanced Operations
    Task<ServiceResult<PagedResult<PaymentDto>>> SearchPaymentsAsync(PaymentSearchDto searchDto);
    Task<ServiceResult<PaymentSummaryDto>> GetPaymentSummaryAsync(string userId);
}
