using CWG.SecureCoding.Core.DTOs.Common;
using CWG.SecureCoding.Core.DTOs.Products;
using System.Threading.Tasks;

namespace CWG.SecureCoding.Core.Interfaces.Services;

/// <summary>
/// Service interface for product management operations.
/// </summary>
public interface IProductService
{
    // Basic CRUD
    Task<ServiceResult<ProductDto>> GetProductByIdAsync(int productId);
    Task<ServiceResult<ProductDto>> CreateProductAsync(UpsertProductDto dto);
    Task<ServiceResult<ProductDto>> UpdateProductAsync(int productId, UpsertProductDto dto);
    Task<ServiceResult<bool>> DeleteProductAsync(int productId);

    // Advanced Operations
    Task<ServiceResult<PagedResult<ProductDto>>> SearchProductsAsync(ProductSearchDto searchDto);
    Task<ServiceResult<bool>> BulkUpdateProductsAsync(BulkProductOperationDto dto);
    Task<ServiceResult<ProductStockDto>> UpdateStockQuantityAsync(int productId, int quantity);
}
