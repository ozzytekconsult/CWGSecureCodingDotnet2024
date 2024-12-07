using CWG.SecureCoding.Core.DTOs.Common;
using CWG.SecureCoding.Core.DTOs.Documents;
using System.Threading.Tasks;

namespace CWG.SecureCoding.Core.Interfaces.Services;

/// <summary>
/// Service interface for secure document management operations
/// </summary>
public interface IDocumentService
{
    // Basic CRUD Operations
    Task<ServiceResult<DocumentDto>> GetDocumentByIdAsync(int documentId);
    Task<ServiceResult<DocumentDto>> UploadDocumentAsync(string userId, UploadDocumentDto dto, Stream fileStream);
    Task<ServiceResult<DocumentDto>> UpdateDocumentAsync(int documentId, UpdateDocumentDto dto);
    Task<ServiceResult<bool>> DeleteDocumentAsync(int documentId);

    // Document Access
    Task<ServiceResult<Stream>> DownloadDocumentAsync(int documentId, string userId);

    

    // Search and Management
    Task<ServiceResult<PagedResult<DocumentDto>>> SearchDocumentsAsync(DocumentSearchDto searchDto);
   
}
