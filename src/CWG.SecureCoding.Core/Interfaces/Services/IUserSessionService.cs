using CWG.SecureCoding.Core.DTOs.Common;
using CWG.SecureCoding.Core.DTOs.Security;
using System.Threading.Tasks;

namespace CWG.SecureCoding.Core.Interfaces.Services;

/// <summary>
/// Service interface for user session management and security operations.
/// </summary>
public interface IUserSessionService
{
    // Basic Operations
    Task<ServiceResult<UserSessionDto>> GetSessionAsync(string sessionId);
    Task<ServiceResult<UserSessionDto>> CreateSessionAsync(CreateSessionDto dto);
    Task<ServiceResult<UserSessionDto>> UpdateSessionAsync(UpdateSessionDto dto);
    Task<ServiceResult<bool>> EndSessionAsync(string sessionId);

    // Security Operations
    Task<ServiceResult<bool>> LogSecurityEventAsync(SessionSecurityEventDto eventDto);
    Task<ServiceResult<PagedResult<UserSessionDto>>> SearchSessionsAsync(SessionSearchDto searchDto);
    Task<ServiceResult<bool>> LockSessionAsync(string sessionId);
    Task<ServiceResult<bool>> UnlockSessionAsync(string sessionId);
}
