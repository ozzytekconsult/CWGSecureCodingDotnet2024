using CWG.SecureCoding.Core.DTOs.Common;
using CWG.SecureCoding.Core.DTOs.Users;
using System.Threading.Tasks;

namespace CWG.SecureCoding.Core.Interfaces.Services;

/// <summary>
/// Service interface for user management operations
/// </summary>
public interface IUserManagementService
{
    // Basic CRUD
    Task<ServiceResult<UserDto>> GetUserByIdAsync(string userId);
    Task<ServiceResult<UserDto>> CreateUserAsync(CreateUserDto dto);
    Task<ServiceResult<UserDto>> UpdateUserAsync(string userId, UpdateUserDto dto);
    Task<ServiceResult<bool>> DeleteUserAsync(string userId);

    // User Operations
    Task<ServiceResult<bool>> ChangePasswordAsync(string userId, ChangePasswordDto dto);
    Task<ServiceResult<bool>> ConfirmEmailAsync(string userId, string token);
    Task<ServiceResult<bool>> ResetPasswordAsync(string email);
    
    // Advanced Operations
    Task<ServiceResult<PagedResult<UserDto>>> SearchUsersAsync(UserSearchDto searchDto);
    Task<ServiceResult<bool>> DeactivateUserAsync(string userId);
    Task<ServiceResult<bool>> ReactivateUserAsync(string userId);
}
