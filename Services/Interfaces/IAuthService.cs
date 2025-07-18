using core_auth.Model;
using core_auth.Model.DTO;

namespace core_auth.Services.Interfaces;

public interface IAuthService
{
    Task<ApiResponse<object>> RegisterUserAsync(RegisterRequest request, string scheme, string host);
    Task<ApiResponse<LoginResponse>>  LoginUserAsync(LoginRequest request, string ipAddress);
    Task<ApiResponse<object>> ConfirmEmailAsync(Guid userId, string token);
    Task<string> GenerateJwtTokenAsync(ApplicationUser user);
    Task<ApiResponse<LoginResponse>> RefreshTokenAsync(string token, string ipAddress);
    string GenerateRefreshTokenValue();
    Task RemoveOldRefreshTokensAsync(Guid userId);
    Task<ApiResponse<object>> SendPasswordResetEmailAsync(string email, string scheme, string host);
    Task<ApiResponse<object>> ResetPasswordAsync(string email, string token, string newPassword);
    Task<ApiResponse<object>> RevokeRefreshTokenAsync(string token, string ipAddress);
    
    Task<ApiResponse<object>> CreateRoleAsync(string roleName);
    Task<ApiResponse<List<RoleResponse>>> GetAllRolesAsync();
    Task<ApiResponse<object>> AddUserToRoleAsync(Guid userId, string roleName);
    Task<ApiResponse<object>> RemoveUserFromRoleAsync(Guid userId, string roleName); 
    Task<ApiResponse<List<string>>> GetUserRolesAsync(Guid userId);
    Task<ApiResponse<object>> AddClaimToRoleAsync(Guid roleId, string claimType, string claimValue);
    Task<ApiResponse<object>> RemoveClaimFromRoleAsync(Guid roleId, string claimType, string claimValue);
    Task<ApiResponse<List<ClaimDto>>> GetRoleClaimsAsync(Guid roleId); 
    
    Task<ApiResponse<TwoFactorAuthSetupDto>> InitiateTwoFactorAuthSetupAsync(Guid userId);
    Task<ApiResponse<object>> VerifyAndEnableTwoFactorAuthAsync(Guid userId, string verificationCode);
    
    Task<ApiResponse<UserProfileResponse>> GetUserProfileAsync(Guid userId);
    Task<ApiResponse<object>> ChangePasswordAsync(Guid userId, ChangePasswordRequest request);
}