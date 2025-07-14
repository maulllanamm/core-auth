using core_auth.Model;
using core_auth.Model.DTO;

namespace core_auth.Services.Interfaces;

public interface IAuthService
{
    Task<ApiResponse<object>> RegisterUserAsync(RegisterRequest request, string scheme, string host);
    Task<ApiResponse<object>>  LoginUserAsync(LoginRequest request, string ipAddress);
    Task<ApiResponse<object>> ConfirmEmailAsync(string userId, string token);
    Task<string> GenerateJwtTokenAsync(ApplicationUser user);

}