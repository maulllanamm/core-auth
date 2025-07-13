using core_auth.Model.DTO;

namespace core_auth.Services.Interfaces;

public interface IAuthService
{
    Task<RegisterResponse> RegisterUserAsync(RegisterRequest request, string scheme, string host);
    Task<LoginResponse> LoginUserAsync(LoginRequest request, string ipAddress); 

 
}