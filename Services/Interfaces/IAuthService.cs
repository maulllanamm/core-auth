using core_auth.Model.DTO;

namespace core_auth.Services.Interfaces;

public interface IAuthService
{
    Task<RegisterResponseDTO> RegisterUserAsync(RegisterRequestDTO request);
}