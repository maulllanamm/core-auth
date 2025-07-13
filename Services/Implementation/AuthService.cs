using core_auth.Model;
using core_auth.Model.DTO;
using core_auth.Services.Interfaces;
using Microsoft.AspNetCore.Identity;

namespace core_auth.Services.Implementation;

public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;

    public AuthService(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }
    
    public async Task<RegisterResponseDTO> RegisterUserAsync(RegisterRequestDTO request)
    {
        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
            CreatedDate = DateTimeOffset.UtcNow,
            EmailConfirmed = false
        };

        var result = await _userManager.CreateAsync(user, request.Password);

        if (result.Succeeded)
        {
            
            return new RegisterResponseDTO
            {
                IsSuccess = true,
                Message = "User registered successfully."
            };
        }

        return new RegisterResponseDTO
        {
            IsSuccess = false,
            Errors = result.Errors.Select(e => e.Description).ToList()
        };
    }
}