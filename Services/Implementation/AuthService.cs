using core_auth.Data;
using core_auth.Model;
using core_auth.Model.DTO;
using core_auth.Services.Interfaces;
using Microsoft.AspNetCore.Identity;

namespace core_auth.Services.Implementation;

public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IEmailService _emailService;
    private readonly CoreAuthDbContext _dbContext;
    public AuthService(UserManager<ApplicationUser> userManager, IEmailService emailService, CoreAuthDbContext dbContext, SignInManager<ApplicationUser> signInManager)
    {
        _userManager = userManager;
        _emailService = emailService;
        _dbContext = dbContext;
        _signInManager = signInManager;
    }
    
    public async Task<RegisterResponse> RegisterUserAsync(RegisterRequest request, string scheme, string host)
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
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmationLink = $"{scheme}://{host}/api/Auth/ConfirmEmail?userId={user.Id}&token={Uri.EscapeDataString(token)}";

            // Panggil IEmailSender untuk mengirim email DI SINI (di dalam service)
            var emailSendResult = await _emailService.SendEmailAsync(new EmailRequest
            {
                ToEmail = user.Email!,
                Subject = "Confirm Your Email Address",
                Body = $"Please confirm your account by clicking this link: <a href='{confirmationLink}'>link</a>",
                IsHtml = true
            });
            
            if (!emailSendResult.IsSuccess)
            {
                return new RegisterResponse
                {
                    IsSuccess = true,
                    Message = "User registered. Failed to send confirmation email. Please request another one later.",
                    Errors = emailSendResult.Errors 
                };
            }
            return new RegisterResponse
            {
                IsSuccess = true,
                Message = "User registered successfully."
            };
        }

        return new RegisterResponse
        {
            IsSuccess = false,
            Errors = result.Errors.Select(e => e.Description).ToList()
        };
    }
    
    public async Task<LoginResponse> LoginUserAsync(LoginRequest request, string ipAddress)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            return new LoginResponse { IsSuccess = false, Message = "Invalid login credentials." };
        }

        if (!user.EmailConfirmed)
        {
            return new LoginResponse { IsSuccess = false, Message = "Your email has not been confirmed yet. Please check your inbox." };
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

        if (result.Succeeded)
        {
            user.LastLoginDate = DateTimeOffset.UtcNow;
            await _userManager.UpdateAsync(user);

            return new LoginResponse
            {
                IsSuccess = true,
                Message = "Login successful.",
            };
        }

        if (result.IsLockedOut)
        {
            return new LoginResponse { IsSuccess = false, Message = "Account locked out due to multiple failed login attempts. Please try again later." };
        }

        return new LoginResponse { IsSuccess = false, Message = "Invalid login credentials." };
    }
}