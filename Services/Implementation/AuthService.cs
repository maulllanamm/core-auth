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
    
    public async Task<ApiResponse<object>> RegisterUserAsync(RegisterRequest request, string scheme, string host)
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

            var emailSendResult = await _emailService.SendEmailAsync(new EmailRequest
            {
                ToEmail = user.Email!,
                Subject = "Confirm Your Email Address",
                Body = $"Please confirm your account by clicking this link: <a href='{confirmationLink}'>link</a>",
                IsHtml = true
            });
            
            if (!emailSendResult.Success)
            {
                return ApiResponseFactory.SuccessWithWarning<object>(
                    null,
                    "User registered. Failed to send confirmation email. Please request another one later.",
                    emailSendResult.Errors
                );
            }
            return ApiResponseFactory.Success<object>(null, "User registered successfully.");
        }

        var errors = result.Errors.Select(e => e.Description).ToList();
        return ApiResponseFactory.Fail<object>("User registration failed.", errors);
    }
    
    public async Task<ApiResponse<object>> LoginUserAsync(LoginRequest request, string ipAddress)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            return ApiResponseFactory.Fail<object>("Invalid login credentials.");
        }

        if (!user.EmailConfirmed)
        {
            return ApiResponseFactory.Fail<object>("Your email has not been confirmed yet. Please check your inbox.");
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

        if (result.Succeeded)
        {
            user.LastLoginDate = DateTimeOffset.UtcNow;
            await _userManager.UpdateAsync(user);


            var loginResult = new LoginResponse
            {
                LastLoginDate = user.LastLoginDate
            };

            return ApiResponseFactory.Success<object>(loginResult, "Login successful.");
        }

        if (result.IsLockedOut)
        {
            return ApiResponseFactory.Fail<object>("Account locked out due to multiple failed login attempts. Please try again later.");
        }

        return ApiResponseFactory.Fail<object>("Invalid login credentials.");
    }

}