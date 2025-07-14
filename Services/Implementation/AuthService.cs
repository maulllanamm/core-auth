using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using core_auth.Data;
using core_auth.Model;
using core_auth.Model.DTO;
using core_auth.Services.Interfaces;
using core_auth.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace core_auth.Services.Implementation;

public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IEmailService _emailService;
    private readonly CoreAuthDbContext _dbContext;
    private readonly JwtSettings _jwtSettings;
    public AuthService(UserManager<ApplicationUser> userManager, IEmailService emailService, CoreAuthDbContext dbContext, SignInManager<ApplicationUser> signInManager, IOptions<JwtSettings> jwtSettings)
    {
        _userManager = userManager;
        _emailService = emailService;
        _dbContext = dbContext;
        _signInManager = signInManager;
        _jwtSettings = jwtSettings.Value;
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
            var confirmationLink = $"{scheme}://{host}/api/auth/confirm-email?userId={user.Id}&token={Uri.EscapeDataString(token)}";

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
    
    public async Task<ApiResponse<object>> ConfirmEmailAsync(string userId, string token)
    {
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
        {
            return ApiResponseFactory.Fail<object>("Invalid email confirmation link.");
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return ApiResponseFactory.Fail<object>($"User with ID '{userId}' not found.");
        }
        var result = await _userManager.ConfirmEmailAsync(user, token);

        if (result.Succeeded)
        {
            return ApiResponseFactory.Success<object>(null, "Email confirmed successfully. You can now login.");
        }

        return ApiResponseFactory.Fail<object>("Error confirming your email.", result.Errors.Select(e => e.Description).ToList());
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

            var jwtToken = await GenerateJwtTokenAsync(user);

            var loginResult = new LoginResponse
            {
                AccessToken = jwtToken,
                LastLoginDate = user.LastLoginDate
            };

            return ApiResponseFactory.Success<object>(loginResult, "Login successful.");
        }

        if (result.IsLockedOut)
        {
            return ApiResponseFactory.Fail<object>("Account locked out due to multiple failed login attempts. Please try again later.");
        }
        if (result.IsNotAllowed)
        {
            return ApiResponseFactory.Fail<object>("Login not allowed. Please confirm your email/phone or contact support.");
        }
        if (result.RequiresTwoFactor)
        {
            return ApiResponseFactory.Fail<object>("Two-factor authentication required. Please proceed with 2FA verification.");
        }
        return ApiResponseFactory.Fail<object>("Invalid login credentials.");
    }
    
    public async Task<string> GenerateJwtTokenAsync(ApplicationUser user)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email ?? ""), 
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Name, user.UserName ?? user.Email ?? "") 
        };

        var roles = await _userManager.GetRolesAsync(user);
        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expires = DateTime.Now.AddMinutes(_jwtSettings.ExpireMinutes);

        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: claims,
            expires: expires,
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

}