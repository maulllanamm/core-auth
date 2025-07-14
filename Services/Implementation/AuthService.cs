using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using core_auth.Data;
using core_auth.Model;
using core_auth.Model.DTO;
using core_auth.Services.Interfaces;
using core_auth.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
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
    
    public async Task<ApiResponse<object>> ConfirmEmailAsync(Guid userId, string token)
    {
        if (userId == Guid.Empty || string.IsNullOrEmpty(token))
        {
            return ApiResponseFactory.Fail<object>("Invalid email confirmation link.");
        }

        var user = await _userManager.FindByIdAsync(userId.ToString());
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
            await RevokeOldRefreshTokensForUser(user.Id);

            var accessToken = await GenerateJwtTokenAsync(user);
            var refreshToken = await GenerateAndSaveRefreshTokenAsync(user.Id, ipAddress);
            
            var loginResult = new LoginResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken.Token,
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
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email ?? ""), 
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.UserName ?? user.Email ?? "") 
        };

        var roles = await _userManager.GetRolesAsync(user);
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

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
    
    public async Task<ApiResponse<LoginResponse>> RefreshTokenAsync(string token, string ipAddress)
    {
        var refreshToken = await _dbContext.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.Token == token);

        if (refreshToken == null || !refreshToken.IsActive)
        {
            if (refreshToken?.User != null)
            {
                await RevokeOldRefreshTokensForUser(refreshToken.User.Id);
            }

            return ApiResponseFactory.Fail<LoginResponse>("Invalid or expired refresh token.");
        }
        // Revoke old token
        refreshToken.Revoked = DateTimeOffset.UtcNow;
        refreshToken.ReasonRevoked = "Rotated by refresh";
    
        var newRefreshToken = await GenerateAndSaveRefreshTokenAsync(refreshToken.UserId, ipAddress);
        refreshToken.ReplacedByToken = newRefreshToken.Token;

        var accessToken = await GenerateJwtTokenAsync(refreshToken.User);

        await _dbContext.SaveChangesAsync();

        var response = new LoginResponse
        {
            AccessToken = accessToken,
            RefreshToken = newRefreshToken.Token,
        };

        return ApiResponseFactory.Success(response, "Token refreshed successfully.");
    }
    
    private async Task RevokeOldRefreshTokensForUser(Guid userId)
    {
        var tokens = await _dbContext.RefreshTokens
            .Where(rt => rt.UserId == userId && rt.Revoked == null && rt.Expires <= DateTimeOffset.UtcNow)
            .ToListAsync();

        foreach (var token in tokens)
        {
            token.Revoked = DateTimeOffset.UtcNow;
            token.ReasonRevoked = "Expired or replaced during login";
        }
    }
    
    public string GenerateRefreshTokenValue()
    {
        var randomNumber = new byte[64]; 
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    private async Task<RefreshToken> GenerateAndSaveRefreshTokenAsync(Guid userId, string ipAddress)
    {
        var refreshToken = new RefreshToken
        {
            Token = GenerateRefreshTokenValue(),
            Expires = DateTimeOffset.UtcNow.AddDays(7), 
            Created = DateTimeOffset.UtcNow,
            UserId = userId,
            RemoteIpAddress = ipAddress
        };

        _dbContext.RefreshTokens.Add(refreshToken);
        await _dbContext.SaveChangesAsync();
        return refreshToken;
    }

    public async Task RemoveOldRefreshTokensAsync(Guid userId)
    {
        var oldTokens = await _dbContext.RefreshTokens
            .Where(rt => rt.UserId == userId && (rt.Revoked != null || rt.Expires <= DateTimeOffset.UtcNow))
            .ToListAsync();

        _dbContext.RefreshTokens.RemoveRange(oldTokens);
        await _dbContext.SaveChangesAsync();
    }
}