using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
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
    private readonly RoleManager<ApplicationRole> _roleManager;
    public AuthService(UserManager<ApplicationUser> userManager, IEmailService emailService, CoreAuthDbContext dbContext, SignInManager<ApplicationUser> signInManager, IOptions<JwtSettings> jwtSettings, RoleManager<ApplicationRole> roleManager)
    {
        _userManager = userManager;
        _emailService = emailService;
        _dbContext = dbContext;
        _signInManager = signInManager;
        _roleManager = roleManager;
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

        var creationResult = await _userManager.CreateAsync(user, request.Password);
        if (!creationResult.Succeeded)
        {
            var errors = creationResult.Errors.Select(e => e.Description).ToList();
            return ApiResponseFactory.Fail<object>("User registration failed.", errors);
        }

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var confirmationLink = $"{scheme}://{host}/api/auth/confirm-email?userId={user.Id}&token={Uri.EscapeDataString(token)}";

        var emailResult = await _emailService.SendEmailAsync(new EmailRequest
        {
            ToEmail = user.Email!,
            Subject = "Confirm Your Email Address",
            Body = $"Please confirm your account by clicking this link: <a href='{confirmationLink}'>link</a>",
            IsHtml = true
        });

        if (!emailResult.Success)
        {
            return ApiResponseFactory.SuccessWithWarning<object>(
                null,
                "User registered. Failed to send confirmation email. Please request another one later.",
                emailResult.Errors
            );
        }

        return ApiResponseFactory.Success<object>(
            null,
            "Registration successful! Please verify your email address to complete the process."
        );

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
    
    public async Task<ApiResponse<LoginResponse>> LoginUserAsync(LoginRequest request, string ipAddress)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
            return ApiResponseFactory.Fail<LoginResponse>("Invalid login credentials.");

        if (!user.EmailConfirmed)
            return ApiResponseFactory.Fail<LoginResponse>("Your email has not been confirmed yet. Please check your inbox.");

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
        if (!result.Succeeded)
        {
            if (result.IsLockedOut)
                return ApiResponseFactory.Fail<LoginResponse>("Account locked out due to multiple failed login attempts.");
            if (result.IsNotAllowed)
                return ApiResponseFactory.Fail<LoginResponse>("Login not allowed. Please confirm your email or contact support.");
            if (result.RequiresTwoFactor)
                return ApiResponseFactory.Fail<LoginResponse>("Two-factor authentication required.");
        
            return ApiResponseFactory.Fail<LoginResponse>("Invalid login credentials.");
        }

        user.LastLoginDate = DateTimeOffset.UtcNow;
        await _userManager.UpdateAsync(user);

        await RevokeOldRefreshTokensForUser(user.Id);

        var accessToken = await GenerateJwtTokenAsync(user);
        var refreshToken = await GenerateAndSaveRefreshTokenAsync(user.Id, ipAddress);

        var response = new LoginResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken.Token,
            LastLoginDate = user.LastLoginDate
        };

        return ApiResponseFactory.Success(response, "Login successful.");
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
    
    public async Task<ApiResponse<object>> SendPasswordResetEmailAsync(string email, string scheme, string host)
    {
        var user = await _userManager.FindByEmailAsync(email);
        var isConfirmed = user != null && await _userManager.IsEmailConfirmedAsync(user);

        if (!isConfirmed)
        {
            return ApiResponseFactory.Success<object>(null, "If an account with that email exists, a password reset link has been sent.");
        }

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var callbackUrl = $"{scheme}://{host}/api/auth/reset-password?token={Uri.EscapeDataString(token)}&email={Uri.EscapeDataString(user.Email!)}";

        var emailSendResult = await _emailService.SendEmailAsync(new EmailRequest
        {
            ToEmail = user.Email!,
            Subject = "Reset Your Password",
            Body = $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>",
            IsHtml = true
        });

        if (!emailSendResult.Success)
        {
            return ApiResponseFactory.Fail<object>("Failed to send password reset email. Please try again later.", emailSendResult.Errors);
        }

        return ApiResponseFactory.Success<object>(null, "If an account with that email exists, a password reset link has been sent.");
    }
    
    public async Task<ApiResponse<object>> ResetPasswordAsync(string email, string token, string newPassword)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return ApiResponseFactory.Fail<object>("User not found.");
        }

        var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
        if (result.Succeeded)
        {
            return ApiResponseFactory.Success<object>(null, "Password has been reset successfully.");
        }

        return ApiResponseFactory.Fail<object>("Failed to reset password.", result.Errors.Select(e => e.Description).ToList());
    }
    
    public async Task<ApiResponse<object>> RevokeRefreshTokenAsync(string token, string ipAddress)
    {
        var refreshToken = await _dbContext.RefreshTokens.SingleOrDefaultAsync(rt => rt.Token == token);

        if (refreshToken == null)
        {
            return ApiResponseFactory.Fail<object>("Invalid refresh token.");
        }

        if (refreshToken.IsExpired)
        {
            return ApiResponseFactory.Fail<object>("Refresh token already expired.");
        }

        if (refreshToken.Revoked != null)
        {
            return ApiResponseFactory.Fail<object>("Refresh token already revoked.");
        }

        refreshToken.Revoked = DateTimeOffset.UtcNow;
        refreshToken.ReasonRevoked = "Manual Revocation";
        refreshToken.RemoteIpAddress = ipAddress;

        await _dbContext.SaveChangesAsync();

        return ApiResponseFactory.Success<object>(null, "Refresh token revoked successfully.");
    }

    public async Task<ApiResponse<object>> CreateRoleAsync(string roleName)
    {
        if (string.IsNullOrWhiteSpace(roleName))
        {
            return ApiResponseFactory.Fail<object>("Role name cannot be empty.");
        }

        if (await _roleManager.RoleExistsAsync(roleName))
        {
            return ApiResponseFactory.Fail<object>($"Role '{roleName}' already exists.");
        }

        var role = new ApplicationRole { Name = roleName };
        var result = await _roleManager.CreateAsync(role);

        if (result.Succeeded)
        {
            return ApiResponseFactory.Success<object>(null, $"Role '{roleName}' created successfully.");
        }

        return ApiResponseFactory.Fail<object>("Failed to create role.", result.Errors.Select(e => e.Description).ToList());
    }

    public async Task<ApiResponse<List<RoleResponse>>> GetAllRolesAsync()
    {
        var roles = await _roleManager.Roles
            .Select(r => new RoleResponse()
            {
                Id = r.Id,
                Name = r.Name! 
            })
            .ToListAsync();

        if (roles.Any())
        {
            return ApiResponseFactory.Success(roles, "Roles retrieved successfully.");
        }

        return ApiResponseFactory.Success(roles, "No roles found."); 
    }
    
    public async Task<ApiResponse<object>> AddUserToRoleAsync(Guid userId, string roleName) // Perubahan di sini: Guid userId
    {
        if (string.IsNullOrWhiteSpace(roleName))
        {
            return ApiResponseFactory.Fail<object>("Role name cannot be empty.");
        }

        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user == null)
        {
            return ApiResponseFactory.Fail<object>($"User with ID '{userId}' not found.");
        }

        if (!await _roleManager.RoleExistsAsync(roleName))
        {
            return ApiResponseFactory.Fail<object>($"Role '{roleName}' does not exist.");
        }

        if (await _userManager.IsInRoleAsync(user, roleName))
        {
            return ApiResponseFactory.Fail<object>($"User '{user.UserName}' is already in role '{roleName}'.");
        }

        var result = await _userManager.AddToRoleAsync(user, roleName);

        if (result.Succeeded)
        {
            await _userManager.UpdateSecurityStampAsync(user);
            return ApiResponseFactory.Success<object>(null, $"User '{user.UserName}' successfully added to role '{roleName}'.");
        }

        return ApiResponseFactory.Fail<object>("Failed to add user to role.", result.Errors.Select(e => e.Description).ToList());
    }

    public async Task<ApiResponse<object>> RemoveUserFromRoleAsync(Guid userId, string roleName)
    {
        if (string.IsNullOrWhiteSpace(roleName))
        {
            return ApiResponseFactory.Fail<object>("Role name cannot be empty.");
        }

        var user = await _userManager.FindByIdAsync(userId.ToString()); 
        if (user == null)
        {
            return ApiResponseFactory.Fail<object>($"User with ID '{userId}' not found.");
        }

        if (!await _roleManager.RoleExistsAsync(roleName))
        {
            return ApiResponseFactory.Fail<object>($"Role '{roleName}' does not exist.");
        }

        if (!await _userManager.IsInRoleAsync(user, roleName))
        {
            return ApiResponseFactory.Fail<object>($"User '{user.UserName}' is not in role '{roleName}'.");
        }

        var result = await _userManager.RemoveFromRoleAsync(user, roleName);

        if (result.Succeeded)
        {
            // Penting: Setelah menghapus peran, SecurityStamp akan berubah.
            // Ini akan menginvalidasi JWT lama dan memaksa user untuk login ulang
            // agar JWT baru mereka tidak lagi mengandung klaim peran yang dihapus.
            await _userManager.UpdateSecurityStampAsync(user);

            return ApiResponseFactory.Success<object>(null, $"User '{user.UserName}' successfully removed from role '{roleName}'.");
        }

        return ApiResponseFactory.Fail<object>("Failed to remove user from role.", result.Errors.Select(e => e.Description).ToList());
    }
    
    public async Task<ApiResponse<List<string>>> GetUserRolesAsync(Guid userId)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString()); 
        if (user == null)
        {
            return ApiResponseFactory.Fail<List<string>>($"User with ID '{userId}' not found.");
        }

        var roles = await _userManager.GetRolesAsync(user);

        if (roles.Any())
        {
            return ApiResponseFactory.Success(roles.ToList(), $"Roles for user '{user.UserName}' retrieved successfully.");
        }

        return ApiResponseFactory.Success(new List<string>(), $"User '{user.UserName}' has no roles assigned.");
    }
    
    public async Task<ApiResponse<object>> AddClaimToRoleAsync(Guid roleId, string claimType, string claimValue)
    {
        if (string.IsNullOrWhiteSpace(claimType) || string.IsNullOrWhiteSpace(claimValue))
        {
            return ApiResponseFactory.Fail<object>("Claim type and value cannot be empty.");
        }

        var role = await _roleManager.FindByIdAsync(roleId.ToString()); 
        if (role == null)
        {
            return ApiResponseFactory.Fail<object>($"Role with ID '{roleId}' not found.");
        }

        var existingClaims = await _roleManager.GetClaimsAsync(role);
        if (existingClaims.Any(c => c.Type == claimType && c.Value == claimValue))
        {
            return ApiResponseFactory.Fail<object>($"Claim '{claimType}:{claimValue}' already exists for role '{role.Name}'.");
        }

        var claim = new Claim(claimType, claimValue);
        var result = await _roleManager.AddClaimAsync(role, claim);

        if (result.Succeeded)
        {
            return ApiResponseFactory.Success<object>(null, $"Claim '{claimType}:{claimValue}' added to role '{role.Name}' successfully.");
        }

        return ApiResponseFactory.Fail<object>("Failed to add claim to role.", result.Errors.Select(e => e.Description).ToList());
    }
    public async Task<ApiResponse<object>> RemoveClaimFromRoleAsync(Guid roleId, string claimType, string claimValue)
    {
        if (string.IsNullOrWhiteSpace(claimType) || string.IsNullOrWhiteSpace(claimValue))
        {
            return ApiResponseFactory.Fail<object>("Claim type and value cannot be empty.");
        }

        var role = await _roleManager.FindByIdAsync(roleId.ToString());
        if (role == null)
        {
            return ApiResponseFactory.Fail<object>($"Role with ID '{roleId}' not found.");
        }

        var claimToRemove = new Claim(claimType, claimValue);

        var existingClaims = await _roleManager.GetClaimsAsync(role);
        if (!existingClaims.Any(c => c.Type == claimType && c.Value == claimValue))
        {
            return ApiResponseFactory.Fail<object>($"Claim '{claimType}:{claimValue}' does not exist for role '{role.Name}'.");
        }

        var result = await _roleManager.RemoveClaimAsync(role, claimToRemove);

        if (result.Succeeded)
        {
            return ApiResponseFactory.Success<object>(null, $"Claim '{claimType}:{claimValue}' removed from role '{role.Name}' successfully.");
        }

        return ApiResponseFactory.Fail<object>("Failed to remove claim from role.", result.Errors.Select(e => e.Description).ToList());
    }
    
    public async Task<ApiResponse<List<ClaimDto>>> GetRoleClaimsAsync(Guid roleId)
    {
        var role = await _roleManager.FindByIdAsync(roleId.ToString()); 
        if (role == null)
        {
            return ApiResponseFactory.Fail<List<ClaimDto>>($"Role with ID '{roleId}' not found.");
        }

        var claims = await _roleManager.GetClaimsAsync(role);

        var claimDtos = claims.Select(c => new ClaimDto
        {
            Type = c.Type,
            Value = c.Value
        }).ToList();

        if (claimDtos.Any())
        {
            return ApiResponseFactory.Success(claimDtos, $"Claims for role '{role.Name}' retrieved successfully.");
        }

        return ApiResponseFactory.Success(claimDtos, $"Role '{role.Name}' has no claims assigned."); 
    }
    
    public async Task<ApiResponse<TwoFactorAuthSetupDto>> InitiateTwoFactorAuthSetupAsync(Guid userId)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user == null)
        {
            return ApiResponseFactory.Fail<TwoFactorAuthSetupDto>($"User with ID '{userId}' not found.");
        }

        if (await _userManager.GetTwoFactorEnabledAsync(user))
        {
            return ApiResponseFactory.Fail<TwoFactorAuthSetupDto>("Two-Factor Authentication is already enabled for this user.");
        }

        var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(unformattedKey))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        var appName = _jwtSettings.Issuer ?? "YourAppName"; 
        var email = await _userManager.GetEmailAsync(user);

        var authenticatorUri = $"otpauth://totp/{UrlEncoder.Default.Encode(appName)}:{UrlEncoder.Default.Encode(email ?? user.UserName!)}?secret={unformattedKey}&issuer={UrlEncoder.Default.Encode(appName)}";

        var setupDto = new TwoFactorAuthSetupDto
        {
            SharedKey = unformattedKey!, 
            AuthenticatorUri = authenticatorUri
        };

        return ApiResponseFactory.Success(setupDto, "2FA setup initiated. Please configure your authenticator app.");
    }

    public async Task<ApiResponse<object>> VerifyAndEnableTwoFactorAuthAsync(Guid userId, string verificationCode)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user == null)
        {
            return ApiResponseFactory.Fail<object>($"User with ID '{userId}' not found.");
        }

        if (await _userManager.GetTwoFactorEnabledAsync(user))
        {
            return ApiResponseFactory.Fail<object>("Two-Factor Authentication is already enabled for this user.");
        }

        var isCodeValid = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

        if (!isCodeValid)
        {
            return ApiResponseFactory.Fail<object>("Invalid verification code. Please try again.");
        }

        var setResult = await _userManager.SetTwoFactorEnabledAsync(user, true);
        if (!setResult.Succeeded)
        {
            return ApiResponseFactory.Fail<object>("Failed to enable Two-Factor Authentication.", setResult.Errors.Select(e => e.Description).ToList());
        }

        var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10); // Generate 10 kode pemulihan

        return ApiResponseFactory.Success<object>(new { RecoveryCodes = recoveryCodes }, "Two-Factor Authentication enabled successfully. Please save your recovery codes.");
    }

}