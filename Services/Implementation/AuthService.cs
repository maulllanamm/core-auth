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
    private readonly ILogger<AuthService> _logger;
    public AuthService(UserManager<ApplicationUser> userManager, IEmailService emailService, CoreAuthDbContext dbContext, SignInManager<ApplicationUser> signInManager, IOptions<JwtSettings> jwtSettings, RoleManager<ApplicationRole> roleManager, ILogger<AuthService> logger)
    {
        _userManager = userManager;
        _emailService = emailService;
        _dbContext = dbContext;
        _signInManager = signInManager;
        _roleManager = roleManager;
        _logger = logger;
        _jwtSettings = jwtSettings.Value;
    }
    
    public async Task<ApiResponse<object>> RegisterUserAsync(RegisterRequest request, string scheme, string host)
    {
        _logger.LogInformation("User registration attempt for email: {Email}", request.Email);

        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
            CreatedDate = DateTimeOffset.UtcNow,
            EmailConfirmed = false
        };

        try
        {
            var creationResult = await _userManager.CreateAsync(user, request.Password);
            if (!creationResult.Succeeded)
            {
                var errors = creationResult.Errors.Select(e => e.Description).ToList();
                _logger.LogWarning("User registration failed for email: {Email}. Errors: {Errors}", request.Email, string.Join(", ", errors));
                return ApiResponseFactory.Fail<object>("User registration failed.", errors);
            }

            _logger.LogInformation("User created successfully: {Email}, generating confirmation email...", request.Email);

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
                _logger.LogWarning("Confirmation email failed to send to: {Email}. Errors: {Errors}", request.Email, string.Join(", ", emailResult.Errors));
                return ApiResponseFactory.SuccessWithWarning<object>(
                    null,
                    "User registered. Failed to send confirmation email. Please request another one later.",
                    emailResult.Errors
                );
            }

            _logger.LogInformation("Registration and email confirmation sent successfully to: {Email}", request.Email);
            return ApiResponseFactory.Success<object>(
                null,
                "Registration successful! Please verify your email address to complete the process."
            );
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An exception occurred during user registration for email: {Email}", request.Email);
            throw; // atau return ApiResponseFactory.Fail<object>("Unexpected error occurred.") jika ingin tangani di sini
        }
    }


    
    public async Task<ApiResponse<object>> ConfirmEmailAsync(Guid userId, string token)
    {
        _logger.LogInformation("Email confirmation attempt. UserId: {UserId}", userId);

        if (userId == Guid.Empty || string.IsNullOrEmpty(token))
        {
            _logger.LogWarning("Email confirmation failed. Reason: Invalid link. UserId: {UserId}", userId);
            return ApiResponseFactory.Fail<object>("Invalid email confirmation link.");
        }

        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user == null)
        {
            _logger.LogWarning("Email confirmation failed. Reason: User not found. UserId: {UserId}", userId);
            return ApiResponseFactory.Fail<object>($"User with ID '{userId}' not found.");
        }

        try
        {
            var result = await _userManager.ConfirmEmailAsync(user, token);

            if (result.Succeeded)
            {
                _logger.LogInformation("Email successfully confirmed for UserId: {UserId}", userId);
                return ApiResponseFactory.Success<object>(null, "Email confirmed successfully. You can now login.");
            }

            var errors = result.Errors.Select(e => e.Description).ToList();
            _logger.LogWarning("Email confirmation failed for UserId: {UserId}. Errors: {Errors}", userId, string.Join(", ", errors));

            return ApiResponseFactory.Fail<object>("Error confirming your email.", errors);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception occurred during email confirmation for UserId: {UserId}", userId);
            throw;
        }
    }

    
    public async Task<ApiResponse<LoginResponse>> LoginUserAsync(LoginRequest request, string ipAddress)
    {
        _logger.LogInformation("Login attempt for email: {Email} from IP: {IpAddress}", request.Email, ipAddress);

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            _logger.LogWarning("Login failed: Email not found. Email: {Email}", request.Email);
            return ApiResponseFactory.Fail<LoginResponse>("Invalid login credentials.");
        }

        if (!user.EmailConfirmed)
        {
            _logger.LogWarning("Login failed: Email not confirmed. Email: {Email}", request.Email);
            return ApiResponseFactory.Fail<LoginResponse>("Your email has not been confirmed yet. Please check your inbox.");
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
        if (!result.Succeeded)
        {
            if (result.IsLockedOut)
            {
                _logger.LogWarning("Login failed: Account locked out. Email: {Email}", request.Email);
                return ApiResponseFactory.Fail<LoginResponse>("Account locked out due to multiple failed login attempts.");
            }

            if (result.IsNotAllowed)
            {
                _logger.LogWarning("Login failed: Not allowed to login. Email: {Email}", request.Email);
                return ApiResponseFactory.Fail<LoginResponse>("Login not allowed. Please confirm your email or contact support.");
            }

            if (result.RequiresTwoFactor)
            {
                _logger.LogInformation("Login requires two-factor authentication. Email: {Email}", request.Email);
                return ApiResponseFactory.Fail<LoginResponse>("Two-factor authentication required.");
            }

            _logger.LogWarning("Login failed: Invalid credentials. Email: {Email}", request.Email);
            return ApiResponseFactory.Fail<LoginResponse>("Invalid login credentials.");
        }

        try
        {
            user.LastLoginDate = DateTimeOffset.UtcNow;
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("Login successful for email: {Email}. Revoking old refresh tokens...", request.Email);

            await RevokeOldRefreshTokensForUser(user.Id);

            var accessToken = await GenerateJwtTokenAsync(user);
            var refreshToken = await GenerateAndSaveRefreshTokenAsync(user.Id, ipAddress);

            var response = new LoginResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken.Token,
                LastLoginDate = user.LastLoginDate
            };

            _logger.LogInformation("Login response generated successfully for email: {Email}", request.Email);
            return ApiResponseFactory.Success(response, "Login successful.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception occurred during login for email: {Email}", request.Email);
            throw; // Bisa juga return ApiResponseFactory.Fail<LoginResponse>("Unexpected error during login.")
        }
    }

    
    public async Task<string> GenerateJwtTokenAsync(ApplicationUser user)
    {
        _logger.LogInformation("Generating JWT token for user: {UserId} ({Email})", user.Id, user.Email);

        try
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

            _logger.LogInformation("User {UserId} has roles: {Roles}", user.Id, string.Join(", ", roles));

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

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            _logger.LogInformation("JWT token generated successfully for user: {UserId}. Expires at: {Expires}", user.Id, expires);

            return tokenString;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating JWT token for user: {UserId}", user.Id);
            throw;
        }
    }

    
    public async Task<ApiResponse<LoginResponse>> RefreshTokenAsync(string token, string ipAddress)
    {
        _logger.LogInformation("Attempting to refresh access token using refresh token: {RefreshToken}", token);

        var refreshToken = await _dbContext.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.Token == token);

        if (refreshToken == null)
        {
            _logger.LogWarning("Refresh token not found: {Token}", token);
            return ApiResponseFactory.Fail<LoginResponse>("Invalid refresh token.");
        }

        if (!refreshToken.IsActive)
        {
            _logger.LogWarning("Refresh token is inactive for user {UserId}. Reason: {ReasonRevoked}", 
                refreshToken.UserId, refreshToken.ReasonRevoked);

            await RevokeOldRefreshTokensForUser(refreshToken.UserId);
            return ApiResponseFactory.Fail<LoginResponse>("Invalid or expired refresh token.");
        }

        // Revoke old refresh token
        refreshToken.Revoked = DateTimeOffset.UtcNow;
        refreshToken.ReasonRevoked = "Rotated by refresh";
    
        // Generate new refresh token
        var newRefreshToken = await GenerateAndSaveRefreshTokenAsync(refreshToken.UserId, ipAddress);
        refreshToken.ReplacedByToken = newRefreshToken.Token;

        // Generate new access token
        var accessToken = await GenerateJwtTokenAsync(refreshToken.User);

        await _dbContext.SaveChangesAsync();

        _logger.LogInformation("Refresh token successfully rotated for user {UserId}", refreshToken.UserId);

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
            .Where(rt => rt.UserId == userId && rt.Revoked == null)
            .ToListAsync();

        foreach (var token in tokens)
        {
            if (token.Expires <= DateTimeOffset.UtcNow)
            {
                token.Revoked = DateTimeOffset.UtcNow;
                token.ReasonRevoked = "Expired";
            }
            else
            {
                token.Revoked = DateTimeOffset.UtcNow;
                token.ReasonRevoked = "Replaced during login";
            }
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
        _logger.LogInformation("Starting password reset process for email: {Email}", email);

        var user = await _userManager.FindByEmailAsync(email);
        var isConfirmed = user != null && await _userManager.IsEmailConfirmedAsync(user);

        if (!isConfirmed)
        {
            _logger.LogWarning("Password reset requested for unconfirmed or non-existent email: {Email}", email);
            return ApiResponseFactory.Success<object>(null, 
                "If an account with that email exists, a password reset link has been sent.");
        }

        _logger.LogInformation("Generating password reset token for user: {UserId}", user.Id);

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var callbackUrl = $"{scheme}://{host}/api/auth/reset-password?token={Uri.EscapeDataString(token)}&email={Uri.EscapeDataString(user.Email!)}";

        _logger.LogDebug("Password reset callback URL generated: {CallbackUrl}", callbackUrl);

        var emailSendResult = await _emailService.SendEmailAsync(new EmailRequest
        {
            ToEmail = user.Email!,
            Subject = "Reset Your Password",
            Body = $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>",
            IsHtml = true
        });

        if (!emailSendResult.Success)
        {
            _logger.LogError("Failed to send password reset email to {Email}. Errors: {Errors}", 
                user.Email, string.Join(", ", emailSendResult.Errors ?? new List<string>()));
            return ApiResponseFactory.Fail<object>("Failed to send password reset email. Please try again later.", emailSendResult.Errors);
        }

        _logger.LogInformation("Password reset email successfully sent to {Email}", user.Email);

        return ApiResponseFactory.Success<object>(null, 
            "If an account with that email exists, a password reset link has been sent.");
    }
    
    public async Task<ApiResponse<object>> ResetPasswordAsync(string email, string token, string newPassword)
    {
        _logger.LogInformation("ResetPasswordAsync started for email: {Email}", email);

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            _logger.LogWarning("Reset password failed: User with email {Email} not found.", email);
            return ApiResponseFactory.Fail<object>("User not found.");
        }

        _logger.LogInformation("User found: {UserId}", user.Id);

        var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
        if (result.Succeeded)
        {
            _logger.LogInformation("Password reset successful for user {UserId}", user.Id);
            return ApiResponseFactory.Success<object>(null, "Password has been reset successfully.");
        }

        var errorDescriptions = result.Errors.Select(e => e.Description).ToList();
        _logger.LogError("Password reset failed for user {UserId}. Errors: {Errors}", user.Id, string.Join(", ", errorDescriptions));

        return ApiResponseFactory.Fail<object>("Failed to reset password.", errorDescriptions);
    }
    
    public async Task<ApiResponse<object>> RevokeRefreshTokenAsync(string token, string ipAddress)
    {
        _logger.LogInformation("Starting RevokeRefreshTokenAsync for token: {Token}, IP: {IpAddress}", token, ipAddress);

        var refreshToken = await _dbContext.RefreshTokens.SingleOrDefaultAsync(rt => rt.Token == token);

        if (refreshToken == null)
        {
            _logger.LogWarning("Revoke failed: Refresh token not found. Token: {Token}", token);
            return ApiResponseFactory.Fail<object>("Invalid refresh token.");
        }

        if (refreshToken.IsExpired)
        {
            _logger.LogWarning("Revoke failed: Refresh token expired at {ExpiredAt}. Token: {Token}", refreshToken.Expires, token);
            return ApiResponseFactory.Fail<object>("Refresh token already expired.");
        }

        if (refreshToken.Revoked != null)
        {
            _logger.LogWarning("Revoke failed: Refresh token already revoked at {RevokedAt}. Token: {Token}", refreshToken.Revoked, token);
            return ApiResponseFactory.Fail<object>("Refresh token already revoked.");
        }

        refreshToken.Revoked = DateTimeOffset.UtcNow;
        refreshToken.ReasonRevoked = "Manual Revocation";
        refreshToken.RemoteIpAddress = ipAddress;

        _logger.LogInformation("Revoking refresh token: {Token} at {RevokedAt} from IP: {IpAddress}", token, refreshToken.Revoked, ipAddress);

        await _dbContext.SaveChangesAsync();

        _logger.LogInformation("Refresh token revoked successfully: {Token}", token);

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
    
    public async Task<ApiResponse<object>> DisableTwoFactorAuthAsync(Guid userId, string password)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user == null)
        {
            return ApiResponseFactory.Fail<object>("User not found.");
        }

        var passwordCheck = await _userManager.CheckPasswordAsync(user, password);
        if (!passwordCheck)
        {
            return ApiResponseFactory.Fail<object>("Invalid password. Cannot disable 2FA.");
        }

        if (!await _userManager.GetTwoFactorEnabledAsync(user))
        {
            return ApiResponseFactory.Fail<object>("Two-Factor Authentication is not enabled for this user.");
        }

        var setResult = await _userManager.SetTwoFactorEnabledAsync(user, false);
        if (!setResult.Succeeded)
        {
            return ApiResponseFactory.Fail<object>("Failed to disable Two-Factor Authentication.", setResult.Errors.Select(e => e.Description).ToList());
        }

        await _userManager.ResetAuthenticatorKeyAsync(user);

        return ApiResponseFactory.Success<object>(null, "Two-Factor Authentication disabled successfully.");
    }
    
    
    public async Task<ApiResponse<UserProfileResponse>> GetUserProfileAsync(Guid userId)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user == null)
        {
            return ApiResponseFactory.Fail<UserProfileResponse>("User not found.");
        }

        var userProfile = new UserProfileResponse
        {
            Id = user.Id,
            UserName = user.UserName!, 
            Email = user.Email!,     
            EmailConfirmed = user.EmailConfirmed,
            TwoFactorEnabled = user.TwoFactorEnabled,
            CreatedDate = user.CreatedDate,
            LastLoginDate = user.LastLoginDate
        };

        return ApiResponseFactory.Success(userProfile, "User profile retrieved successfully.");
    }
    
    public async Task<ApiResponse<object>> ChangePasswordAsync(Guid userId, ChangePasswordRequest request)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user == null)
        {
            return ApiResponseFactory.Fail<object>("User not found.");
        }

        var result = await _userManager.ChangePasswordAsync(user, request.OldPassword, request.NewPassword);

        if (result.Succeeded)
        {
            return ApiResponseFactory.Success<object>(null, "Password changed successfully. Please log in again with your new password.");
        }

        return ApiResponseFactory.Fail<object>("Failed to change password.", result.Errors.Select(e => e.Description).ToList());
    }

}