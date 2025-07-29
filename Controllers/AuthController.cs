using System.Security.Claims;
using core_auth.Model;
using core_auth.Model.DTO;
using core_auth.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace core_auth.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IAuthService authService, ILogger<AuthController> logger)
    {
        _authService = authService;
        _logger = logger;
    }

    /// <summary>
    /// Register a new user.
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        _logger.LogInformation("Register request received for email: {Email}", request.Email);

        try
        {
            var response = await _authService.RegisterUserAsync(
                request,
                HttpContext.Request.Scheme,
                HttpContext.Request.Host.ToUriComponent()
            );

            if (response.Success)
            {
                _logger.LogInformation("Registration successful for email: {Email}", request.Email);
                return Ok(response);
            }

            _logger.LogWarning("Registration failed for email: {Email} with message: {Message}", request.Email, response.Message);
            return BadRequest(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error occurred during registration for email: {Email}", request.Email);
            return StatusCode(500, "Internal server error.");
        }
    }
    
    /// <summary>
    /// Confirms user email using a token.
    /// </summary>
    [HttpGet("confirm-email")]
    public async Task<IActionResult> ConfirmEmail([FromQuery] Guid userId, [FromQuery] string token)
    {
        _logger.LogInformation("Email confirmation request received for UserId: {UserId}", userId);

        try
        {
            var response = await _authService.ConfirmEmailAsync(userId, token);

            if (response.Success)
            {
                _logger.LogInformation("Email confirmation successful for UserId: {UserId}", userId);
                return Ok(response);
            }

            _logger.LogWarning("Email confirmation failed for UserId: {UserId} with message: {Message}", userId, response.Message);
            return BadRequest(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error occurred while confirming email for UserId: {UserId}", userId);
            return StatusCode(500, "Internal server error.");
        }
    }


    
    /// <summary>
    /// Login user and return JWT.
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        _logger.LogInformation("Login request received for email: {Email} from IP: {IPAddress}", request.Email, ipAddress);

        try
        {
            var response = await _authService.LoginUserAsync(request, ipAddress);

            if (response.Success)
            {
                _logger.LogInformation("Login successful for email: {Email} from IP: {IPAddress}", request.Email, ipAddress);
                return Ok(response);
            }

            _logger.LogWarning("Login failed for email: {Email} from IP: {IPAddress} with message: {Message}", request.Email, ipAddress, response.Message);
            return Unauthorized(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error occurred during login for email: {Email} from IP: {IPAddress}", request.Email, ipAddress);
            return StatusCode(500, "Internal server error.");
        }
    }

    
    /// <summary>
    /// Refreshes JWT using a valid refresh token.
    /// </summary>
    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest model)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        _logger.LogInformation("Refresh token request received from IP: {IPAddress}", ipAddress);

        try
        {
            var response = await _authService.RefreshTokenAsync(model.RefreshToken, ipAddress);

            if (response.Success)
            {
                _logger.LogInformation("Refresh token successful from IP: {IPAddress}", ipAddress);
                return Ok(response);
            }

            _logger.LogWarning("Refresh token failed from IP: {IPAddress} with message: {Message}", ipAddress, response.Message);
            return BadRequest(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error occurred during token refresh from IP: {IPAddress}", ipAddress);
            return StatusCode(500, "Internal server error.");
        }
    }

    
    /// <summary>
    /// Requests a password reset token to be sent to the user's email.
    /// </summary>
    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest model)
    {
        _logger.LogInformation("ForgotPassword request received for email: {Email}", model.Email);

        try
        {
            var response = await _authService.SendPasswordResetEmailAsync(
                model.Email,
                HttpContext.Request.Scheme,
                HttpContext.Request.Host.ToUriComponent()
            );

            _logger.LogInformation("ForgotPassword email sent successfully to: {Email}", model.Email);
            return Ok(response.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ForgotPassword failed for email: {Email}", model.Email);
            return StatusCode(500, "An error occurred while processing your request.");
        }
    }
    
    
    /// <summary>
    /// Resets the user's password using a valid token.
    /// </summary>
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest model)
    {
        _logger.LogInformation("ResetPassword request received for email: {Email}", model.Email);

        try
        {
            var response = await _authService.ResetPasswordAsync(model.Email, model.Token, model.NewPassword);

            if (response.Success)
            {
                _logger.LogInformation("Password reset successful for email: {Email}", model.Email);
                return Ok(response);
            }

            _logger.LogWarning("Password reset failed for email: {Email}. Reason: {Message}", model.Email, response.Message);
            return BadRequest(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ResetPassword encountered an error for email: {Email}", model.Email);
            return StatusCode(500, "An internal error occurred while resetting the password.");
        }
    }


    /// <summary>
    /// Revokes a refresh token (e.g., on logout).
    /// </summary>
    [Authorize]
    [HttpPost("revoke-token")]
    public async Task<IActionResult> RevokeToken([FromBody] RevokeTokenRequest model)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        _logger.LogInformation("RevokeToken request received from IP: {IpAddress}, Token: {Token}", ipAddress, model.Token);

        try
        {
            var response = await _authService.RevokeRefreshTokenAsync(model.Token, ipAddress);

            if (response.Success)
            {
                _logger.LogInformation("RevokeToken succeeded for Token: {Token}, IP: {IpAddress}", model.Token, ipAddress);
                return Ok(response);
            }

            _logger.LogWarning("RevokeToken failed for Token: {Token}, IP: {IpAddress}. Reason: {Message}", model.Token, ipAddress, response.Message);
            return BadRequest(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while revoking token: {Token}, IP: {IpAddress}", model.Token, ipAddress);
            return StatusCode(500, "An error occurred while processing the revoke request.");
        }
    }

    
    /// <summary>
    /// Creates a new role. Requires administrator access.
    /// </summary>
    [HttpPost("roles")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> CreateRole([FromBody] CreateRoleRequest request)
    {
        var user = User?.Identity?.Name ?? "Unknown";
        _logger.LogInformation("CreateRole request received by user: {User}. Role to create: {RoleName}", user, request.RoleName);

        try
        {
            var response = await _authService.CreateRoleAsync(request.RoleName);

            if (response.Success)
            {
                _logger.LogInformation("Role '{RoleName}' created successfully by user: {User}", request.RoleName, user);
                return Ok(response);
            }

            _logger.LogWarning("Failed to create role '{RoleName}' by user: {User}. Reason: {Message}", request.RoleName, user, response.Message);
            return BadRequest(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while creating role '{RoleName}' by user: {User}", request.RoleName, user);
            return StatusCode(500, "An error occurred while creating the role.");
        }
    }

    
    /// <summary>
    /// Retrieves all roles. Requires administrator access.
    /// </summary>
    [HttpGet("roles")]
    [Authorize(Roles = "Admin")] 
    public async Task<IActionResult> GetAllRoles()
    {
        var user = User?.Identity?.Name ?? "Unknown";
        _logger.LogInformation("GetAllRoles request received by user: {User}", user);

        try
        {
            var response = await _authService.GetAllRolesAsync();

            if (response.Success)
            {
                _logger.LogInformation("GetAllRoles succeeded. Retrieved {Count} roles by user: {User}", response.Data?.Count ?? 0, user);
                return Ok(response);
            }

            _logger.LogWarning("GetAllRoles failed with message: {Message} by user: {User}", response.Message, user);
            return StatusCode(500, ApiResponseFactory.Fail<List<RoleResponse>>("An unexpected error occurred."));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception occurred in GetAllRoles by user: {User}", user);
            return StatusCode(500, ApiResponseFactory.Fail<List<RoleResponse>>("An unexpected error occurred."));
        }
    }


    /// <summary>
    /// Adds a user to a specified role. Requires administrator access.
    /// </summary>
    [HttpPost("users/roles")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> AddUserToRole([FromBody] AddUserToRoleRequest request)
    {

        var response = await _authService.AddUserToRoleAsync(request.UserId, request.RoleName);

        if (response.Success)
        {
            return Ok(response);
        }

        return BadRequest(response);
    }
    
    /// <summary>
    /// Removes a user from a specified role. Requires administrator access.
    /// </summary>
    [HttpDelete("users/roles")] 
    [Authorize(Roles = "Admin")] 
    public async Task<IActionResult> RemoveUserFromRole([FromBody] RemoveUserFromRoleRequest request)
    {

        var response = await _authService.RemoveUserFromRoleAsync(request.UserId, request.RoleName);

        if (response.Success)
        {
            return Ok(response);
        }

        return BadRequest(response);
    }

    /// <summary>
    /// Retrieves all roles for a specific user. Requires administrator access.
    /// </summary>
    /// <param name="userId">The ID of the user.</param>
    [HttpGet("users/{userId}/roles")] 
    [Authorize(Roles = "Admin")] 
    public async Task<IActionResult> GetUserRoles([FromRoute] Guid userId) 
    {
        var response = await _authService.GetUserRolesAsync(userId);

        if (response.Success)
        {
            return Ok(response);
        }

        return BadRequest(response); 
    }
    
    /// <summary>
    /// Adds a claim to a specified role. Requires administrator access.
    /// </summary>
    [HttpPost("roles/claims")] 
    [Authorize(Roles = "Admin")] 
    public async Task<IActionResult> AddClaimToRole([FromBody] AddClaimToRoleRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ApiResponseFactory.Fail<object>("Validation failed.", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList()));
        }

        var response = await _authService.AddClaimToRoleAsync(request.RoleId, request.ClaimType, request.ClaimValue);

        if (response.Success)
        {
            return Ok(response);
        }

        return BadRequest(response);
    }
    
    /// <summary>
    /// Removes a claim from a specified role. Requires administrator access.
    /// </summary>
    [HttpDelete("roles/claims")] 
    [Authorize(Roles = "Admin")] 
    public async Task<IActionResult> RemoveClaimFromRole([FromBody] RemoveClaimFromRoleRequest request)
    {
        var response = await _authService.RemoveClaimFromRoleAsync(request.RoleId, request.ClaimType, request.ClaimValue);

        if (response.Success)
        {
            return Ok(response);
        }

        return BadRequest(response);
    }
    
    /// <summary>
    /// Retrieves all claims for a specific role. Requires administrator access.
    /// </summary>
    /// <param name="roleId">The ID of the role.</param>
    [HttpGet("roles/{roleId}/claims")] 
    [Authorize(Roles = "Admin")] 
    public async Task<IActionResult> GetRoleClaims([FromRoute] Guid roleId) 
    {
        var response = await _authService.GetRoleClaimsAsync(roleId);

        if (response.Success)
        {
            return Ok(response);
        }

        return BadRequest(response); 
    }
    
    [HttpGet("2fa/setup")] 
    [Authorize]
    public async Task<IActionResult> InitiateTwoFactorAuthSetup()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized(ApiResponseFactory.Fail<TwoFactorAuthSetupDto>("User not authenticated."));
        }

        if (!Guid.TryParse(userId, out Guid userGuid))
        {
            return BadRequest(ApiResponseFactory.Fail<TwoFactorAuthSetupDto>("Invalid User ID format."));
        }

        var response = await _authService.InitiateTwoFactorAuthSetupAsync(userGuid); 

        if (response.Success)
        {
            return Ok(response);
        }

        return BadRequest(response);
    }
    
    /// <summary>
    /// Verifies the 2FA code and enables Two-Factor Authentication for the authenticated user.
    /// Returns recovery codes upon successful activation.
    /// </summary>
    /// <param name="request">The verification code from the authenticator app.</param>
    [HttpPost("2fa/enable")] 
    [Authorize]
    public async Task<IActionResult> VerifyAndEnableTwoFactorAuth([FromBody] VerifyTwoFactorAuthRequest request)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized(ApiResponseFactory.Fail<object>("User not authenticated."));
        }
        
        if (!Guid.TryParse(userId, out Guid userGuid))
        {
            return BadRequest(ApiResponseFactory.Fail<TwoFactorAuthSetupDto>("Invalid User ID format."));
        }

        var response = await _authService.VerifyAndEnableTwoFactorAuthAsync(userGuid, request.VerificationCode);

        if (response.Success)
        {
            return Ok(response);
        }

        return BadRequest(response);
    }
    
    
    [HttpGet("me")] 
    [Authorize]
    public async Task<IActionResult> GetCurrentUserProfile()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized(ApiResponseFactory.Fail<UserProfileResponse>("User not authenticated or ID not found in token."));
        }
        if (!Guid.TryParse(userId, out Guid userGuid))
        {
            return BadRequest(ApiResponseFactory.Fail<TwoFactorAuthSetupDto>("Invalid User ID format."));
        }
        
        var response = await _authService.GetUserProfileAsync(userGuid);

        if (response.Success)
        {
            return Ok(response);
        }

        return BadRequest(response);
    }
    
    /// <summary>
    /// Allows the authenticated user to change their password.
    /// </summary>
    [HttpPost("me/change-password")] 
    [Authorize] 
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized(ApiResponseFactory.Fail<object>("User not authenticated or ID not found in token."));
        }

        if (!Guid.TryParse(userId, out Guid userGuid))
        {
            return BadRequest(ApiResponseFactory.Fail<TwoFactorAuthSetupDto>("Invalid User ID format."));
        }
        
        var response = await _authService.ChangePasswordAsync(userGuid, request);

        if (response.Success)
        {
            return Ok(response);
        }

        return BadRequest(response);
    }
    
    [HttpPost("me/disable-2fa")] 
    [Authorize] 
    public async Task<IActionResult> DisableTwoFactorAuth([FromBody] DisableTwoFactorAuthRequest request)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized(ApiResponseFactory.Fail<object>("User not authenticated or ID not found in token."));
        }

        if (!Guid.TryParse(userId, out Guid userGuid))
        {
            return BadRequest(ApiResponseFactory.Fail<TwoFactorAuthSetupDto>("Invalid User ID format."));
        }
        
        var response = await _authService.DisableTwoFactorAuthAsync(userGuid, request.Password);

        if (response.Success)
        {
            return Ok(response);
        }

        return BadRequest(response); 
    }

}