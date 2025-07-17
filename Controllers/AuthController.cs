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

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    /// <summary>
    /// Register a new user.
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        var response = await _authService.RegisterUserAsync(
            request,
            HttpContext.Request.Scheme,
            HttpContext.Request.Host.ToUriComponent()
        );

        if (response.Success)
        {
            return Ok(response);
        }

        return BadRequest(response);
    }
    
    /// <summary>
    /// Confirms user email using a token.
    /// </summary>
    [HttpGet("confirm-email")]
    public async Task<IActionResult> ConfirmEmail([FromQuery] Guid userId, [FromQuery] string token)
    {
        var response = await _authService.ConfirmEmailAsync(userId, token);

        if (response.Success)
        {
            return Ok(response);
        }

        return BadRequest(response);
    }

    
    /// <summary>
    /// Login user and return JWT.
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";

        var response = await _authService.LoginUserAsync(request, ipAddress);

        if (response.Success)
        {
            return Ok(response);
        }
        return Unauthorized(response);
    }
    
    /// <summary>
    /// Refreshes JWT using a valid refresh token.
    /// </summary>
    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest model)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";

        var response = await _authService.RefreshTokenAsync(model.RefreshToken, ipAddress);

        if (response.Success)
        {
            return Ok(response);
        }

        return BadRequest(response);
    }
    
    /// <summary>
    /// Requests a password reset token to be sent to the user's email.
    /// </summary>
    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest model)
    {
        var response = await _authService.SendPasswordResetEmailAsync(model.Email, HttpContext.Request.Scheme, HttpContext.Request.Host.ToUriComponent());

        return Ok(response.Message);
    }
    
    
    /// <summary>
    /// Resets the user's password using a valid token.
    /// </summary>
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest model)
    {
        var response = await _authService.ResetPasswordAsync(model.Email, model.Token, model.NewPassword);

        if (response.Success)
        {
            return Ok(response);
        }

        return BadRequest(response);
    }

    /// <summary>
    /// Revokes a refresh token (e.g., on logout).
    /// </summary>
    [Authorize]
    [HttpPost("revoke-token")]
    public async Task<IActionResult> RevokeToken([FromBody] RevokeTokenRequest model)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
            
        var response = await _authService.RevokeRefreshTokenAsync(model.Token, ipAddress);

        if (response.Success)
        {
            return Ok(response);
        }

        return BadRequest(response);
    }
    
    /// <summary>
    /// Creates a new role. Requires administrator access.
    /// </summary>
    [HttpPost("roles")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> CreateRole([FromBody] CreateRoleRequest request)
    {
        var response = await _authService.CreateRoleAsync(request.RoleName);

        if (response.Success)
        {
            return Ok(response);
        }

        return BadRequest(response);
    }
    
    /// <summary>
    /// Retrieves all roles. Requires administrator access.
    /// </summary>
    [HttpGet("roles")]
    [Authorize(Roles = "Admin")] // Only users with "Admin" role can access
    public async Task<IActionResult> GetAllRoles()
    {
        var response = await _authService.GetAllRolesAsync();

        if (response.Success)
        {
            return Ok(response);
        }

        return StatusCode(500, ApiResponseFactory.Fail<List<RoleResponse>>("An unexpected error occurred."));
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


}