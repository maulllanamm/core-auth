using core_auth.Model;
using core_auth.Model.DTO;
using core_auth.Services.Interfaces;
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

}