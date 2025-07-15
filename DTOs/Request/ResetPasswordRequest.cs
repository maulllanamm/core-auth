using System.ComponentModel.DataAnnotations;

namespace core_auth.Model.DTO;

public class ResetPasswordRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
    [Required]
    [EmailAddress]
    public string Token { get; set; } = string.Empty;
    [Required]
    [EmailAddress]
    public string NewPassword { get; set; } = string.Empty;
}