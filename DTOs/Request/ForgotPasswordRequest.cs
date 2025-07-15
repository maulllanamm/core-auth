using System.ComponentModel.DataAnnotations;

namespace core_auth.Model.DTO;

public class ForgotPasswordRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
}