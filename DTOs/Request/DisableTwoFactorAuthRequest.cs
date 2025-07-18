using System.ComponentModel.DataAnnotations;

namespace core_auth.Model.DTO;

public class DisableTwoFactorAuthRequest
{
    [Required(ErrorMessage = "Password is required to disable 2FA.")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;
}