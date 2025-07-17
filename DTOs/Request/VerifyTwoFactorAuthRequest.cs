using System.ComponentModel.DataAnnotations;

namespace core_auth.Model.DTO;

public class VerifyTwoFactorAuthRequest
{
    [Required(ErrorMessage = "Verification code is required.")]
    [StringLength(6, MinimumLength = 6, ErrorMessage = "Verification code must be 6 digits.")]
    [RegularExpression("^[0-9]*$", ErrorMessage = "Verification code must be numeric.")]
    public string VerificationCode { get; set; } = string.Empty;
}