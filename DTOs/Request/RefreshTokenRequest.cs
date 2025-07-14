using System.ComponentModel.DataAnnotations;

namespace core_auth.Model.DTO;

public class RefreshTokenRequest
{
    [Required]
    public string RefreshToken { get; set; } = string.Empty;
}