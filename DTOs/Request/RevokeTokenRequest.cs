using System.ComponentModel.DataAnnotations;

namespace core_auth.Model.DTO;

public class RevokeTokenRequest
{
    [Required]
    public string Token { get; set; } = string.Empty;
}