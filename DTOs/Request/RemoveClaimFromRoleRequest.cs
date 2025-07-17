using System.ComponentModel.DataAnnotations;

namespace core_auth.Model.DTO;

public class RemoveClaimFromRoleRequest
{
    [Required(ErrorMessage = "Role ID is required.")]
    public Guid RoleId { get; set; }

    [Required(ErrorMessage = "Claim type is required.")]
    public string ClaimType { get; set; } = string.Empty;

    [Required(ErrorMessage = "Claim value is required.")]
    public string ClaimValue { get; set; } = string.Empty;
}