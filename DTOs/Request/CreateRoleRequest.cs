using System.ComponentModel.DataAnnotations;

namespace core_auth.Model.DTO;

public class CreateRoleRequest
{
    [Required(ErrorMessage = "Role name is required.")]
    [StringLength(256, ErrorMessage = "Role name cannot exceed 256 characters.")]
    public string RoleName { get; set; } = string.Empty;
}