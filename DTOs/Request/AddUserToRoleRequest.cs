using System.ComponentModel.DataAnnotations;

namespace core_auth.Model.DTO;

public class AddUserToRoleRequest
{
    [Required(ErrorMessage = "User ID is required.")]
    public Guid UserId { get; set; } 

    [Required(ErrorMessage = "Role name is required.")]
    public string RoleName { get; set; } = string.Empty;
}