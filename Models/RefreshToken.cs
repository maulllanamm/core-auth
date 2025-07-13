using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace core_auth.Model;

public class RefreshToken
{
    [Key]
    public Guid Id { get; set; } 

    [Required]
    [MaxLength(500)] 
    public string Token { get; set; } = string.Empty;

    [Required]
    public DateTimeOffset Expires { get; set; }

    [Required]
    public DateTimeOffset Created { get; set; } = DateTimeOffset.UtcNow; 

    public DateTimeOffset? Revoked { get; set; } 

    public string? ReplacedByToken { get; set; } 

    public string? ReasonRevoked { get; set; } 

    [MaxLength(45)] 
    public string? RemoteIpAddress { get; set; }

    [Required]
    [ForeignKey("Users")] 
    public string UserId { get; set; } = string.Empty;

    public ApplicationUser User { get; set; } = null!;

    [NotMapped] 
    public bool IsActive => Revoked == null && !IsExpired;

    [NotMapped] 
    public bool IsExpired => DateTimeOffset.UtcNow >= Expires;
}