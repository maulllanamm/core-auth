using Microsoft.AspNetCore.Identity;

namespace core_auth.Model;

public class ApplicationUser : IdentityUser<Guid>
{
    public DateTimeOffset CreatedDate { get; set; } = DateTimeOffset.UtcNow; 
    public DateTimeOffset? LastLoginDate { get; set; }
}