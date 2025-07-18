namespace core_auth.Model.DTO;

public class UserProfileResponse
{
    public Guid Id { get; set; } 
    public string UserName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public bool EmailConfirmed { get; set; }
    public bool TwoFactorEnabled { get; set; }
    public DateTimeOffset CreatedDate { get; set; }
    public DateTimeOffset? LastLoginDate { get; set; }
}