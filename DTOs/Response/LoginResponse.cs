namespace core_auth.Model.DTO;

public class LoginResponse
{
    public string? Token { get; set; } 
    public string? RefreshToken { get; set; }
    public DateTimeOffset? LastLoginDate { get; set; }
}
