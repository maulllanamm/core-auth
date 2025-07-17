namespace core_auth.Model.DTO;

public class TwoFactorAuthSetupDto
{
    public string SharedKey { get; set; } = string.Empty;
    public string AuthenticatorUri { get; set; } = string.Empty; 
    public string? WarningMessage { get; set; } 
}