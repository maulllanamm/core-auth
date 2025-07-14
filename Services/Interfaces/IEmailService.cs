using core_auth.Model.DTO;

namespace core_auth.Services.Interfaces;

public interface IEmailService
{
    Task<ApiResponse<object>> SendEmailAsync(EmailRequest request);
}