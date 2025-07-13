using core_auth.Model.DTO;

namespace core_auth.Services.Interfaces;

public interface IEmailSender
{
    Task<BaseResponse> SendEmailAsync(EmailRequest request);
}