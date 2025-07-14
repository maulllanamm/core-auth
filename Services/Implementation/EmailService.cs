using System.Net;
using System.Net.Mail;
using core_auth.Model.DTO;
using core_auth.Services.Interfaces;

namespace core_auth.Services.Implementation;

public class EmailService: IEmailService
{
    private readonly IConfiguration _configuration;

    public EmailService(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    
    public async Task<ApiResponse<object>> SendEmailAsync(EmailRequest request)
    {
        try
        {
            var smtpHost = _configuration["SmtpSettings:Host"] ?? throw new InvalidOperationException("SMTP Host not configured.");
            var smtpPort = _configuration.GetValue<int>("SmtpSettings:Port");
            var smtpUsername = _configuration["SmtpSettings:Username"] ?? string.Empty; 
            var smtpPassword = _configuration["SmtpSettings:Password"] ?? string.Empty;
            var smtpEnableSsl = _configuration.GetValue<bool>("SmtpSettings:EnableSsl");
            var fromEmail = _configuration["SmtpSettings:FromEmail"] ?? throw new InvalidOperationException("SMTP FromEmail not configured.");
            var fromDisplayName = _configuration["SmtpSettings:FromDisplayName"] ?? fromEmail;


            using (var client = new SmtpClient(smtpHost, smtpPort))
            {
                client.EnableSsl = smtpEnableSsl;
                client.UseDefaultCredentials = false;
                if (!string.IsNullOrEmpty(smtpUsername) && !string.IsNullOrEmpty(smtpPassword))
                {
                    client.Credentials = new NetworkCredential(smtpUsername, smtpPassword);
                }


                var mailMessage = new MailMessage
                {
                    From = new MailAddress(fromEmail, fromDisplayName),
                    Subject = request.Subject,
                    Body = request.Body,
                    IsBodyHtml = request.IsHtml
                };
                mailMessage.To.Add(request.ToEmail);

                await client.SendMailAsync(mailMessage);
            }

            return ApiResponseFactory.Success<object>(null, "Email sent successfully.");
        }
        catch (SmtpException smtpEx)
        {
            Console.Error.WriteLine($"SMTP Error sending email to {request.ToEmail}: {smtpEx.StatusCode} - {smtpEx.Message}");
            return ApiResponseFactory.Fail<object>(
                $"Failed to send email: SMTP error {smtpEx.StatusCode}.",
                new List<string> { smtpEx.Message }
            );

        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error sending email to {request.ToEmail}: {ex.Message}");
            return ApiResponseFactory.Fail<object>(
                "Failed to send email.",
                new List<string> { ex.Message }
            );

        }
    }
}