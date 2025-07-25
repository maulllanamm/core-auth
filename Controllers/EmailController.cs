using core_auth.Model.DTO;
using core_auth.Services.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace core_auth.Controllers;

[ApiController]
[Route("api/email")]
public class EmailController: ControllerBase
{
    private readonly IEmailService _emailService;

    public EmailController(IEmailService emailService)
    {
        _emailService = emailService;
    }

    [HttpPost("test")]
    public async Task<IActionResult> TestEmail()
    {
        var result = await _emailService.SendEmailAsync(new EmailRequest
        {
            ToEmail = "maulllanamuhammad@gmail.com",
            Subject = "Test Email",
            Body = "<b>Ini body email</b>",
            IsHtml = true
        });

        return Ok(result);
    }
}