namespace core_auth.Model.DTO;

public class BaseResponse
{
    public bool IsSuccess { get; set; }
    public string? Message { get; set; }
    public List<string>? Errors { get; set; }
}