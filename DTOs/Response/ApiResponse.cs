namespace core_auth.Model.DTO;

public class ApiResponse<T>
{
    public bool Success { get; set; } = true;
    public string Message { get; set; } = "Success";
    public T Data { get; set; }
    public List<string> Errors { get; set; } = new();
}

