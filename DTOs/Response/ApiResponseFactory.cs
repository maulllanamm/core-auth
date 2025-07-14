namespace core_auth.Model.DTO;

public static class ApiResponseFactory
{
    public static ApiResponse<T> Success<T>(T data, string message = "Success") =>
        new() { Success = true, Message = message, Data = data };

    public static ApiResponse<T> Fail<T>(string message, List<string> errors = null) =>
        new() { Success = false, Message = message, Errors = errors ?? new() };
    
    public static ApiResponse<T> SuccessWithWarning<T>(T data, string message, List<string> warnings) =>
        new()
        {
            Success = true,
            Message = message,
            Data = data,
            Errors = warnings ?? new()
        }; 
}
