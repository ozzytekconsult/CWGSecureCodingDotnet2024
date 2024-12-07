namespace CWG.SecureCoding.Core.DTOs.Common;

/// <summary>
/// Represents the result of a service operation
/// </summary>
public class ServiceResult
{
    public bool IsSuccess { get; }
    public string? Error { get; }
    public ServiceResultStatus Status { get; }

    protected ServiceResult(bool isSuccess, string? error, ServiceResultStatus status)
    {
        IsSuccess = isSuccess;
        Error = error;
        Status = status;
    }

    public static ServiceResult Success() => 
        new ServiceResult(true, null, ServiceResultStatus.Success);

    public static ServiceResult Failure(string message) => 
        new ServiceResult(false, message, ServiceResultStatus.Error);

    public static ServiceResult NotFound(string message = "Resource not found") => 
        new ServiceResult(false, message, ServiceResultStatus.NotFound);

    public static ServiceResult Unauthorized(string message = "Unauthorized access") => 
        new ServiceResult(false, message, ServiceResultStatus.Unauthorized);

    public static ServiceResult ValidationError(string message) => 
        new ServiceResult(false, message, ServiceResultStatus.ValidationError);

    public static ServiceResult SecurityError(string message) => 
        new ServiceResult(false, message, ServiceResultStatus.SecurityError);
}

/// <summary>
/// Represents the result of a service operation with a generic data type
/// </summary>
public class ServiceResult<T> : ServiceResult
{
    public T? Data { get; }

    private ServiceResult(bool isSuccess, T? data, string? error, ServiceResultStatus status) 
        : base(isSuccess, error, status)
    {
        Data = data;
    }

    public static ServiceResult<T> Success(T data) => 
        new ServiceResult<T>(true, data, null, ServiceResultStatus.Success);

    public static new ServiceResult<T> Failure(string message) => 
        new ServiceResult<T>(false, default, message, ServiceResultStatus.Error);

    public static new ServiceResult<T> NotFound(string message = "Resource not found") => 
        new ServiceResult<T>(false, default, message, ServiceResultStatus.NotFound);

    public static new ServiceResult<T> Unauthorized(string message = "Unauthorized access") => 
        new ServiceResult<T>(false, default, message, ServiceResultStatus.Unauthorized);

    public static new ServiceResult<T> ValidationError(string message) => 
        new ServiceResult<T>(false, default, message, ServiceResultStatus.ValidationError);

    public static new ServiceResult<T> SecurityError(string message) => 
        new ServiceResult<T>(false, default, message, ServiceResultStatus.SecurityError);
}

/// <summary>
/// Represents the status of a service operation result
/// </summary>
public enum ServiceResultStatus
{
    Success,
    Error,
    NotFound,
    Unauthorized,
    ValidationError,
    SecurityError
}
