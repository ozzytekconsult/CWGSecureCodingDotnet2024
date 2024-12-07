# Sensitive Information Exposure

## Overview

Sensitive Information Exposure occurs when an application inadvertently reveals sensitive data such as:

- Passwords and encryption keys
- Personal identifiable information (PII)
- Financial data
- Healthcare information
- Authentication tokens
- Debug information
- System configurations
- Internal implementation details

In our application context, sensitive data includes:
- User credentials and personal data
- Payment information
- Document metadata
- System configurations
- API keys and secrets
- Debug logs and stack traces

## Technical Details

### Common Exposure Points

1. **Application Layer**
   - Error messages
   - Debug output
   - Comments in HTML/JS
   - API responses
   - URL parameters
   - Form fields

2. **Transport Layer**
   - Unencrypted communications
   - Weak SSL/TLS
   - Missing security headers
   - Cookie settings
   - Cache controls

3. **Storage Layer**
   - Unencrypted databases
   - Log files
   - Temporary files
   - Backups
   - Configuration files

### Vulnerable Patterns in Our Domain

```csharp
// Vulnerable: Exposing sensitive data in errors
public class UserController
{
    public IActionResult Login(string username, string password)
    {
        try
        {
            // Login logic
        }
        catch (Exception ex)
        {
            // Reveals internal details
            return BadRequest(ex.ToString());
        }
    }
}

// Vulnerable: Logging sensitive data
public class PaymentService
{
    public async Task ProcessPayment(PaymentInfo payment)
    {
        _logger.LogInformation(
            $"Processing payment: {JsonSerializer.Serialize(payment)}");
    }
}

// Vulnerable: Exposing system info
public class SystemController
{
    public IActionResult GetStatus()
    {
        return Json(new
        {
            OS = Environment.OSVersion,
            Path = Environment.CurrentDirectory,
            User = Environment.UserName
        });
    }
}
```

## OWASP Mitigation Details

1. **Data Classification**
   - Identify sensitive data
   - Apply security controls
   - Define handling procedures
   - Monitor access
   - Regular audits

2. **Transport Security**
   - TLS 1.3
   - Strong ciphers
   - Perfect forward secrecy
   - Certificate validation
   - Security headers

3. **Storage Security**
   - Encryption at rest
   - Secure key management
   - Access controls
   - Data masking
   - Secure deletion

4. **Application Security**
   - Input validation
   - Output encoding
   - Error handling
   - Access logging
   - Security headers

## ASP.NET Core Mitigation Details

### 1. Secure Error Handling

```csharp
public class SecureErrorHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SecureErrorHandlingMiddleware> _logger;
    private readonly IHostEnvironment _environment;
    
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            await HandleExceptionAsync(
                context, ex);
        }
    }
    
    private async Task HandleExceptionAsync(
        HttpContext context, 
        Exception ex)
    {
        // Log full error internally
        _logger.LogError(ex, 
            "An unhandled exception occurred");
        
        // Prepare safe error response
        var error = new ApiError
        {
            Id = Activity.Current?.Id 
                ?? context.TraceIdentifier,
            Message = _environment.IsDevelopment()
                ? ex.Message
                : "An error occurred processing your request."
        };
        
        // Set response
        context.Response.StatusCode = 
            GetStatusCode(ex);
        context.Response.ContentType = 
            "application/json";
            
        await context.Response.WriteAsJsonAsync(
            error);
    }
    
    private int GetStatusCode(Exception ex) =>
        ex switch
        {
            ValidationException _ => 400,
            NotFoundException _ => 404,
            UnauthorizedAccessException _ => 401,
            _ => 500
        };
}
```

### 2. Secure Data Handling

```csharp
public class SecureDataHandler
{
    private readonly IEncryptionService _encryption;
    private readonly ILogger<SecureDataHandler> _logger;
    
    public async Task<string> SecureDataAsync(
        SensitiveData data)
    {
        try
        {
            // Validate data
            if (!IsValidData(data))
                throw new ValidationException(
                    "Invalid data");
            
            // Mask sensitive fields
            var maskedData = MaskSensitiveFields(data);
            
            // Encrypt data
            var encrypted = await _encryption
                .EncryptAsync(maskedData);
            
            // Log safely
            _logger.LogInformation(
                "Data secured: {Id}", 
                data.Id);
            
            return encrypted;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Data security error for ID: {Id}", 
                data.Id);
            throw;
        }
    }
    
    private SensitiveData MaskSensitiveFields(
        SensitiveData data)
    {
        return new SensitiveData
        {
            Id = data.Id,
            Email = MaskEmail(data.Email),
            Phone = MaskPhone(data.Phone),
            // Mask other fields
        };
    }
    
    private string MaskEmail(string email)
    {
        if (string.IsNullOrEmpty(email))
            return string.Empty;
            
        var parts = email.Split('@');
        if (parts.Length != 2) 
            return string.Empty;
            
        return $"{parts[0][0]}***@{parts[1]}";
    }
    
    private string MaskPhone(string phone)
    {
        if (string.IsNullOrEmpty(phone))
            return string.Empty;
            
        return phone.Length > 4
            ? $"***{phone[^4..]}"
            : "****";
    }
}
```

### 3. Secure Configuration Management

```csharp
public class SecureConfigurationService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<SecureConfigurationService> _logger;
    private readonly IEncryptionService _encryption;
    
    public async Task<T> GetSecureConfigAsync<T>(
        string key) where T : class
    {
        try
        {
            // Get encrypted value
            var encrypted = _configuration
                .GetValue<string>(key);
            
            if (string.IsNullOrEmpty(encrypted))
                throw new ConfigurationException(
                    $"Configuration not found: {key}");
            
            // Decrypt value
            var decrypted = await _encryption
                .DecryptAsync(encrypted);
            
            // Deserialize safely
            return JsonSerializer
                .Deserialize<T>(decrypted);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Configuration error for key: {Key}", 
                key);
            throw;
        }
    }
    
    public async Task SetSecureConfigAsync<T>(
        string key, 
        T value) where T : class
    {
        try
        {
            // Serialize value
            var json = JsonSerializer
                .Serialize(value);
            
            // Encrypt value
            var encrypted = await _encryption
                .EncryptAsync(json);
            
            // Store securely
            await StoreSecurelyAsync(
                key, encrypted);
            
            _logger.LogInformation(
                "Configuration updated: {Key}", 
                key);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Configuration update error: {Key}", 
                key);
            throw;
        }
    }
}
```

### 4. Secure Response Headers

```csharp
public class SecureHeadersMiddleware
{
    private readonly RequestDelegate _next;
    
    public async Task InvokeAsync(HttpContext context)
    {
        // Add security headers
        var headers = context.Response.Headers;
        
        // Prevent XSS
        headers["X-XSS-Protection"] = "1; mode=block";
        
        // Prevent clickjacking
        headers["X-Frame-Options"] = "DENY";
        
        // Prevent MIME sniffing
        headers["X-Content-Type-Options"] = "nosniff";
        
        // Enable HSTS
        headers["Strict-Transport-Security"] = 
            "max-age=31536000; includeSubDomains";
        
        // Control referrer information
        headers["Referrer-Policy"] = 
            "strict-origin-when-cross-origin";
        
        // Content Security Policy
        headers["Content-Security-Policy"] = 
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
            "style-src 'self' 'unsafe-inline';";
        
        await _next(context);
    }
}
```

## Sample Test Payloads

### 1. Error Handling Tests

```csharp
[Fact]
public async Task ErrorHandler_HidesSensitiveInfo()
{
    var exception = new Exception(
        "Database connection string: xyz");
    
    var response = await _handler
        .HandleExceptionAsync(exception);
    
    Assert.DoesNotContain(
        "connection string",
        response.Message);
}
```

### 2. Data Masking Tests

```csharp
[Fact]
public void DataHandler_MasksSensitiveData()
{
    var data = new SensitiveData
    {
        Email = "user@example.com",
        Phone = "1234567890"
    };
    
    var masked = _handler.MaskSensitiveFields(data);
    
    Assert.Equal("u***@example.com", masked.Email);
    Assert.Equal("***7890", masked.Phone);
}
```

### 3. Configuration Security Tests

```csharp
[Fact]
public async Task Config_SecuresSecrets()
{
    var secret = new ApiSecret
    {
        Key = "api_key",
        Value = "secret_value"
    };
    
    await _config.SetSecureConfigAsync(
        "ApiSecret", 
        secret);
    
    var stored = await _config
        .GetSecureConfigAsync<ApiSecret>(
            "ApiSecret");
    
    Assert.NotEqual(
        secret.Value,
        stored.Value);
}
```

### 4. Headers Security Tests

```csharp
[Fact]
public async Task Headers_SetSecurityHeaders()
{
    var context = new DefaultHttpContext();
    
    await _middleware.InvokeAsync(context);
    
    Assert.Contains(
        "X-Frame-Options",
        context.Response.Headers.Keys);
    Assert.Equal(
        "DENY",
        context.Response.Headers["X-Frame-Options"]);
}
```

### 5. Logging Security Tests

```csharp
[Fact]
public void Logger_RedactsSensitiveInfo()
{
    var payment = new PaymentInfo
    {
        CardNumber = "4111111111111111",
        CVV = "123"
    };
    
    var logMessage = _logger.FormatMessage(payment);
    
    Assert.DoesNotContain(
        payment.CardNumber,
        logMessage);
    Assert.DoesNotContain(
        payment.CVV,
        logMessage);
}
```
