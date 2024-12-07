# Security Misconfiguration

## Overview

Security Misconfiguration, ranked #5 in the OWASP Top 10 2021, occurs when security settings are defined, implemented, or maintained improperly. This includes:

- Missing security headers
- Unnecessary features enabled
- Default accounts/passwords
- Overly detailed error messages
- Disabled security features
- Outdated software
- Insecure system configurations

In our application context, security misconfiguration could affect:
- Web server settings
- Framework configurations
- Database security settings
- Application security features
- Cloud service configurations

## Technical Details

### Common Vulnerability Patterns

1. **Framework Misconfigurations**
   - Debug mode enabled
   - Default configurations unchanged
   - Development features in production
   - Missing security middleware

2. **Server Misconfigurations**
   - Directory listing enabled
   - Default credentials
   - Unnecessary services
   - Insecure SSL/TLS settings

3. **Application Misconfigurations**
   - Detailed error messages
   - Missing security headers
   - Insecure cookie settings
   - CORS misconfiguration

### Vulnerable Patterns in Our Domain

Using our solution's models, here are examples of vulnerable patterns:

```csharp
// Vulnerable: Insecure application configuration
public class Startup
{
    public void Configure(IApplicationBuilder app)
    {
        // Development features in production
        app.UseDeveloperExceptionPage();
        
        // Missing security headers
        app.UseRouting();
        app.UseEndpoints(endpoints => 
        {
            endpoints.MapControllers();
        });
    }
}

// Vulnerable: Detailed error exposure
public class DocumentController
{
    public IActionResult GetDocument(int id)
    {
        try
        {
            var doc = _context.Documents.Find(id);
            return Ok(doc);
        }
        catch (Exception ex)
        {
            // Exposing detailed error
            return StatusCode(500, ex.ToString());
        }
    }
}

// Vulnerable: Insecure cookie configuration
public class UserSession
{
    public void SetSessionCookie(HttpContext context)
    {
        context.Response.Cookies.Append("SessionId", 
            SessionId,
            new CookieOptions
            {
                // Missing security options
                HttpOnly = false,
                Secure = false
            });
    }
}
```

## OWASP Mitigation Details

1. **Security Hardening**
   - Secure defaults
   - Minimal attack surface
   - Defense in depth
   - Least privilege

2. **Configuration Management**
   - Configuration review
   - Security baselines
   - Change control
   - Environment separation

3. **Error Handling**
   - Generic error messages
   - Custom error pages
   - Logging configuration
   - Debug mode control

4. **Security Headers**
   - HTTP security headers
   - Content security policy
   - Cookie security
   - CORS policy

## ASP.NET Core Mitigation Details

### 1. Secure Application Configuration

```csharp
public class Startup
{
    private readonly IWebHostEnvironment _env;
    
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddControllers()
            .ConfigureApiBehaviorOptions(options =>
            {
                options.SuppressModelStateInvalidFilter = false;
                options.InvalidModelStateResponseFactory = 
                    ActionContext =>
                    {
                        var result = new BadRequestObjectResult(
                            ActionContext.ModelState);
                        result.ContentTypes.Clear();
                        result.ContentTypes.Add(
                            "application/problem+json");
                        return result;
                    };
            });
            
        // Add security services
        services.AddHsts(options =>
        {
            options.MaxAge = TimeSpan.FromDays(365);
            options.IncludeSubDomains = true;
            options.Preload = true;
        });
        
        services.AddHttpsRedirection(options =>
        {
            options.RedirectStatusCode = 
                StatusCodes.Status307TemporaryRedirect;
            options.HttpsPort = 443;
        });
    }
    
    public void Configure(IApplicationBuilder app)
    {
        if (_env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/error");
            app.UseHsts();
        }
        
        // Security middleware
        app.UseHttpsRedirection();
        app.UseSecurityHeaders();
        
        app.UseRouting();
        
        // Configure CORS
        app.UseCors(policy => 
        {
            policy.WithOrigins("https://trusted-origin.com")
                .AllowAnyMethod()
                .AllowAnyHeader()
                .AllowCredentials();
        });
        
        app.UseAuthentication();
        app.UseAuthorization();
        
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers()
                .RequireAuthorization();
        });
    }
}
```

### 2. Secure Error Handling

```csharp
public class ErrorHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ErrorHandlingMiddleware> _logger;
    private readonly IWebHostEnvironment _env;
    
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "An unhandled exception occurred");
                
            await HandleExceptionAsync(context, ex);
        }
    }
    
    private Task HandleExceptionAsync(
        HttpContext context, Exception ex)
    {
        var error = new ApiError();
        
        if (_env.IsDevelopment())
        {
            error.Detail = ex.ToString();
        }
        else
        {
            error.Detail = "An unexpected error occurred.";
        }
        
        context.Response.StatusCode = 
            StatusCodes.Status500InternalServerError;
        context.Response.ContentType = 
            "application/problem+json";
            
        return context.Response.WriteAsJsonAsync(error);
    }
}
```

### 3. Secure Session Configuration

```csharp
public class SessionConfig
{
    public static void ConfigureSession(
        IServiceCollection services)
    {
        services.AddSession(options =>
        {
            options.Cookie.Name = ".App.Session";
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = 
                CookieSecurePolicy.Always;
            options.Cookie.SameSite = 
                SameSiteMode.Strict;
            options.IdleTimeout = TimeSpan.FromMinutes(20);
        });
        
        services.AddDataProtection()
            .SetApplicationName("AppName")
            .SetDefaultKeyLifetime(TimeSpan.FromDays(14))
            .PersistKeysToFileSystem(
                new DirectoryInfo(@"path\to\keys"));
    }
}
```

### 4. Security Headers Middleware

```csharp
public class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;
    
    public async Task InvokeAsync(HttpContext context)
    {
        // Add security headers
        context.Response.Headers.Add(
            "X-Content-Type-Options", "nosniff");
        context.Response.Headers.Add(
            "X-Frame-Options", "DENY");
        context.Response.Headers.Add(
            "X-XSS-Protection", "1; mode=block");
        context.Response.Headers.Add(
            "Referrer-Policy", "strict-origin-when-cross-origin");
        context.Response.Headers.Add(
            "Permissions-Policy", 
            "accelerometer=(), camera=(), geolocation=(), " +
            "gyroscope=(), magnetometer=(), microphone=(), " +
            "payment=(), usb=()");
            
        // Content Security Policy
        context.Response.Headers.Add(
            "Content-Security-Policy",
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data: https:; " +
            "font-src 'self'; " +
            "connect-src 'self';");
            
        await _next(context);
    }
}
```

## Sample Test Payloads

### 1. Security Headers Tests

```http
# Test missing security headers
GET / HTTP/1.1
Host: example.com

# Expected response headers:
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
```

### 2. Error Handling Tests

```http
# Test detailed error exposure
GET /api/documents/invalid HTTP/1.1
Host: example.com

# Expected: Generic error message in production
{
    "type": "https://tools.ietf.org/html/rfc7231#section-6.6.1",
    "title": "An error occurred while processing your request.",
    "status": 500,
    "traceId": "00-1234...5678"
}
```

### 3. CORS Tests

```http
# Test CORS configuration
OPTIONS /api/documents HTTP/1.1
Host: example.com
Origin: https://malicious-site.com
Access-Control-Request-Method: POST

# Expected: CORS error for unauthorized origin
```

### 4. Cookie Security Tests

```http
# Test cookie security attributes
POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/json

{
    "username": "test@example.com",
    "password": "password123"
}

# Expected cookie attributes:
# Secure; HttpOnly; SameSite=Strict
```

### 5. TLS Configuration Tests

```bash
# Test SSL/TLS configuration
nmap --script ssl-enum-ciphers -p 443 example.com

# Expected: Only strong ciphers
# No support for TLS 1.0/1.1
# Perfect Forward Secrecy enabled
```
