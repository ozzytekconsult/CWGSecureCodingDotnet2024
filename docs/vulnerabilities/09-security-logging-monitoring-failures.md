# Security Logging and Monitoring Failures

## Overview

Security Logging and Monitoring Failures, ranked #9 in the OWASP Top 10 2021, occur when applications fail to detect, escalate, or alert for security events. Key issues include:

- Insufficient logging
- Unclear log messages
- Missing critical events
- Inadequate monitoring
- No real-time alerts
- Unprotected log data
- Missing audit trails

In our application context, logging failures could affect:
- Authentication attempts
- Access control decisions
- Data modifications
- Payment processing
- Security events

## Technical Details

### Common Vulnerability Patterns

1. **Logging Gaps**
   - Missing security events
   - Insufficient detail
   - Inconsistent formats
   - Unprotected sensitive data

2. **Monitoring Weaknesses**
   - Delayed detection
   - Missing alerts
   - Poor visibility
   - Inadequate metrics

3. **Audit Trail Issues**
   - Incomplete history
   - Missing user context
   - Tampered logs
   - Insufficient retention

### Vulnerable Patterns in Our Domain

Using our solution's models, here are examples of vulnerable patterns:

```csharp
// Vulnerable: Insufficient authentication logging
public class AuthenticationService
{
    public async Task<bool> Login(string username, string password)
    {
        var user = await _userManager.FindByNameAsync(username);
        if (user == null) return false;
        
        // No logging of failed attempts
        return await _userManager.CheckPasswordAsync(
            user, password);
    }
}

// Vulnerable: Missing audit trail
public class Document
{
    public void UpdateContent(string content)
    {
        // No logging of content changes
        Content = content;
        LastModified = DateTime.UtcNow;
    }
}

// Vulnerable: Inadequate payment logging
public class PaymentProcessor
{
    public async Task ProcessPayment(Payment payment)
    {
        // Basic logging without security context
        _logger.LogInformation(
            "Processing payment {Id}", payment.Id);
        await _paymentGateway.ProcessAsync(payment);
    }
}
```

## OWASP Mitigation Details

1. **Logging Strategy**
   - Comprehensive events
   - Structured logging
   - Secure storage
   - Log rotation

2. **Monitoring Implementation**
   - Real-time monitoring
   - Alert thresholds
   - Security metrics
   - Incident response

3. **Audit Requirements**
   - Complete trails
   - Tamper protection
   - Retention policies
   - Access controls

4. **Security Events**
   - Authentication events
   - Authorization failures
   - Data access
   - System changes

## ASP.NET Core Mitigation Details

### 1. Secure Authentication Logging

```csharp
public class SecureAuthenticationService
{
    private readonly ILogger<SecureAuthenticationService> _logger;
    private readonly ISecurityEventService _securityEvents;
    
    public async Task<AuthResult> Login(
        string username,
        string password,
        HttpContext context)
    {
        try
        {
            // Log attempt with context
            var attemptId = await LogLoginAttempt(
                username, context);
            
            var user = await _userManager.FindByNameAsync(username);
            if (user == null)
            {
                await LogFailedAttempt(attemptId, 
                    "UserNotFound", username);
                return AuthResult.Failed();
            }
            
            if (await _userManager.IsLockedOutAsync(user))
            {
                await LogFailedAttempt(attemptId, 
                    "AccountLocked", username);
                return AuthResult.LockedOut();
            }
            
            if (!await _userManager.CheckPasswordAsync(user, password))
            {
                await LogFailedAttempt(attemptId, 
                    "InvalidPassword", username);
                    
                // Increment failed attempts
                await _userManager.AccessFailedAsync(user);
                return AuthResult.Failed();
            }
            
            // Log successful login
            await LogSuccessfulLogin(attemptId, user);
            
            return AuthResult.Success(user);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Login failed for user {Username}", username);
            return AuthResult.Error();
        }
    }
    
    private async Task<string> LogLoginAttempt(
        string username,
        HttpContext context)
    {
        var attempt = new SecurityEvent
        {
            EventType = "LoginAttempt",
            Username = username,
            IpAddress = context.Connection.RemoteIpAddress?.ToString(),
            UserAgent = context.Request.Headers["User-Agent"].ToString(),
            Timestamp = DateTime.UtcNow
        };
        
        return await _securityEvents.LogAsync(attempt);
    }
}
```

### 2. Document Audit Trail

```csharp
public class Document
{
    private readonly IAuditLogger _auditLogger;
    private readonly ILogger<Document> _logger;
    
    public async Task<DocumentResult> UpdateContent(
        string content,
        string userId)
    {
        try
        {
            // Create audit record
            var audit = new DocumentAudit
            {
                DocumentId = Id,
                UserId = userId,
                Operation = "UpdateContent",
                OldContent = Content,
                NewContent = content,
                Timestamp = DateTime.UtcNow
            };
            
            // Update content
            Content = content;
            LastModified = audit.Timestamp;
            ModifiedBy = userId;
            
            // Log audit with secure hash
            audit.ContentHash = ComputeHash(content);
            await _auditLogger.LogAsync(audit);
            
            // Raise security event
            await _securityEvents.RaiseAsync(
                "Document.Modified",
                new
                {
                    DocumentId = Id,
                    UserId = userId,
                    Operation = audit.Operation,
                    Hash = audit.ContentHash
                });
                
            return DocumentResult.Success();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Failed to update document {DocumentId}", Id);
            return DocumentResult.Error();
        }
    }
    
    private string ComputeHash(string content)
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(
            Encoding.UTF8.GetBytes(content));
        return Convert.ToBase64String(hash);
    }
}
```

### 3. Secure Payment Logging

```csharp
public class SecurePaymentProcessor
{
    private readonly ILogger<SecurePaymentProcessor> _logger;
    private readonly IAuditLogger _auditLogger;
    private readonly ISecurityEventService _securityEvents;
    
    public async Task<PaymentResult> ProcessPayment(
        Payment payment,
        string userId)
    {
        var correlationId = Guid.NewGuid().ToString();
        
        try
        {
            // Log payment attempt
            await LogPaymentAttempt(payment, userId, correlationId);
            
            // Validate payment
            if (!await ValidatePayment(payment))
            {
                await LogPaymentFailure(payment, 
                    "ValidationFailed", 
                    correlationId);
                return PaymentResult.ValidationFailed();
            }
            
            // Process payment
            var result = await _paymentGateway
                .ProcessAsync(payment);
                
            if (result.Success)
            {
                await LogPaymentSuccess(payment, 
                    result, 
                    correlationId);
            }
            else
            {
                await LogPaymentFailure(payment,
                    result.Error,
                    correlationId);
            }
            
            return result;
        }
        catch (Exception ex)
        {
            await LogPaymentError(payment, ex, correlationId);
            return PaymentResult.Error();
        }
    }
    
    private async Task LogPaymentAttempt(
        Payment payment,
        string userId,
        string correlationId)
    {
        // Secure logging - mask sensitive data
        var maskedPayment = new
        {
            payment.Id,
            payment.Amount,
            CardNumber = MaskCardNumber(payment.CardNumber),
            payment.Currency,
            UserId = userId,
            CorrelationId = correlationId
        };
        
        await _auditLogger.LogAsync(
            "Payment.Attempt",
            maskedPayment);
            
        await _securityEvents.RaiseAsync(
            "Payment.Initiated",
            maskedPayment);
    }
}
```

### 4. Security Monitoring Configuration

```csharp
public class SecurityMonitoringConfig
{
    public static IServiceCollection AddSecurityMonitoring(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Add structured logging
        services.AddLogging(builder =>
        {
            builder.AddSeq(configuration.GetSection("Seq"));
            builder.AddElasticSearch(
                configuration.GetSection("Elasticsearch"));
        });
        
        // Add security event service
        services.AddSecurityEventService(options =>
        {
            options.EnableRealTimeAlerts = true;
            options.AlertThresholds = new Dictionary<string, int>
            {
                ["FailedLogin"] = 5,
                ["PaymentFailure"] = 3,
                ["UnauthorizedAccess"] = 1
            };
        });
        
        // Add audit logging
        services.AddAuditLogging(options =>
        {
            options.ConnectionString = 
                configuration.GetConnectionString("AuditDb");
            options.RetentionDays = 365;
            options.EnableEncryption = true;
        });
        
        return services;
    }
}
```

## Sample Test Payloads

### 1. Authentication Logging Tests

```csharp
[Fact]
public async Task Login_LogsFailedAttempts()
{
    var service = new SecureAuthenticationService();
    
    await service.Login("invalid@example.com", "wrongpass");
    
    var events = await _securityEvents
        .GetEventsAsync("LoginAttempt");
        
    Assert.Single(events);
    Assert.Equal("InvalidPassword", events[0].Reason);
    Assert.NotNull(events[0].IpAddress);
}
```

### 2. Document Audit Tests

```csharp
[Fact]
public async Task UpdateContent_CreatesAuditTrail()
{
    var document = new Document();
    var userId = "test-user";
    
    await document.UpdateContent("New content", userId);
    
    var audit = await _auditLogger
        .GetEntriesAsync("Document.Modified");
        
    Assert.Single(audit);
    Assert.Equal(userId, audit[0].UserId);
    Assert.NotNull(audit[0].ContentHash);
}
```

### 3. Payment Logging Tests

```csharp
[Fact]
public async Task ProcessPayment_LogsSensitiveDataSecurely()
{
    var payment = new Payment
    {
        CardNumber = "4111111111111111",
        Amount = 100m
    };
    
    await _processor.ProcessPayment(payment, "userId");
    
    var logs = await _auditLogger
        .GetEntriesAsync("Payment.Attempt");
        
    Assert.Single(logs);
    Assert.Equal("411111******1111", logs[0].CardNumber);
}
```

### 4. Security Event Tests

```http
# Test security event generation
POST /api/documents HTTP/1.1
Content-Type: application/json
Authorization: Bearer invalid_token

{
    "content": "test"
}

# Expected security events:
# 1. UnauthorizedAccess
# 2. Alert triggered for immediate threshold
```

### 5. Monitoring Alert Tests

```csharp
[Fact]
public async Task FailedLogins_TriggersAlert()
{
    var service = new SecureAuthenticationService();
    
    // Generate 5 failed login attempts
    for (int i = 0; i < 5; i++)
    {
        await service.Login("test@example.com", "wrong");
    }
    
    var alerts = await _securityEvents
        .GetAlertsAsync("FailedLogin");
        
    Assert.Single(alerts);
    Assert.Equal("Multiple failed login attempts detected",
        alerts[0].Message);
}
```
