# Insufficient Logging and Monitoring

## Overview

Insufficient Logging and Monitoring occurs when applications fail to:

- Record security-critical events
- Generate adequate log details
- Monitor system activities
- Detect security incidents
- Respond to security alerts
- Maintain audit trails
- Track user activities

Critical events requiring logging include:
- Authentication attempts
- Authorization failures
- Input validation failures
- Application errors
- Configuration changes
- Data access patterns
- System health metrics

## Technical Details

### Common Logging Gaps

1. **Authentication Events**
   - Failed login attempts
   - Password changes
   - Account lockouts
   - Session management
   - Token operations

2. **Authorization Events**
   - Access denials
   - Permission changes
   - Role modifications
   - Elevation attempts
   - Resource access

3. **Data Operations**
   - Create/Read/Update/Delete
   - Bulk operations
   - Export/Import
   - Data transfers
   - Schema changes

### Vulnerable Patterns in Our Domain

```csharp
// Vulnerable: No authentication logging
public class AuthController
{
    public async Task<IActionResult> Login(
        LoginModel model)
    {
        var result = await _signInManager
            .PasswordSignInAsync(model.Email, 
                model.Password, 
                model.RememberMe, 
                lockoutOnFailure: false);
        
        return result.Succeeded 
            ? RedirectToAction("Index") 
            : View(model);
    }
}

// Vulnerable: Insufficient error logging
public class DocumentService
{
    public async Task<Document> GetDocument(string id)
    {
        try
        {
            return await _repository
                .GetDocumentAsync(id);
        }
        catch
        {
            return null; // Silent failure
        }
    }
}

// Vulnerable: No audit logging
public class UserManager
{
    public async Task UpdatePermissions(
        string userId, 
        List<string> permissions)
    {
        var user = await _userRepository
            .GetUserAsync(userId);
        user.Permissions = permissions;
        await _userRepository.SaveAsync();
    }
}
```

## OWASP Mitigation Details

1. **Logging Strategy**
   - Event identification
   - Log levels
   - Data elements
   - Format standards
   - Retention policy

2. **Monitoring Strategy**
   - Real-time alerts
   - Threshold monitoring
   - Pattern detection
   - Anomaly detection
   - Health checks

3. **Response Strategy**
   - Alert prioritization
   - Incident response
   - Escalation paths
   - Recovery procedures
   - Post-mortem analysis

4. **Audit Strategy**
   - Compliance requirements
   - Data retention
   - Access controls
   - Integrity checks
   - Regular reviews

## ASP.NET Core Mitigation Details

### 1. Secure Logging Service

```csharp
public class SecureLoggingService
{
    private readonly ILogger<SecureLoggingService> _logger;
    private readonly IHttpContextAccessor _contextAccessor;
    private readonly IConfiguration _config;
    
    public async Task LogSecurityEventAsync(
        SecurityEvent eventData)
    {
        try
        {
            // Enrich with context
            var enrichedEvent = await EnrichEventAsync(
                eventData);
            
            // Log based on severity
            switch (eventData.Severity)
            {
                case SecuritySeverity.Critical:
                    _logger.LogCritical(
                        CreateLogMessage(enrichedEvent));
                    await AlertSecurityTeamAsync(
                        enrichedEvent);
                    break;
                    
                case SecuritySeverity.High:
                    _logger.LogError(
                        CreateLogMessage(enrichedEvent));
                    await NotifyAdministratorsAsync(
                        enrichedEvent);
                    break;
                    
                case SecuritySeverity.Medium:
                    _logger.LogWarning(
                        CreateLogMessage(enrichedEvent));
                    break;
                    
                default:
                    _logger.LogInformation(
                        CreateLogMessage(enrichedEvent));
                    break;
            }
            
            // Store for audit
            await StoreAuditLogAsync(enrichedEvent);
        }
        catch (Exception ex)
        {
            // Fallback logging
            _logger.LogError(ex, 
                "Logging system error");
        }
    }
    
    private async Task<EnrichedSecurityEvent> 
        EnrichEventAsync(SecurityEvent eventData)
    {
        var context = _contextAccessor
            .HttpContext;
            
        return new EnrichedSecurityEvent
        {
            Timestamp = DateTimeOffset.UtcNow,
            EventId = Guid.NewGuid().ToString(),
            EventType = eventData.EventType,
            Severity = eventData.Severity,
            Message = eventData.Message,
            UserId = context?.User?.Identity?.Name,
            IpAddress = context?.Connection
                ?.RemoteIpAddress?.ToString(),
            UserAgent = context?.Request
                ?.Headers["User-Agent"].ToString(),
            RequestPath = context?.Request?.Path,
            RequestMethod = context?.Request?.Method,
            CorrelationId = Activity.Current?.Id
                ?? context?.TraceIdentifier,
            AdditionalData = eventData.AdditionalData
        };
    }
}
```

### 2. Security Monitoring Service

```csharp
public class SecurityMonitoringService
{
    private readonly ILogger<SecurityMonitoringService> _logger;
    private readonly ISecurityAlertService _alertService;
    private readonly IConfiguration _config;
    
    public async Task MonitorSecurityEventsAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            var rules = await LoadMonitoringRulesAsync();
            
            while (!cancellationToken.IsCancellationRequested)
            {
                // Process security events
                var events = await GetSecurityEventsAsync();
                
                foreach (var evt in events)
                {
                    // Apply monitoring rules
                    foreach (var rule in rules)
                    {
                        if (await rule.EvaluateAsync(evt))
                        {
                            await HandleSecurityAlertAsync(
                                rule, evt);
                        }
                    }
                }
                
                await Task.Delay(
                    _config.GetValue<int>(
                        "Monitoring:Interval"),
                    cancellationToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Security monitoring error");
            throw;
        }
    }
    
    private async Task HandleSecurityAlertAsync(
        MonitoringRule rule,
        SecurityEvent evt)
    {
        var alert = new SecurityAlert
        {
            RuleId = rule.Id,
            EventData = evt,
            Timestamp = DateTimeOffset.UtcNow,
            Severity = rule.Severity,
            Message = rule.FormatAlertMessage(evt)
        };
        
        await _alertService.ProcessAlertAsync(alert);
    }
}
```

### 3. Audit Trail Service

```csharp
public class AuditTrailService
{
    private readonly ILogger<AuditTrailService> _logger;
    private readonly IAuditRepository _repository;
    
    public async Task<AuditTrail> CreateAuditTrailAsync(
        AuditableOperation operation)
    {
        try
        {
            var trail = new AuditTrail
            {
                OperationId = Guid.NewGuid(),
                Timestamp = DateTimeOffset.UtcNow,
                OperationType = operation.Type,
                EntityType = operation.EntityType,
                EntityId = operation.EntityId,
                UserId = operation.UserId,
                OldValue = operation.OldValue,
                NewValue = operation.NewValue,
                Changes = GetDetailedChanges(
                    operation.OldValue,
                    operation.NewValue)
            };
            
            // Store audit trail
            await _repository.SaveAuditTrailAsync(
                trail);
            
            // Log audit event
            _logger.LogInformation(
                "Audit trail created: {TrailId}",
                trail.OperationId);
            
            return trail;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Audit trail creation failed");
            throw;
        }
    }
    
    private List<AuditChange> GetDetailedChanges(
        object oldValue,
        object newValue)
    {
        var changes = new List<AuditChange>();
        
        if (oldValue == null || newValue == null)
            return changes;
            
        var properties = oldValue.GetType()
            .GetProperties();
            
        foreach (var prop in properties)
        {
            var oldVal = prop.GetValue(oldValue);
            var newVal = prop.GetValue(newValue);
            
            if (!Equals(oldVal, newVal))
            {
                changes.Add(new AuditChange
                {
                    PropertyName = prop.Name,
                    OldValue = oldVal?.ToString(),
                    NewValue = newVal?.ToString()
                });
            }
        }
        
        return changes;
    }
}
```

### 4. Health Monitoring Service

```csharp
public class HealthMonitoringService
{
    private readonly ILogger<HealthMonitoringService> _logger;
    private readonly IHealthCheckService _healthCheck;
    
    public async Task MonitorHealthAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var health = await _healthCheck
                    .CheckHealthAsync();
                
                // Log health status
                _logger.LogInformation(
                    "Health Status: {Status}",
                    health.Status);
                
                // Check thresholds
                foreach (var entry in health.Entries)
                {
                    if (entry.Value.Status == 
                        HealthStatus.Unhealthy)
                    {
                        await HandleUnhealthyServiceAsync(
                            entry.Key,
                            entry.Value);
                    }
                }
                
                await Task.Delay(
                    TimeSpan.FromMinutes(5),
                    cancellationToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Health monitoring error");
            throw;
        }
    }
}
```

## Sample Test Payloads

### 1. Security Event Logging Tests

```csharp
[Fact]
public async Task LogSecurityEvent_LogsAllDetails()
{
    var evt = new SecurityEvent
    {
        EventType = "Authentication",
        Severity = SecuritySeverity.High,
        Message = "Failed login attempt"
    };
    
    await _loggingService.LogSecurityEventAsync(evt);
    
    var log = _logStore.LastLog;
    Assert.Contains("Authentication", log);
    Assert.Contains("High", log);
    Assert.Contains("Failed login", log);
}
```

### 2. Monitoring Rule Tests

```csharp
[Fact]
public async Task MonitoringRule_DetectsViolations()
{
    var rule = new MonitoringRule
    {
        Type = "FailedLogin",
        Threshold = 5,
        TimeWindow = TimeSpan.FromMinutes(5)
    };
    
    // Generate events
    for (int i = 0; i < 6; i++)
    {
        await _monitoringService
            .ProcessEventAsync(new SecurityEvent
            {
                EventType = "FailedLogin",
                UserId = "test@example.com"
            });
    }
    
    var alerts = await _alertService.GetAlertsAsync();
    Assert.Single(alerts);
    Assert.Equal("FailedLogin", alerts[0].RuleId);
}
```

### 3. Audit Trail Tests

```csharp
[Fact]
public async Task AuditTrail_TracksChanges()
{
    var oldUser = new User { Name = "Old Name" };
    var newUser = new User { Name = "New Name" };
    
    var operation = new AuditableOperation
    {
        Type = "UserUpdate",
        EntityType = "User",
        OldValue = oldUser,
        NewValue = newUser
    };
    
    var trail = await _auditService
        .CreateAuditTrailAsync(operation);
    
    Assert.Single(trail.Changes);
    Assert.Equal("Name", trail.Changes[0].PropertyName);
    Assert.Equal("Old Name", trail.Changes[0].OldValue);
    Assert.Equal("New Name", trail.Changes[0].NewValue);
}
```

### 4. Health Monitoring Tests

```csharp
[Fact]
public async Task HealthCheck_DetectsIssues()
{
    // Simulate unhealthy service
    _mockDatabase.Setup(db => db.IsHealthy())
        .Returns(false);
    
    var health = await _healthService
        .CheckHealthAsync();
    
    Assert.Equal(
        HealthStatus.Unhealthy,
        health.Status);
    Assert.Contains(
        health.Entries,
        e => e.Value.Status == HealthStatus.Unhealthy);
}
```

### 5. Alert Processing Tests

```csharp
[Fact]
public async Task SecurityAlert_ProcessesCorrectly()
{
    var alert = new SecurityAlert
    {
        Severity = SecuritySeverity.Critical,
        Message = "Potential data breach detected"
    };
    
    await _alertService.ProcessAlertAsync(alert);
    
    // Verify notifications
    Assert.True(_mockNotifier
        .ReceivedNotification(alert));
    
    // Verify escalation
    Assert.True(_mockEscalation
        .WasEscalated(alert));
}
```
