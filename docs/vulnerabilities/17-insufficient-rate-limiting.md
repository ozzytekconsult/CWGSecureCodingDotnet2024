# Insufficient Rate Limiting

## Overview

Insufficient Rate Limiting occurs when applications fail to:

- Limit request frequency
- Prevent brute force attacks
- Control resource consumption
- Manage API usage
- Protect against DoS
- Handle traffic spikes
- Enforce usage quotas

Critical areas requiring rate limiting:
- Authentication endpoints
- Password reset flows
- Search operations
- API endpoints
- File uploads
- Resource-intensive operations
- User registration

## Technical Details

### Common Attack Vectors

1. **Authentication Attacks**
   - Credential stuffing
   - Password spraying
   - Account enumeration
   - Token brute force
   - Session flooding

2. **Resource Exhaustion**
   - CPU exhaustion
   - Memory depletion
   - Disk space filling
   - Network saturation
   - Database connection pool exhaustion

3. **API Abuse**
   - Excessive requests
   - Parallel connections
   - Scraping attempts
   - Automated attacks
   - Service degradation

### Vulnerable Patterns in Our Domain

```csharp
// Vulnerable: No rate limiting on login
public class AuthController
{
    public async Task<IActionResult> Login(
        LoginModel model)
    {
        var result = await _signInManager
            .PasswordSignInAsync(model.Email, 
                model.Password, 
                false, false);
        
        return result.Succeeded
            ? RedirectToAction("Index")
            : View(model);
    }
}

// Vulnerable: Unprotected search endpoint
public class SearchController
{
    public async Task<IActionResult> Search(
        string query)
    {
        var results = await _searchService
            .SearchAsync(query);
        return Json(results);
    }
}

// Vulnerable: Unlimited API access
public class ApiController
{
    public async Task<IActionResult> GetData(
        string id)
    {
        var data = await _repository
            .GetDataAsync(id);
        return Json(data);
    }
}
```

## OWASP Mitigation Details

1. **Rate Limiting Strategy**
   - Request quotas
   - Time windows
   - IP-based limits
   - User-based limits
   - Endpoint-specific limits

2. **Response Strategy**
   - Graceful degradation
   - Clear error messages
   - Retry-After headers
   - Alternative endpoints
   - Backoff guidance

3. **Monitoring Strategy**
   - Usage tracking
   - Abuse detection
   - Alert thresholds
   - Traffic analysis
   - Performance monitoring

4. **Policy Strategy**
   - Fair usage policies
   - Service tiers
   - Quota management
   - Overage handling
   - Emergency responses

## ASP.NET Core Mitigation Details

### 1. Rate Limiting Middleware

```csharp
public class RateLimitingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RateLimitingMiddleware> _logger;
    private readonly IRateLimitingService _rateLimiter;
    private readonly IConfiguration _config;
    
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            // Get client identifier
            var clientId = GetClientIdentifier(context);
            
            // Get rate limit policy
            var policy = await GetRateLimitPolicy(
                context.Request);
            
            // Check rate limit
            var result = await _rateLimiter
                .CheckRateLimitAsync(clientId, policy);
            
            if (!result.IsAllowed)
            {
                await HandleRateLimitExceededAsync(
                    context, result);
                return;
            }
            
            // Add rate limit headers
            AddRateLimitHeaders(
                context.Response, result);
            
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Rate limiting error");
            throw;
        }
    }
    
    private string GetClientIdentifier(
        HttpContext context)
    {
        // Try authenticated user
        var userId = context.User?.Identity?.Name;
        if (!string.IsNullOrEmpty(userId))
            return $"user:{userId}";
        
        // Fall back to IP address
        var ip = context.Connection
            .RemoteIpAddress?.ToString();
        return $"ip:{ip}";
    }
    
    private void AddRateLimitHeaders(
        HttpResponse response,
        RateLimitResult result)
    {
        response.Headers["X-RateLimit-Limit"] = 
            result.Limit.ToString();
        response.Headers["X-RateLimit-Remaining"] = 
            result.Remaining.ToString();
        response.Headers["X-RateLimit-Reset"] = 
            result.ResetAt.ToUnixTimeSeconds()
                .ToString();
    }
}
```

### 2. Rate Limiting Service

```csharp
public class RateLimitingService
{
    private readonly IDistributedCache _cache;
    private readonly ILogger<RateLimitingService> _logger;
    
    public async Task<RateLimitResult> CheckRateLimitAsync(
        string clientId,
        RateLimitPolicy policy)
    {
        try
        {
            // Get current window
            var window = GetTimeWindow(
                policy.WindowSeconds);
            
            // Get cache key
            var key = GetCacheKey(
                clientId, 
                policy.ResourceName,
                window);
            
            // Get current count
            var count = await GetRequestCountAsync(key);
            
            if (count >= policy.MaxRequests)
            {
                return new RateLimitResult
                {
                    IsAllowed = false,
                    Limit = policy.MaxRequests,
                    Remaining = 0,
                    ResetAt = GetWindowResetTime(window)
                };
            }
            
            // Increment count
            await IncrementRequestCountAsync(
                key,
                window);
            
            return new RateLimitResult
            {
                IsAllowed = true,
                Limit = policy.MaxRequests,
                Remaining = policy.MaxRequests - count - 1,
                ResetAt = GetWindowResetTime(window)
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Rate limit check failed");
            throw;
        }
    }
    
    private async Task<int> GetRequestCountAsync(
        string key)
    {
        var value = await _cache.GetAsync(key);
        return value == null 
            ? 0 
            : BitConverter.ToInt32(value);
    }
    
    private async Task IncrementRequestCountAsync(
        string key,
        long window)
    {
        var count = await GetRequestCountAsync(key);
        var value = BitConverter.GetBytes(count + 1);
        
        await _cache.SetAsync(
            key,
            value,
            new DistributedCacheEntryOptions
            {
                AbsoluteExpiration = 
                    GetWindowResetTime(window)
            });
    }
}
```

### 3. Dynamic Rate Limiting

```csharp
public class DynamicRateLimitingService
{
    private readonly ILogger<DynamicRateLimitingService> _logger;
    private readonly ILoadMonitoringService _loadMonitor;
    
    public async Task<RateLimitPolicy> GetDynamicPolicyAsync(
        HttpRequest request)
    {
        try
        {
            // Get base policy
            var policy = GetBasePolicy(request);
            
            // Check system load
            var load = await _loadMonitor
                .GetCurrentLoadAsync();
            
            // Adjust limits based on load
            if (load.IsCritical)
            {
                return ApplyEmergencyLimits(policy);
            }
            
            if (load.IsHigh)
            {
                return ApplyRestrictiveLimits(policy);
            }
            
            return policy;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Dynamic policy calculation failed");
            throw;
        }
    }
    
    private RateLimitPolicy ApplyEmergencyLimits(
        RateLimitPolicy policy)
    {
        return new RateLimitPolicy
        {
            ResourceName = policy.ResourceName,
            MaxRequests = policy.MaxRequests / 10,
            WindowSeconds = policy.WindowSeconds,
            Priority = RequestPriority.Emergency
        };
    }
}
```

### 4. Rate Limit Policy Provider

```csharp
public class RateLimitPolicyProvider
{
    private readonly IConfiguration _config;
    private readonly ILogger<RateLimitPolicyProvider> _logger;
    
    public RateLimitPolicy GetPolicy(
        HttpRequest request)
    {
        // Get endpoint policy
        var endpoint = request.Path.ToString()
            .ToLowerInvariant();
            
        switch (endpoint)
        {
            case "/api/auth/login":
                return new RateLimitPolicy
                {
                    ResourceName = "login",
                    MaxRequests = 5,
                    WindowSeconds = 300, // 5 minutes
                    Priority = RequestPriority.Critical
                };
                
            case "/api/search":
                return new RateLimitPolicy
                {
                    ResourceName = "search",
                    MaxRequests = 30,
                    WindowSeconds = 60, // 1 minute
                    Priority = RequestPriority.Normal
                };
                
            default:
                return new RateLimitPolicy
                {
                    ResourceName = "default",
                    MaxRequests = 100,
                    WindowSeconds = 60,
                    Priority = RequestPriority.Low
                };
        }
    }
}
```

## Sample Test Payloads

### 1. Basic Rate Limiting Tests

```csharp
[Fact]
public async Task RateLimit_BlocksExcessiveRequests()
{
    var clientId = "test-client";
    var policy = new RateLimitPolicy
    {
        MaxRequests = 5,
        WindowSeconds = 60
    };
    
    // Make requests up to limit
    for (int i = 0; i < 5; i++)
    {
        var result = await _rateLimiter
            .CheckRateLimitAsync(clientId, policy);
        Assert.True(result.IsAllowed);
    }
    
    // Next request should be blocked
    var blocked = await _rateLimiter
        .CheckRateLimitAsync(clientId, policy);
    Assert.False(blocked.IsAllowed);
}
```

### 2. Window Reset Tests

```csharp
[Fact]
public async Task RateLimit_ResetsAfterWindow()
{
    var clientId = "test-client";
    var policy = new RateLimitPolicy
    {
        MaxRequests = 1,
        WindowSeconds = 1
    };
    
    // Use up limit
    var first = await _rateLimiter
        .CheckRateLimitAsync(clientId, policy);
    Assert.True(first.IsAllowed);
    
    // Wait for window reset
    await Task.Delay(1100);
    
    // Should allow new request
    var second = await _rateLimiter
        .CheckRateLimitAsync(clientId, policy);
    Assert.True(second.IsAllowed);
}
```

### 3. Dynamic Policy Tests

```csharp
[Fact]
public async Task DynamicPolicy_AdjustsToLoad()
{
    // Simulate high load
    _mockLoadMonitor.Setup(m => m.GetCurrentLoadAsync())
        .ReturnsAsync(new SystemLoad { IsHigh = true });
    
    var request = CreateTestRequest("/api/search");
    var policy = await _dynamicLimiter
        .GetDynamicPolicyAsync(request);
    
    Assert.True(
        policy.MaxRequests < 
        _basePolicy.MaxRequests);
}
```

### 4. Client Identification Tests

```csharp
[Fact]
public void ClientIdentifier_HandlesAllCases()
{
    // Authenticated user
    var authContext = CreateAuthenticatedContext("user1");
    var userId = _middleware
        .GetClientIdentifier(authContext);
    Assert.StartsWith("user:", userId);
    
    // Anonymous user
    var anonContext = CreateAnonymousContext("1.2.3.4");
    var ipId = _middleware
        .GetClientIdentifier(anonContext);
    Assert.StartsWith("ip:", ipId);
}
```

### 5. Header Tests

```csharp
[Fact]
public async Task RateLimit_SetsHeaders()
{
    var context = new DefaultHttpContext();
    var result = new RateLimitResult
    {
        Limit = 100,
        Remaining = 99,
        ResetAt = DateTimeOffset.UtcNow
            .AddMinutes(1)
    };
    
    _middleware.AddRateLimitHeaders(
        context.Response, result);
    
    Assert.Equal("100", context.Response
        .Headers["X-RateLimit-Limit"]);
    Assert.Equal("99", context.Response
        .Headers["X-RateLimit-Remaining"]);
}
```
