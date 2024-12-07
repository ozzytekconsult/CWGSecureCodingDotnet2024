# Server-Side Request Forgery (SSRF)

## Overview

Server-Side Request Forgery (SSRF), ranked #10 in the OWASP Top 10 2021, occurs when an application makes HTTP requests to an arbitrary URL that is partially or fully controlled by an attacker. Key issues include:

- Access to internal services
- Cloud service metadata access
- Port scanning
- File system access
- Remote code execution
- Service exploitation
- Data exfiltration

In our application context, SSRF could affect:
- Document URL processing
- Payment gateway integration
- External API calls
- Image processing
- Resource fetching

## Technical Details

### Common Attack Vectors

1. **Direct SSRF**
   - URL parameter manipulation
   - Path traversal in URLs
   - Protocol smuggling
   - DNS rebinding

2. **Indirect SSRF**
   - Webhook configurations
   - File uploads with URLs
   - API integrations
   - Resource references

3. **Cloud Metadata Attacks**
   - AWS metadata endpoint access
   - Azure instance metadata
   - GCP metadata server
   - Cloud credentials theft

### Vulnerable Patterns in Our Domain

Using our solution's models, here are examples of vulnerable patterns:

```csharp
// Vulnerable: Direct URL fetch
public class Document
{
    public async Task<string> FetchContent(string url)
    {
        // Direct URL fetch without validation
        using var client = new HttpClient();
        return await client.GetStringAsync(url);
    }
}

// Vulnerable: Webhook processing
public class PaymentProcessor
{
    public async Task ProcessWebhook(string callbackUrl)
    {
        // Unvalidated webhook URL
        using var client = new HttpClient();
        await client.PostAsync(callbackUrl, null);
    }
}

// Vulnerable: Image processing
public class Product
{
    public async Task<byte[]> FetchImage(string imageUrl)
    {
        // Direct image fetch without validation
        using var client = new HttpClient();
        return await client.GetByteArrayAsync(imageUrl);
    }
}
```

## OWASP Mitigation Details

1. **URL Validation**
   - Whitelist allowed domains
   - Block internal ranges
   - Validate protocols
   - Check redirects

2. **Network Controls**
   - Segregate networks
   - Block metadata endpoints
   - Restrict outbound access
   - Use proxy servers

3. **Request Hardening**
   - Disable redirects
   - Timeout controls
   - Response validation
   - Protocol restrictions

4. **Access Controls**
   - Least privilege
   - Network policies
   - Service isolation
   - Resource restrictions

## ASP.NET Core Mitigation Details

### 1. Secure URL Fetching

```csharp
public class SecureUrlFetcher
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<SecureUrlFetcher> _logger;
    private readonly UrlValidationOptions _options;
    
    public SecureUrlFetcher(
        HttpClient httpClient,
        IOptions<UrlValidationOptions> options,
        ILogger<SecureUrlFetcher> logger)
    {
        _httpClient = httpClient;
        _options = options.Value;
        _logger = logger;
        
        // Configure client
        _httpClient.DefaultRequestHeaders.Add(
            "User-Agent", "SecureApp/1.0");
        _httpClient.Timeout = TimeSpan.FromSeconds(10);
    }
    
    public async Task<FetchResult> FetchUrlAsync(string url)
    {
        try
        {
            // Validate URL
            if (!ValidateUrl(url))
            {
                _logger.LogWarning(
                    "Blocked request to unauthorized URL: {Url}", 
                    url);
                return FetchResult.Unauthorized();
            }
            
            // Create request
            using var request = new HttpRequestMessage(
                HttpMethod.Get, url);
                
            // Disable automatic redirects
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                MaxAutomaticRedirections = 0
            };
            
            // Send request
            using var response = await _httpClient
                .SendAsync(request);
                
            // Validate response
            if (!ValidateResponse(response))
            {
                return FetchResult.InvalidResponse();
            }
            
            return FetchResult.Success(
                await response.Content.ReadAsStringAsync());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Error fetching URL: {Url}", url);
            return FetchResult.Error();
        }
    }
    
    private bool ValidateUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;
            
        // Check protocol
        if (uri.Scheme != "https")
            return false;
            
        // Check against whitelist
        if (!_options.AllowedDomains.Any(domain => 
            uri.Host.EndsWith(domain, StringComparison.OrdinalIgnoreCase)))
            return false;
            
        // Check for internal addresses
        if (IsInternalAddress(uri))
            return false;
            
        return true;
    }
    
    private bool IsInternalAddress(Uri uri)
    {
        // Resolve IP address
        if (IPAddress.TryParse(uri.Host, out var ip))
        {
            return IsPrivateNetwork(ip);
        }
        
        try
        {
            var ips = Dns.GetHostAddresses(uri.Host);
            return ips.Any(IsPrivateNetwork);
        }
        catch
        {
            return true; // Fail safe
        }
    }
    
    private bool IsPrivateNetwork(IPAddress ip)
    {
        // Check RFC 1918 ranges
        if (ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();
            
        byte[] bytes = ip.GetAddressBytes();
        
        // 10.0.0.0/8
        if (bytes[0] == 10)
            return true;
            
        // 172.16.0.0/12
        if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            return true;
            
        // 192.168.0.0/16
        if (bytes[0] == 192 && bytes[1] == 168)
            return true;
            
        // 127.0.0.0/8
        if (bytes[0] == 127)
            return true;
            
        return false;
    }
}
```

### 2. Secure Document Processing

```csharp
public class Document
{
    private readonly ISecureUrlFetcher _urlFetcher;
    private readonly ILogger<Document> _logger;
    
    public async Task<DocumentResult> ProcessExternalContent(
        string url,
        string userId)
    {
        try
        {
            // Fetch content securely
            var result = await _urlFetcher.FetchUrlAsync(url);
            if (!result.Success)
            {
                _logger.LogWarning(
                    "Failed to fetch content from {Url}: {Error}",
                    url, result.Error);
                return DocumentResult.Failed(result.Error);
            }
            
            // Process content
            Content = result.Content;
            LastModified = DateTime.UtcNow;
            ModifiedBy = userId;
            
            return DocumentResult.Success();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Error processing external content from {Url}",
                url);
            return DocumentResult.Error();
        }
    }
}
```

### 3. Secure Webhook Processing

```csharp
public class WebhookProcessor
{
    private readonly ISecureUrlFetcher _urlFetcher;
    private readonly ILogger<WebhookProcessor> _logger;
    
    public async Task<WebhookResult> ProcessWebhook(
        WebhookRequest request)
    {
        try
        {
            // Validate webhook configuration
            if (!ValidateWebhook(request))
            {
                _logger.LogWarning(
                    "Invalid webhook configuration: {WebhookId}",
                    request.WebhookId);
                return WebhookResult.InvalidConfig();
            }
            
            // Create signed payload
            var payload = CreateSignedPayload(request);
            
            // Send webhook
            var result = await _urlFetcher.PostAsync(
                request.Url,
                payload,
                new Dictionary<string, string>
                {
                    ["X-Webhook-Signature"] = payload.Signature
                });
                
            if (!result.Success)
            {
                _logger.LogWarning(
                    "Webhook delivery failed: {Error}",
                    result.Error);
                return WebhookResult.DeliveryFailed();
            }
            
            return WebhookResult.Success();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Error processing webhook: {WebhookId}",
                request.WebhookId);
            return WebhookResult.Error();
        }
    }
    
    private bool ValidateWebhook(WebhookRequest request)
    {
        // Validate URL
        if (!Uri.TryCreate(request.Url, UriKind.Absolute, out var uri))
            return false;
            
        // Must use HTTPS
        if (uri.Scheme != "https")
            return false;
            
        // Check against registered webhooks
        return _webhookRegistry.IsRegistered(
            request.WebhookId,
            uri.Host);
    }
}
```

## Sample Test Payloads

### 1. Internal Network Access Tests

```http
# Test internal network access
POST /api/documents/fetch HTTP/1.1
Content-Type: application/json

{
    "url": "http://192.168.1.1/admin"
}

# Expected: 400 Bad Request
# Invalid URL: Internal network access not allowed
```

### 2. Cloud Metadata Tests

```http
# Test AWS metadata access
POST /api/documents/fetch HTTP/1.1
Content-Type: application/json

{
    "url": "http://169.254.169.254/latest/meta-data/"
}

# Expected: 400 Bad Request
# Invalid URL: Metadata access not allowed
```

### 3. Protocol Tests

```http
# Test non-HTTPS protocol
POST /api/documents/fetch HTTP/1.1
Content-Type: application/json

{
    "url": "ftp://example.com/file"
}

# Expected: 400 Bad Request
# Invalid protocol: Only HTTPS allowed
```

### 4. Redirect Tests

```csharp
[Fact]
public async Task FetchUrl_BlocksRedirectsToInternalNetworks()
{
    var fetcher = new SecureUrlFetcher();
    var url = "https://evil.com/redirect";  // Redirects to 192.168.1.1
    
    var result = await fetcher.FetchUrlAsync(url);
    
    Assert.False(result.Success);
    Assert.Equal("Redirect to internal network blocked", 
        result.Error);
}
```

### 5. DNS Rebinding Tests

```csharp
[Fact]
public async Task FetchUrl_BlocksDnsRebinding()
{
    var fetcher = new SecureUrlFetcher();
    
    // First request resolves to external IP
    var result1 = await fetcher.FetchUrlAsync(
        "https://rebind.example.com");
    Assert.True(result1.Success);
    
    // Second request resolves to internal IP
    var result2 = await fetcher.FetchUrlAsync(
        "https://rebind.example.com");
    Assert.False(result2.Success);
    Assert.Equal("DNS rebinding attempt detected", 
        result2.Error);
}
```
