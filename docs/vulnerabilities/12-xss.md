# Cross-Site Scripting (XSS)

## Overview

Cross-Site Scripting (XSS), ranked #12 in the OWASP Top 10 2021, occurs when untrusted data is included in a web page without proper validation or escaping. Key issues include:

- Stored XSS (Persistent)
- Reflected XSS (Non-Persistent)
- DOM-based XSS
- Mutation XSS
- Template Injection
- Script Injection
- Event Handler Injection

In our application context, XSS could affect:
- Document content display
- User input fields
- Product descriptions
- Order details
- Payment forms

## Technical Details

### Common Attack Vectors

1. **Stored XSS**
   - Persisted malicious content
   - Database-stored scripts
   - User profile data
   - Comments/reviews

2. **Reflected XSS**
   - URL parameters
   - Form inputs
   - Search queries
   - Error messages

3. **DOM-based XSS**
   - Client-side manipulation
   - JavaScript frameworks
   - Dynamic content
   - Template rendering

### Vulnerable Patterns in Our Domain

Using our solution's models, here are examples of vulnerable patterns:

```csharp
// Vulnerable: Direct content rendering
public class Document
{
    public string GetHtmlContent()
    {
        // Directly returning unescaped content
        return $"<div>{Content}</div>";
    }
}

// Vulnerable: Reflected user input
public class ProductController
{
    public IActionResult Search(string query)
    {
        // Reflecting unescaped search query
        ViewBag.SearchTerm = query;
        return View();
    }
}

// Vulnerable: Stored user content
public class Order
{
    public string GetOrderSummary()
    {
        // Unescaped customer notes
        return $"<div class='notes'>{CustomerNotes}</div>";
    }
}
```

## OWASP Mitigation Details

1. **Input Validation**
   - Whitelist validation
   - Character filtering
   - Length restrictions
   - Format validation

2. **Output Encoding**
   - Context-aware encoding
   - HTML encoding
   - JavaScript encoding
   - URL encoding

3. **Security Headers**
   - Content Security Policy
   - X-XSS-Protection
   - X-Content-Type-Options
   - Frame options

4. **Framework Controls**
   - Built-in protections
   - Encoding helpers
   - Security middleware
   - Sanitization libraries

## ASP.NET Core Mitigation Details

### 1. Secure Document Display

```csharp
public class Document
{
    private readonly IHtmlSanitizer _sanitizer;
    private readonly ILogger<Document> _logger;
    
    public string GetSafeHtmlContent()
    {
        try
        {
            // Sanitize content
            var sanitized = _sanitizer.Sanitize(Content);
            
            // Encode for HTML context
            var encoded = HtmlEncoder.Default.Encode(sanitized);
            
            return new HtmlString(encoded).ToString();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Error sanitizing document content");
            return string.Empty;
        }
    }
    
    public async Task<DocumentResult> SetContent(
        string content,
        string userId)
    {
        try
        {
            // Validate content
            if (!await ValidateContent(content))
                return DocumentResult.InvalidContent();
                
            // Sanitize before storage
            Content = _sanitizer.Sanitize(content);
            LastModified = DateTime.UtcNow;
            ModifiedBy = userId;
            
            return DocumentResult.Success();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Error setting document content");
            return DocumentResult.Error();
        }
    }
    
    private async Task<bool> ValidateContent(string content)
    {
        if (string.IsNullOrEmpty(content))
            return false;
            
        // Check length
        if (content.Length > MaxContentLength)
            return false;
            
        // Check for suspicious patterns
        if (ContainsSuspiciousPatterns(content))
            return false;
            
        return true;
    }
}
```

### 2. Secure Controller Implementation

```csharp
public class SecureController : Controller
{
    private readonly IHtmlSanitizer _sanitizer;
    private readonly ILogger<SecureController> _logger;
    
    [HttpGet]
    public IActionResult Search(string query)
    {
        try
        {
            // Validate input
            if (!ValidateSearchQuery(query))
                return BadRequest("Invalid search query");
                
            // Encode for view display
            ViewBag.SearchTerm = HtmlEncoder.Default
                .Encode(query);
                
            return View();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Error processing search query");
            return Error();
        }
    }
    
    [HttpPost]
    public async Task<IActionResult> SaveComment(
        CommentModel model)
    {
        try
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
                
            // Sanitize user input
            model.Content = _sanitizer.Sanitize(model.Content);
            
            // Save sanitized content
            await _commentService.SaveAsync(model);
            
            return Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Error saving comment");
            return Error();
        }
    }
}
```

### 3. Secure View Implementation

```cshtml
@model DocumentViewModel
@inject IHtmlSanitizer Sanitizer

<!-- Safe content display -->
<div class="document-content">
    @Html.Raw(Sanitizer.Sanitize(Model.Content))
</div>

<!-- Safe input handling -->
<form asp-action="Search" method="get">
    <input type="text" 
           name="query" 
           value="@Html.Encode(ViewBag.SearchTerm)"
           maxlength="100"
           pattern="[a-zA-Z0-9\s]+"
           required />
</form>

<!-- Safe dynamic content -->
<script>
    const searchTerm = '@Html.JavaScriptEncode(ViewBag.SearchTerm)';
    const userId = '@Html.JavaScriptEncode(User.Identity.Name)';
</script>
```

### 4. Security Middleware Configuration

```csharp
public class Startup
{
    public void Configure(IApplicationBuilder app)
    {
        // Add security headers
        app.Use(async (context, next) =>
        {
            // Content Security Policy
            context.Response.Headers.Add(
                "Content-Security-Policy",
                "default-src 'self'; " +
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
                "style-src 'self' 'unsafe-inline'; " +
                "img-src 'self' data: https:; " +
                "font-src 'self'; " +
                "connect-src 'self';");
                
            // XSS Protection
            context.Response.Headers.Add(
                "X-XSS-Protection", 
                "1; mode=block");
                
            // Content Type Options
            context.Response.Headers.Add(
                "X-Content-Type-Options", 
                "nosniff");
                
            // Frame Options
            context.Response.Headers.Add(
                "X-Frame-Options", 
                "DENY");
                
            await next();
        });
        
        // Configure antiforgery
        app.UseAntiforgeryTokens();
    }
    
    public void ConfigureServices(IServiceCollection services)
    {
        // Add HTML sanitizer
        services.AddHtmlSanitizer(options =>
        {
            options.AllowedTags.Add("div");
            options.AllowedTags.Add("span");
            options.AllowedAttributes.Add("class");
            options.AllowedAttributes.Add("style");
        });
        
        // Configure antiforgery
        services.AddAntiforgery(options =>
        {
            options.Cookie.SecurePolicy = 
                CookieSecurePolicy.Always;
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
        });
    }
}
```

## Sample Test Payloads

### 1. Stored XSS Tests

```csharp
[Fact]
public async Task SetContent_BlocksStoredXSS()
{
    var document = new Document();
    var maliciousContent = 
        "<script>alert('XSS')</script>";
    
    var result = await document.SetContent(
        maliciousContent, "userId");
    var safeContent = document.GetSafeHtmlContent();
    
    Assert.DoesNotContain("<script>", safeContent);
    Assert.Contains("&lt;script&gt;", safeContent);
}
```

### 2. Reflected XSS Tests

```http
# Test script injection
GET /search?query=<script>alert('XSS')</script> HTTP/1.1
Host: example.com

# Expected response:
# - Script tags should be encoded
# - CSP headers should be present
```

### 3. DOM XSS Tests

```javascript
// Test JavaScript context encoding
const testCases = [
    `'-alert(1)-'`,
    `';alert(1)//`,
    `\`;alert(1);//`,
    `</script><script>alert(1)</script>`
];

testCases.forEach(payload => {
    cy.visit(`/search?q=${encodeURIComponent(payload)}`);
    cy.get('script').should('not.contain', 'alert(1)');
});
```

### 4. Template Injection Tests

```csharp
[Fact]
public void RenderTemplate_PreventsSideEffects()
{
    var template = @"
        @{
            var cmd = ""calc.exe"";
            System.Diagnostics.Process.Start(cmd);
        }";
    
    Assert.Throws<SecurityException>(() => 
        _renderer.RenderTemplate(template));
}
```

### 5. Event Handler Tests

```html
<!-- Test event handler injection -->
<form method="post">
    <input name="username" 
           value="user' onmouseover='alert(1)" />
</form>

<!-- Expected: Encoded output -->
<input name="username" 
       value="user&#x27; onmouseover=&#x27;alert(1)" />
```
