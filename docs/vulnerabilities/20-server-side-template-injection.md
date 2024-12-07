# Server-Side Template Injection

## Overview

Server-Side Template Injection (SSTI) occurs when applications fail to:

- Validate template input
- Sanitize dynamic content
- Control template execution
- Restrict template access
- Prevent code execution
- Secure template engines
- Isolate template contexts

Critical areas requiring SSTI protection:
- Email templates
- Report generation
- Document rendering
- Dynamic content
- CMS systems
- PDF generation
- HTML rendering

## Technical Details

### Common Attack Vectors

1. **Template Manipulation**
   - Code injection
   - Expression evaluation
   - Object traversal
   - Method invocation
   - Context escaping

2. **Context Exploitation**
   - Template syntax abuse
   - Variable overwriting
   - Filter bypass
   - Sandbox escape
   - Environment access

3. **Engine Vulnerabilities**
   - Unsafe evaluation
   - Remote execution
   - File system access
   - Memory corruption
   - Resource exhaustion

### Vulnerable Patterns in Our Domain

```csharp
// Vulnerable: Direct template input
public class EmailService
{
    public async Task SendEmail(string template, 
        object model)
    {
        // Unsafe direct template evaluation
        var content = Engine.Evaluate(template, model);
        await _emailSender.SendAsync(content);
    }
}

// Vulnerable: Unvalidated template source
public class ReportGenerator
{
    public string GenerateReport(string template,
        ReportData data)
    {
        // Unsafe template loading
        return _templateEngine.Process(
            template, data);
    }
}

// Vulnerable: Dynamic template compilation
public class ContentRenderer
{
    public IActionResult Render(string template)
    {
        // Unsafe dynamic compilation
        var view = _compiler.Compile(template);
        return View(view);
    }
}
```

## OWASP Mitigation Details

1. **Input Validation**
   - Template whitelisting
   - Syntax validation
   - Context verification
   - Type checking
   - Size limits

2. **Template Security**
   - Sandboxing
   - Access control
   - Context isolation
   - Safe defaults
   - Feature restrictions

3. **Engine Configuration**
   - Safe mode
   - Feature disabling
   - Resource limits
   - Access controls
   - Security policies

4. **Runtime Protection**
   - Execution monitoring
   - Context validation
   - Error handling
   - Audit logging
   - Security headers

## ASP.NET Core Mitigation Details

### 1. Secure Template Engine

```csharp
public class SecureTemplateEngine
{
    private readonly ILogger<SecureTemplateEngine> _logger;
    private readonly ITemplateValidator _validator;
    private readonly ITemplateRepository _repository;
    
    public async Task<Result<string>> RenderTemplateAsync(
        string templateId,
        object model,
        TemplateContext context)
    {
        try
        {
            // Load template from secure source
            var template = await _repository
                .GetTemplateAsync(templateId);
            
            if (template == null)
                return Result<string>.Failure(
                    "Template not found");
            
            // Validate template
            var validation = await _validator
                .ValidateTemplateAsync(
                    template.Content,
                    context);
                    
            if (!validation.IsValid)
                return Result<string>.Failure(
                    "Invalid template",
                    validation.Errors);
            
            // Create sandbox
            using var sandbox = CreateSandbox(context);
            
            // Render in sandbox
            var result = await sandbox.RenderAsync(
                template.Content,
                model);
            
            // Validate output
            var outputValidation = await _validator
                .ValidateOutputAsync(
                    result,
                    context);
                    
            if (!outputValidation.IsValid)
                return Result<string>.Failure(
                    "Invalid output",
                    outputValidation.Errors);
            
            return Result<string>.Success(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Template rendering failed");
            return Result<string>.Failure(
                "Template processing error");
        }
    }
    
    private ITemplateSandbox CreateSandbox(
        TemplateContext context)
    {
        return new TemplateSandbox
        {
            AllowedTypes = context.AllowedTypes,
            AllowedMethods = context.AllowedMethods,
            MaxDepth = context.MaxDepth,
            MaxIterations = context.MaxIterations,
            Timeout = context.Timeout,
            MaxOutputSize = context.MaxOutputSize
        };
    }
}
```

### 2. Template Validator

```csharp
public class TemplateValidator
{
    private readonly ILogger<TemplateValidator> _logger;
    private readonly IEnumerable<ITemplateRule> _rules;
    
    public async Task<ValidationResult> ValidateTemplateAsync(
        string template,
        TemplateContext context)
    {
        try
        {
            var result = new ValidationResult();
            
            // Parse template
            var ast = await ParseTemplateAsync(template);
            
            // Validate syntax
            if (!await ValidateSyntaxAsync(ast))
            {
                result.AddError("Invalid template syntax");
                return result;
            }
            
            // Apply security rules
            foreach (var rule in _rules)
            {
                var ruleResult = await rule
                    .ValidateAsync(ast, context);
                    
                if (!ruleResult.IsValid)
                {
                    result.AddErrors(ruleResult.Errors);
                }
            }
            
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Template validation failed");
            throw;
        }
    }
    
    private async Task<bool> ValidateSyntaxAsync(
        TemplateAst ast)
    {
        // Validate template structure
        if (!ast.IsValid)
            return false;
            
        // Check for unsafe patterns
        if (ContainsUnsafePatterns(ast))
            return false;
            
        // Validate expressions
        foreach (var expr in ast.Expressions)
        {
            if (!await ValidateExpressionAsync(expr))
                return false;
        }
        
        return true;
    }
}
```

### 3. Template Repository

```csharp
public class SecureTemplateRepository
{
    private readonly ILogger<SecureTemplateRepository> _logger;
    private readonly IEncryptionService _encryption;
    private readonly IDbContext _dbContext;
    
    public async Task<Template> GetTemplateAsync(
        string templateId)
    {
        try
        {
            // Load encrypted template
            var encrypted = await _dbContext.Templates
                .FirstOrDefaultAsync(t => 
                    t.Id == templateId);
                    
            if (encrypted == null)
                return null;
                
            // Decrypt content
            var content = await _encryption
                .DecryptAsync(encrypted.Content);
                
            return new Template
            {
                Id = encrypted.Id,
                Name = encrypted.Name,
                Content = content,
                Version = encrypted.Version,
                LastModified = encrypted.LastModified
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Template retrieval failed");
            throw;
        }
    }
    
    public async Task SaveTemplateAsync(Template template)
    {
        try
        {
            // Encrypt content
            var encrypted = await _encryption
                .EncryptAsync(template.Content);
                
            // Save template
            await _dbContext.Templates.AddOrUpdateAsync(
                new EncryptedTemplate
                {
                    Id = template.Id,
                    Name = template.Name,
                    Content = encrypted,
                    Version = template.Version,
                    LastModified = DateTimeOffset.UtcNow
                });
                
            await _dbContext.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Template save failed");
            throw;
        }
    }
}
```

### 4. Template Sandbox

```csharp
public class TemplateSandbox : IDisposable
{
    private readonly ILogger<TemplateSandbox> _logger;
    private readonly AppDomain _sandboxDomain;
    private readonly CancellationTokenSource _cts;
    
    public async Task<string> RenderAsync(
        string template,
        object model)
    {
        try
        {
            // Create execution context
            using var context = CreateContext();
            
            // Set up monitoring
            using var monitor = new ExecutionMonitor(
                _cts.Token);
            
            // Execute template
            return await Task.Run(async () =>
            {
                try
                {
                    return await context.RenderAsync(
                        template,
                        model);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex,
                        "Template execution failed");
                    throw;
                }
            }, _cts.Token);
        }
        catch (OperationCanceledException)
        {
            throw new TemplateExecutionException(
                "Template execution timed out");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Sandbox execution failed");
            throw;
        }
    }
    
    private ExecutionContext CreateContext()
    {
        return new ExecutionContext
        {
            AllowedTypes = AllowedTypes,
            AllowedMethods = AllowedMethods,
            MaxDepth = MaxDepth,
            MaxIterations = MaxIterations,
            MaxOutputSize = MaxOutputSize
        };
    }
    
    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        AppDomain.Unload(_sandboxDomain);
    }
}
```

## Sample Test Payloads

### 1. Template Validation Tests

```csharp
[Fact]
public async Task Validator_BlocksCodeExecution()
{
    var template = @"
        @{
            System.Diagnostics.Process.Start(""cmd.exe"");
        }";
    
    var result = await _validator
        .ValidateTemplateAsync(template, _context);
    
    Assert.False(result.IsValid);
    Assert.Contains(
        result.Errors,
        e => e.Contains("code execution"));
}
```

### 2. Sandbox Tests

```csharp
[Fact]
public async Task Sandbox_EnforcesLimits()
{
    var template = @"
        @for(var i = 0; i < 1000000; i++) {
            <p>@i</p>
        }";
    
    await Assert.ThrowsAsync<TemplateExecutionException>(
        () => _sandbox.RenderAsync(template, null));
}
```

### 3. Output Validation Tests

```csharp
[Fact]
public async Task Validator_SanitizesOutput()
{
    var template = @"
        <script>alert('xss')</script>
        Hello, @Model.Name!";
    
    var result = await _engine.RenderTemplateAsync(
        template,
        new { Name = "Test" });
    
    Assert.DoesNotContain(
        "<script>",
        result.Value);
}
```

### 4. Security Rule Tests

```csharp
[Fact]
public async Task Rules_PreventObjectTraversal()
{
    var template = @"
        @Model.GetType().Assembly.GetType(
            'System.Diagnostics.Process')";
    
    var result = await _validator
        .ValidateTemplateAsync(template, _context);
    
    Assert.False(result.IsValid);
    Assert.Contains(
        result.Errors,
        e => e.Contains("object traversal"));
}
```

### 5. Integration Tests

```csharp
[Fact]
public async Task TemplateEngine_WorksSecurely()
{
    // Create test template
    var templateId = await CreateTestTemplate();
    
    // Render template
    var result = await _engine.RenderTemplateAsync(
        templateId,
        new { Name = "Test" },
        new TemplateContext
        {
            MaxDepth = 2,
            MaxIterations = 100,
            Timeout = TimeSpan.FromSeconds(1)
        });
    
    // Verify result
    Assert.True(result.IsSuccess);
    Assert.DoesNotContain(
        "<script>",
        result.Value);
    Assert.DoesNotContain(
        "System.",
        result.Value);
}
```
