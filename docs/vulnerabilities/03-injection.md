# Injection

## Overview

Injection flaws, ranked #3 in the OWASP Top 10 2021, occur when untrusted data is sent to an interpreter as part of a command or query. Common types include:
- SQL Injection
- NoSQL Injection
- OS Command Injection
- LDAP Injection
- Expression Language Injection
- Object Relational Mapping (ORM) Injection

In our application context, injection vulnerabilities could affect:
- Document queries and content
- Order processing
- User authentication
- Product catalog searches
- Payment processing

## Technical Details

### Common Attack Vectors

1. **SQL Injection**
   - Union-based attacks
   - Error-based attacks
   - Boolean-based blind attacks
   - Time-based blind attacks

2. **Command Injection**
   - Direct OS command execution
   - Indirect command execution through file paths
   - Environment variable manipulation

3. **ORM Injection**
   - Dynamic LINQ queries
   - Raw SQL through ORM
   - Unsafe parameter handling

### Vulnerable Patterns in Our Domain

Using our solution's models, here are examples of vulnerable patterns:

```csharp
// Vulnerable: SQL Injection in document search
public async Task<IEnumerable<Document>> SearchDocuments(string searchTerm)
{
    var sql = $"SELECT * FROM Documents WHERE Content LIKE '%{searchTerm}%'";
    return await _context.Documents.FromSqlRaw(sql).ToListAsync();
}

// Vulnerable: Command Injection in file handling
public class Document
{
    public void ExportToPdf(string outputPath)
    {
        var command = $"convert {Path} {outputPath}";
        Process.Start("cmd.exe", $"/c {command}");
    }
}

// Vulnerable: ORM Injection in product search
public async Task<IEnumerable<Product>> SearchProducts(string query)
{
    return await _context.Products
        .Where("Name LIKE '%" + query + "%'")
        .ToListAsync();
}
```

## OWASP Mitigation Details

1. **Input Validation**
   - Strict syntax validation
   - Whitelist validation
   - Strong typing

2. **Parameterization**
   - Use of prepared statements
   - ORM parameterization
   - Stored procedures

3. **Escaping**
   - Context-aware escaping
   - HTML encoding
   - SQL escaping

4. **Access Controls**
   - Principle of least privilege
   - Separate database accounts
   - Limited permissions

## ASP.NET Core Mitigation Details

### 1. Safe Database Access

```csharp
public class DocumentRepository
{
    private readonly ApplicationDbContext _context;
    
    public async Task<IEnumerable<Document>> SearchDocuments(string searchTerm)
    {
        // Safe: Using parameters with EF Core
        return await _context.Documents
            .Where(d => EF.Functions.Like(d.Content, $"%{searchTerm}%"))
            .ToListAsync();
            
        // Alternative: Using SqlParameter
        var param = new SqlParameter("@search", $"%{searchTerm}%");
        return await _context.Documents
            .FromSqlRaw("SELECT * FROM Documents WHERE Content LIKE @search", param)
            .ToListAsync();
    }
}
```

### 2. Safe Command Execution

```csharp
public class Document
{
    private readonly IFileProcessor _fileProcessor;
    
    public async Task ExportToPdf(string outputPath)
    {
        // Validate path
        if (!PathValidator.IsValidPath(outputPath))
            throw new ArgumentException("Invalid output path");
            
        // Use safe file processing service
        await _fileProcessor.ConvertToPdfAsync(
            this.Path,
            outputPath,
            new ConversionOptions { MaxSize = 10_000_000 });
    }
}
```

### 3. Safe Product Search

```csharp
public class ProductRepository
{
    private readonly ApplicationDbContext _context;
    
    public async Task<IEnumerable<Product>> SearchProducts(
        string query,
        int maxResults = 100)
    {
        // Safe: Using LINQ with proper parameters
        return await _context.Products
            .Where(p => p.Name.Contains(query))
            .Take(maxResults)
            .ToListAsync();
    }
}
```

### 4. Safe Payment Processing

```csharp
public class PaymentProcessor
{
    private readonly ApplicationDbContext _context;
    
    public async Task ProcessPayment(Payment payment)
    {
        // Validate payment data
        if (!PaymentValidator.IsValid(payment))
            throw new ValidationException("Invalid payment data");
            
        // Use parameterized query for payment record
        await _context.Payments.AddAsync(payment);
        
        // Use transaction for atomicity
        using var transaction = await _context.Database
            .BeginTransactionAsync();
        try
        {
            await _context.SaveChangesAsync();
            await transaction.CommitAsync();
        }
        catch
        {
            await transaction.RollbackAsync();
            throw;
        }
    }
}
```

### 5. Input Validation Middleware

```csharp
public class InputValidationMiddleware
{
    private readonly RequestDelegate _next;
    
    public async Task InvokeAsync(HttpContext context)
    {
        // Validate request parameters
        if (!await ValidateRequest(context.Request))
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsJsonAsync(
                new { error = "Invalid input detected" });
            return;
        }
        
        await _next(context);
    }
    
    private async Task<bool> ValidateRequest(HttpRequest request)
    {
        // Implement input validation logic
        return await InputValidator.ValidateAsync(request);
    }
}
```

## Sample Test Payloads

### 1. SQL Injection Tests

```sql
-- Test basic SQL injection
searchTerm = "' OR '1'='1"

-- Test UNION-based injection
searchTerm = "' UNION SELECT username, password FROM Users--"

-- Test blind SQL injection
searchTerm = "' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)='1"
```

### 2. Command Injection Tests

```http
# Test basic command injection
POST /api/documents/export HTTP/1.1
Content-Type: application/json

{
    "outputPath": "output.pdf & del /f /q important.txt"
}

# Test indirect command injection
POST /api/documents/process HTTP/1.1
Content-Type: application/json

{
    "filePath": "../../../etc/passwd"
}
```

### 3. ORM Injection Tests

```csharp
// Test dynamic LINQ injection
[Fact]
public async Task SearchProducts_WithMaliciousQuery_ThrowsException()
{
    var repo = new ProductRepository(_context);
    var maliciousQuery = "Name != null; DELETE FROM Products--";
    
    await Assert.ThrowsAsync<InvalidOperationException>(
        () => repo.SearchProducts(maliciousQuery));
}
```

### 4. Input Validation Tests

```http
# Test XSS in document content
POST /api/documents HTTP/1.1
Content-Type: application/json

{
    "content": "<script>alert('XSS')</script>"
}

# Test path traversal
GET /api/documents/../../../etc/passwd HTTP/1.1

# Test integer overflow
POST /api/orders HTTP/1.1
Content-Type: application/json

{
    "quantity": 2147483648
}
```

### 5. Parameterization Tests

```csharp
[Fact]
public async Task SearchDocuments_WithSpecialCharacters_WorksCorrectly()
{
    var repo = new DocumentRepository(_context);
    var searchTerm = "Test's Document % _ []";
    
    var results = await repo.SearchDocuments(searchTerm);
    
    Assert.NotNull(results);
    Assert.DoesNotContain(results, d => d.Content.Contains("'"));
}
```
