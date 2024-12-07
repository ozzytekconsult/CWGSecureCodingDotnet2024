# Cryptographic Failures

## Overview

Cryptographic failures, ranked #2 in the OWASP Top 10 2021, occur when sensitive data is not properly protected. This includes:
- Transmitting sensitive data in clear text
- Using weak or outdated cryptographic algorithms
- Using default or weak cryptographic keys
- Proper key management failures
- Not enforcing encryption using directives like security headers

The most common types of sensitive data in our application context include:
- Authentication credentials
- Payment information (PaymentMethod model)
- Personal user data (ApplicationUser model)
- Session tokens (UserSession model)
- Business-critical documents (Document model)

## Technical Details

### Common Vulnerability Patterns

1. **Data in Transit**
   - Missing HTTPS
   - Weak SSL/TLS configurations
   - Mixed content (HTTP in HTTPS pages)

2. **Data at Rest**
   - Unencrypted sensitive data in databases
   - Use of weak hashing algorithms
   - Hardcoded secrets in source code

3. **Key Management**
   - Insufficient key rotation
   - Weak key generation
   - Insecure key storage

### Vulnerable Patterns in Our Domain

Using our solution's models, here are examples of vulnerable patterns:

```csharp
// Vulnerable: Storing payment information without encryption
public class PaymentMethod
{
    public string CardNumber { get; set; }
    public string CVV { get; set; }
    public string ExpiryDate { get; set; }
}

// Vulnerable: Weak password hashing
public class ApplicationUser
{
    public string Username { get; set; }
    public string Password { get; set; } // Stored as plain MD5
}

// Vulnerable: Unencrypted sensitive document storage
public class Document
{
    public string Content { get; set; }
    public bool IsConfidential { get; set; }
}
```

## OWASP Mitigation Details

1. **Data Classification**
   - Identify sensitive data
   - Apply appropriate protection levels
   - Regular data audits

2. **Encryption Requirements**
   - Use strong, up-to-date algorithms
   - Proper key management
   - Secure key storage

3. **Transmission Security**
   - Enforce HTTPS everywhere
   - Strong TLS configuration
   - Secure cookie attributes

4. **Password Security**
   - Strong password hashing
   - Salt usage
   - Proper password storage

## ASP.NET Core Mitigation Details

### 1. Secure Configuration

```csharp
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    // Force HTTPS
    app.UseHsts();
    app.UseHttpsRedirection();
    
    // Add security headers
    app.Use(async (context, next) =>
    {
        context.Response.Headers.Add("Strict-Transport-Security", 
            "max-age=31536000; includeSubDomains");
        await next();
    });
}
```

### 2. Secure Payment Information

```csharp
public class PaymentMethod
{
    private readonly IEncryptionService _encryptionService;
    
    // Only last 4 digits stored unencrypted
    public string LastFourDigits { get; set; }
    
    // Encrypted card data
    private string _encryptedCardData;
    
    public void SetCardDetails(string cardNumber, string cvv, string expiryDate)
    {
        var sensitiveData = new
        {
            CardNumber = cardNumber,
            CVV = cvv,
            ExpiryDate = expiryDate
        };
        
        LastFourDigits = cardNumber.Substring(cardNumber.Length - 4);
        _encryptedCardData = _encryptionService.Encrypt(
            JsonSerializer.Serialize(sensitiveData));
    }
}
```

### 3. Secure Document Storage

```csharp
public class Document
{
    private readonly IEncryptionService _encryptionService;
    
    public string EncryptedContent { get; private set; }
    
    public void SetContent(string content, bool isConfidential)
    {
        if (isConfidential)
        {
            EncryptedContent = _encryptionService.Encrypt(content);
        }
        else
        {
            EncryptedContent = content;
        }
    }
    
    public string GetContent(IUserContext userContext)
    {
        if (IsConfidential)
        {
            if (!userContext.HasAccess(this))
                throw new UnauthorizedAccessException();
                
            return _encryptionService.Decrypt(EncryptedContent);
        }
        
        return EncryptedContent;
    }
}
```

### 4. Secure User Data

```csharp
public class ApplicationUser
{
    private readonly IPasswordHasher<ApplicationUser> _passwordHasher;
    
    public string HashedPassword { get; private set; }
    
    public void SetPassword(string password)
    {
        HashedPassword = _passwordHasher.HashPassword(this, password);
    }
    
    public bool VerifyPassword(string password)
    {
        return _passwordHasher.VerifyHashedPassword(
            this, 
            HashedPassword, 
            password) != PasswordVerificationResult.Failed;
    }
}
```

### 5. Secure Session Management

```csharp
public class UserSession
{
    private readonly IEncryptionService _encryptionService;
    
    public string EncryptedSessionData { get; private set; }
    public DateTime ExpiresAt { get; set; }
    
    public void StoreSessionData(Dictionary<string, string> sessionData)
    {
        EncryptedSessionData = _encryptionService.Encrypt(
            JsonSerializer.Serialize(sessionData));
        ExpiresAt = DateTime.UtcNow.AddHours(1);
    }
}
```

## Sample Test Payloads

### 1. HTTPS Enforcement Tests

```http
# Attempt non-HTTPS access
GET http://yourdomain.com/api/documents HTTP/1.1

# Expected: Redirect to HTTPS
```

### 2. Sensitive Data Exposure Tests

```http
# Attempt to retrieve payment information
GET /api/payments/123 HTTP/1.1
Authorization: Bearer [valid_token]

# Expected Response: Only masked data
{
    "id": 123,
    "lastFourDigits": "4321",
    "cardType": "VISA",
    "expiryMonth": "**",
    "expiryYear": "**"
}
```

### 3. Password Storage Tests

```http
# Test password hash collision resistance
POST /api/users/register HTTP/1.1
Content-Type: application/json

{
    "username": "test@example.com",
    "password": "TestPassword123!"
}

# Verify stored hash is properly salted and using strong algorithm
```

### 4. Encryption Tests

```csharp
// Unit test for document encryption
[Fact]
public void Document_WhenConfidential_IsProperlyEncrypted()
{
    var document = new Document();
    var content = "Sensitive Data";
    
    document.SetContent(content, isConfidential: true);
    
    Assert.NotEqual(content, document.EncryptedContent);
    Assert.True(IsBase64String(document.EncryptedContent));
}
```

### 5. Key Management Tests

```csharp
[Fact]
public void EncryptionService_UsesDifferentIVForEachEncryption()
{
    var service = new EncryptionService();
    var data = "Test Data";
    
    var encrypted1 = service.Encrypt(data);
    var encrypted2 = service.Encrypt(data);
    
    Assert.NotEqual(encrypted1, encrypted2);
}
```
