# Software and Data Integrity Failures

## Overview

Software and Data Integrity Failures, ranked #8 in the OWASP Top 10 2021, occur when code and infrastructure don't protect against integrity violations. Key issues include:

- Unsigned software updates
- Insecure deserialization
- Untrusted CI/CD pipelines
- Auto-update vulnerabilities
- Unsigned data modifications
- Supply chain attacks
- Dependency confusion

In our application context, integrity failures could affect:
- Document processing and storage
- Payment data handling
- User data modifications
- Order processing
- Product updates

## Technical Details

### Common Vulnerability Patterns

1. **Data Integrity Issues**
   - Missing data signatures
   - Inadequate checksums
   - Unsigned modifications
   - Missing audit trails

2. **Software Integrity Issues**
   - Insecure dependencies
   - Unsigned updates
   - Compromised packages
   - Build process vulnerabilities

3. **Deserialization Vulnerabilities**
   - Untrusted data deserialization
   - Type confusion attacks
   - Object injection
   - Remote code execution

### Vulnerable Patterns in Our Domain

Using our solution's models, here are examples of vulnerable patterns:

```csharp
// Vulnerable: Unsafe deserialization
public class Document
{
    public static Document FromJson(string json)
    {
        // Unsafe deserialization without type checking
        return JsonConvert.DeserializeObject<Document>(json);
    }
}

// Vulnerable: Missing data integrity checks
public class Payment
{
    public void UpdateAmount(decimal amount)
    {
        // No validation or audit trail
        Amount = amount;
        LastModified = DateTime.UtcNow;
    }
}

// Vulnerable: Unsigned data modifications
public class Order
{
    public void ModifyItems(string itemsJson)
    {
        // Direct deserialization without verification
        Items = JsonConvert.DeserializeObject<List<OrderItem>>(
            itemsJson);
    }
}
```

## OWASP Mitigation Details

1. **Data Integrity**
   - Digital signatures
   - Checksums verification
   - Audit logging
   - Version control

2. **Software Integrity**
   - Signed packages
   - Verified builds
   - Secure CI/CD
   - Dependency verification

3. **Deserialization Security**
   - Type constraints
   - Input validation
   - Whitelisting
   - Serialization controls

4. **Supply Chain Security**
   - Vendor verification
   - Package signing
   - Build reproducibility
   - Dependency scanning

## ASP.NET Core Mitigation Details

### 1. Secure Document Processing

```csharp
public class Document
{
    private readonly IDataProtector _protector;
    private readonly ILogger<Document> _logger;
    
    public string SerializeSecurely()
    {
        var json = JsonSerializer.Serialize(this);
        var protected = _protector.Protect(json);
        
        // Add integrity signature
        var signature = ComputeSignature(protected);
        
        return new DocumentPackage
        {
            Content = protected,
            Signature = signature,
            Timestamp = DateTime.UtcNow
        }.ToBase64();
    }
    
    public static Document DeserializeSecurely(
        string package,
        IDataProtector protector)
    {
        try
        {
            var pkg = DocumentPackage.FromBase64(package);
            
            // Verify signature
            if (!VerifySignature(pkg.Content, pkg.Signature))
                throw new SecurityException("Invalid signature");
                
            // Decrypt and deserialize with type checking
            var json = protector.Unprotect(pkg.Content);
            return JsonSerializer.Deserialize<Document>(
                json,
                new JsonSerializerOptions
                {
                    TypeInfoResolver = new DefaultJsonTypeInfoResolver()
                });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Document integrity verification failed");
            throw new SecurityException(
                "Document integrity check failed", ex);
        }
    }
    
    private string ComputeSignature(string content)
    {
        using var hmac = new HMACSHA256(_signingKey);
        var hash = hmac.ComputeHash(
            Encoding.UTF8.GetBytes(content));
        return Convert.ToBase64String(hash);
    }
}
```

### 2. Secure Payment Processing

```csharp
public class Payment
{
    private readonly IAuditLogger _auditLogger;
    private readonly IDataProtector _protector;
    
    public async Task UpdateAmount(
        decimal newAmount, 
        string reason,
        string userId)
    {
        // Validate amount
        if (newAmount <= 0)
            throw new ArgumentException("Invalid amount");
            
        // Create modification record
        var modification = new PaymentModification
        {
            PaymentId = Id,
            OldAmount = Amount,
            NewAmount = newAmount,
            Reason = reason,
            ModifiedBy = userId,
            ModifiedAt = DateTime.UtcNow
        };
        
        // Sign modification
        modification.Signature = _protector.Protect(
            JsonSerializer.Serialize(modification));
            
        // Update with audit
        var oldAmount = Amount;
        Amount = newAmount;
        LastModified = modification.ModifiedAt;
        
        await _auditLogger.LogAsync(
            "Payment.AmountModified",
            new
            {
                PaymentId = Id,
                OldAmount = oldAmount,
                NewAmount = newAmount,
                ModifiedBy = userId,
                Reason = reason,
                Signature = modification.Signature
            });
    }
}
```

### 3. Secure Order Processing

```csharp
public class Order
{
    private readonly IValidator<OrderItem> _itemValidator;
    private readonly IAuditLogger _auditLogger;
    
    public async Task<OrderResult> ModifyItems(
        string itemsJson,
        string signature,
        string userId)
    {
        try
        {
            // Verify signature
            if (!VerifySignature(itemsJson, signature))
                return OrderResult.InvalidSignature();
                
            // Deserialize with type checking
            var items = JsonSerializer.Deserialize<List<OrderItem>>(
                itemsJson,
                new JsonSerializerOptions
                {
                    TypeInfoResolver = new DefaultJsonTypeInfoResolver()
                });
                
            // Validate items
            foreach (var item in items)
            {
                var validation = await _itemValidator
                    .ValidateAsync(item);
                if (!validation.IsValid)
                    return OrderResult.ValidationFailed(
                        validation.Errors);
            }
            
            // Update with audit
            var oldItems = Items.ToList();
            Items = items;
            ModifiedAt = DateTime.UtcNow;
            
            await _auditLogger.LogAsync(
                "Order.ItemsModified",
                new
                {
                    OrderId = Id,
                    OldItems = oldItems,
                    NewItems = items,
                    ModifiedBy = userId,
                    Signature = signature
                });
                
            return OrderResult.Success();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Order modification failed for {OrderId}", Id);
            return OrderResult.SystemError();
        }
    }
}
```

### 4. Secure Build Pipeline

```yaml
# Azure DevOps pipeline with integrity checks
trigger:
  - main

pool:
  vmImage: 'windows-latest'

variables:
  solution: '**/*.sln'
  buildPlatform: 'Any CPU'
  buildConfiguration: 'Release'

steps:
- task: NuGetToolInstaller@1

- task: NuGetCommand@2
  inputs:
    restoreSolution: '$(solution)'

# Verify package integrity
- task: PowerShell@2
  inputs:
    targetType: 'inline'
    script: |
      Get-ChildItem -Path $(Build.SourcesDirectory) -Filter packages.config -Recurse | 
      ForEach-Object {
        $xml = [xml](Get-Content $_.FullName)
        $xml.packages.package | ForEach-Object {
          Write-Host "Verifying package: $($_.id) $($_.version)"
          nuget verify -Signatures $_.id -Version $_.version
        }
      }

# Code signing
- task: CodeSigning@1
  inputs:
    folderPath: '$(Build.ArtifactStagingDirectory)'
    signType: 'real'
    timestampServer: 'http://timestamp.digicert.com'

# Security scanning
- task: SecurityScan@1
  inputs:
    scanType: 'full'
    verbosity: 'detailed'
```

## Sample Test Payloads

### 1. Deserialization Tests

```csharp
[Fact]
public void DeserializeSecurely_RejectsInvalidSignature()
{
    var document = new Document { Content = "Test" };
    var serialized = document.SerializeSecurely();
    
    // Tamper with content
    var tampered = serialized.Replace("Test", "Hacked");
    
    Assert.Throws<SecurityException>(() => 
        Document.DeserializeSecurely(tampered, _protector));
}
```

### 2. Data Integrity Tests

```csharp
[Fact]
public async Task UpdateAmount_MaintainsAuditTrail()
{
    var payment = new Payment { Amount = 100m };
    
    await payment.UpdateAmount(150m, "Price adjustment", "userId");
    
    var audit = await _auditLogger.GetEntriesAsync(
        "Payment.AmountModified",
        payment.Id);
        
    Assert.Single(audit);
    Assert.Equal(100m, audit[0].OldAmount);
    Assert.Equal(150m, audit[0].NewAmount);
    Assert.NotNull(audit[0].Signature);
}
```

### 3. Type Safety Tests

```http
# Test type confusion attack
POST /api/orders/modify HTTP/1.1
Content-Type: application/json

{
    "items": [
        {
            "$type": "System.IO.FileInfo",
            "path": "c:\\windows\\system32"
        }
    ]
}

# Expected: 400 Bad Request
# Invalid type in deserialization
```

### 4. Signature Verification Tests

```csharp
[Fact]
public async Task ModifyItems_RequiresValidSignature()
{
    var order = new Order();
    var items = new List<OrderItem>
    {
        new() { ProductId = 1, Quantity = 2 }
    };
    
    var json = JsonSerializer.Serialize(items);
    var invalidSignature = "invalid_signature";
    
    var result = await order.ModifyItems(
        json, 
        invalidSignature,
        "userId");
        
    Assert.False(result.Success);
    Assert.Equal("Invalid signature", result.Error);
}
```

### 5. Build Integrity Tests

```powershell
# Verify build artifacts
Get-ChildItem *.dll | ForEach-Object {
    $cert = Get-AuthenticodeSignature $_
    if ($cert.Status -ne "Valid") {
        throw "Invalid signature for $_"
    }
}
```
