# Insecure Deserialization

## Overview

Insecure Deserialization, ranked #13 in the OWASP Top 10 2021, occurs when untrusted data is used to abuse the logic of an application, inflict a denial of service (DoS), or execute arbitrary code. Key issues include:

- Remote code execution
- Object injection
- Type confusion
- Memory corruption
- DoS attacks
- Privilege escalation
- Data tampering

In our application context, deserialization could affect:
- Document processing
- API communication
- Session management
- Configuration loading
- Data import/export

## Technical Details

### Common Attack Vectors

1. **Object Injection**
   - Malicious object graphs
   - Type manipulation
   - Gadget chains
   - Property injection

2. **Remote Code Execution**
   - Serialized commands
   - Assembly loading
   - Type forwarding
   - Method invocation

3. **DoS Attacks**
   - Deep object graphs
   - Large payloads
   - Circular references
   - Resource exhaustion

### Vulnerable Patterns in Our Domain

Using our solution's models, here are examples of vulnerable patterns:

```csharp
// Vulnerable: Unsafe JSON deserialization
public class Document
{
    public static Document FromJson(string json)
    {
        // Unsafe deserialization
        return JsonConvert.DeserializeObject<Document>(json);
    }
}

// Vulnerable: Binary deserialization
public class Order
{
    public static Order Deserialize(byte[] data)
    {
        // Unsafe binary deserialization
        var formatter = new BinaryFormatter();
        using var stream = new MemoryStream(data);
        return (Order)formatter.Deserialize(stream);
    }
}

// Vulnerable: XML deserialization
public class PaymentMethod
{
    public static PaymentMethod FromXml(string xml)
    {
        // Unsafe XML deserialization
        var serializer = new XmlSerializer(typeof(PaymentMethod));
        using var reader = new StringReader(xml);
        return (PaymentMethod)serializer.Deserialize(reader);
    }
}
```

## OWASP Mitigation Details

1. **Input Validation**
   - Type validation
   - Schema validation
   - Size limits
   - Format verification

2. **Serialization Controls**
   - Safe serializers
   - Type whitelisting
   - Custom converters
   - Encryption

3. **Architecture Controls**
   - Minimal serialization
   - Data validation
   - Safe defaults
   - Principle of least privilege

4. **Monitoring**
   - Deserialization monitoring
   - Error tracking
   - Resource monitoring
   - Security logging

## ASP.NET Core Mitigation Details

### 1. Secure JSON Processing

```csharp
public class SecureJsonSerializer
{
    private readonly JsonSerializerOptions _options;
    private readonly ILogger<SecureJsonSerializer> _logger;
    
    public SecureJsonSerializer(ILogger<SecureJsonSerializer> logger)
    {
        _logger = logger;
        
        // Configure secure options
        _options = new JsonSerializerOptions
        {
            MaxDepth = 10,
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = 
                JsonIgnoreCondition.WhenWritingNull,
            ReferenceHandler = ReferenceHandler.Preserve,
            TypeInfoResolver = new DefaultJsonTypeInfoResolver()
        };
        
        // Add custom converters
        _options.Converters.Add(
            new JsonStringEnumConverter());
    }
    
    public T Deserialize<T>(string json) where T : class
    {
        try
        {
            // Validate input
            if (string.IsNullOrEmpty(json))
                throw new ArgumentException("Invalid JSON");
                
            // Validate length
            if (json.Length > MaxJsonLength)
                throw new ArgumentException("JSON too large");
                
            // Deserialize with type checking
            return JsonSerializer.Deserialize<T>(
                json, _options);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "JSON deserialization error");
            throw new SecurityException(
                "Deserialization failed", ex);
        }
    }
    
    public string Serialize<T>(T obj) where T : class
    {
        try
        {
            return JsonSerializer.Serialize(obj, _options);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "JSON serialization error");
            throw new SecurityException(
                "Serialization failed", ex);
        }
    }
}
```

### 2. Secure Document Processing

```csharp
public class Document
{
    private readonly SecureJsonSerializer _serializer;
    private readonly ILogger<Document> _logger;
    
    public static async Task<Document> FromJsonAsync(
        string json,
        SecureJsonSerializer serializer)
    {
        try
        {
            // Validate document schema
            if (!await ValidateSchema(json))
                throw new ValidationException("Invalid schema");
                
            // Deserialize securely
            var document = serializer.Deserialize<Document>(json);
            
            // Validate document state
            if (!document.IsValid())
                throw new ValidationException("Invalid state");
                
            return document;
        }
        catch (Exception ex)
        {
            throw new SecurityException(
                "Document deserialization failed", ex);
        }
    }
    
    public async Task<string> ToJsonAsync()
    {
        try
        {
            // Validate state before serialization
            if (!IsValid())
                throw new ValidationException("Invalid state");
                
            // Serialize securely
            return _serializer.Serialize(this);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Document serialization failed");
            throw;
        }
    }
    
    private bool IsValid()
    {
        // Implement validation logic
        return true;
    }
}
```

### 3. Secure Configuration Loading

```csharp
public class ConfigurationLoader
{
    private readonly SecureJsonSerializer _serializer;
    private readonly ILogger<ConfigurationLoader> _logger;
    
    public async Task<AppConfiguration> LoadConfigAsync(
        string configJson)
    {
        try
        {
            // Validate configuration
            if (!await ValidateConfig(configJson))
                throw new ValidationException("Invalid config");
                
            // Deserialize with type constraints
            var config = _serializer.Deserialize<AppConfiguration>(
                configJson);
                
            // Validate settings
            if (!await ValidateSettings(config))
                throw new ValidationException("Invalid settings");
                
            return config;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Configuration loading failed");
            throw new SecurityException(
                "Configuration error", ex);
        }
    }
    
    private async Task<bool> ValidateConfig(string config)
    {
        // Implement validation logic
        return true;
    }
    
    private async Task<bool> ValidateSettings(
        AppConfiguration config)
    {
        // Implement settings validation
        return true;
    }
}
```

### 4. API Communication Security

```csharp
public class ApiCommunication
{
    private readonly SecureJsonSerializer _serializer;
    private readonly ILogger<ApiCommunication> _logger;
    
    public async Task<ApiResponse<T>> SendRequest<T>(
        ApiRequest request) where T : class
    {
        try
        {
            // Serialize request
            var json = _serializer.Serialize(request);
            
            // Send request
            using var client = new HttpClient();
            var response = await client.PostAsync(
                request.Url,
                new StringContent(json, Encoding.UTF8, 
                    "application/json"));
                    
            // Validate response
            if (!response.IsSuccessStatusCode)
                return ApiResponse<T>.Error(
                    response.StatusCode);
                    
            // Deserialize response
            var content = await response
                .Content.ReadAsStringAsync();
            var result = _serializer.Deserialize<T>(content);
            
            return ApiResponse<T>.Success(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "API communication error");
            return ApiResponse<T>.Error(ex);
        }
    }
}
```

## Sample Test Payloads

### 1. Object Injection Tests

```csharp
[Fact]
public void Deserialize_BlocksObjectInjection()
{
    var maliciousJson = @"{
        '$type': 'System.IO.FileInfo',
        'fileName': 'malicious.exe'
    }";
    
    Assert.Throws<SecurityException>(() =>
        _serializer.Deserialize<Document>(maliciousJson));
}
```

### 2. Type Confusion Tests

```csharp
[Fact]
public void Deserialize_PreventTypeConfusion()
{
    var json = @"{
        'type': 'AdminUser',
        'permissions': ['ALL']
    }";
    
    Assert.Throws<JsonException>(() =>
        _serializer.Deserialize<RegularUser>(json));
}
```

### 3. DoS Prevention Tests

```csharp
[Fact]
public void Deserialize_PreventsDosAttacks()
{
    // Create deep nested object
    var obj = new { next = new { next = new { } } };
    var deepJson = JsonSerializer.Serialize(obj);
    
    Assert.Throws<JsonException>(() =>
        _serializer.Deserialize<object>(deepJson));
}
```

### 4. Resource Limit Tests

```csharp
[Fact]
public async Task LoadConfig_EnforcesResourceLimits()
{
    var largeConfig = new string('x', 1024 * 1024 * 10); // 10MB
    
    await Assert.ThrowsAsync<ArgumentException>(() =>
        _loader.LoadConfigAsync(largeConfig));
}
```

### 5. Custom Type Tests

```csharp
[Fact]
public void Deserialize_HandlesCustomTypes()
{
    var json = @"{
        'customType': 'Special',
        'data': 'test'
    }";
    
    var result = _serializer.Deserialize<CustomType>(json);
    
    Assert.NotNull(result);
    Assert.Equal("Special", result.CustomType);
}
```
