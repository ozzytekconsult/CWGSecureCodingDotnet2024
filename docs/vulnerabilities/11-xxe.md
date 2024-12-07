# XML External Entities (XXE)

## Overview

XML External Entities (XXE), ranked #11 in the OWASP Top 10 2021, occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser. Key issues include:

- File disclosure
- Server-side request forgery
- Denial of service
- Port scanning
- Remote code execution
- Data exfiltration
- Internal service probing

In our application context, XXE could affect:
- Document processing
- Data import/export
- API integrations
- Configuration files
- Legacy system interfaces

## Technical Details

### Common Attack Vectors

1. **File Disclosure**
   - Local file inclusion
   - System file access
   - Configuration file reading
   - Sensitive data exposure

2. **Network Attacks**
   - Internal service probing
   - Port scanning
   - SSRF via XXE
   - Network traversal

3. **DoS Attacks**
   - Billion laughs attack
   - External entity expansion
   - Resource exhaustion
   - Infinite recursion

### Vulnerable Patterns in Our Domain

Using our solution's models, here are examples of vulnerable patterns:

```csharp
// Vulnerable: Basic XML processing
public class Document
{
    public void LoadFromXml(string xml)
    {
        // Unsafe XML parsing
        var doc = new XmlDocument();
        doc.LoadXml(xml);
        // Process document...
    }
}

// Vulnerable: XML deserialization
public class Order
{
    public static Order FromXml(string xml)
    {
        // Unsafe XML deserialization
        var serializer = new XmlSerializer(typeof(Order));
        using var reader = new StringReader(xml);
        return (Order)serializer.Deserialize(reader);
    }
}

// Vulnerable: Configuration loading
public class PaymentProcessor
{
    public void LoadConfig(string configXml)
    {
        // Unsafe configuration loading
        var doc = new XmlDocument();
        doc.LoadXml(configXml);
        // Process configuration...
    }
}
```

## OWASP Mitigation Details

1. **Parser Configuration**
   - Disable DTDs
   - Disable external entities
   - Limit entity expansion
   - Use safe defaults

2. **Input Validation**
   - XML schema validation
   - Content validation
   - Size limits
   - Format verification

3. **Alternative Formats**
   - Use JSON where possible
   - Modern data formats
   - Simple data structures
   - Standard protocols

4. **Security Controls**
   - Network segmentation
   - Access controls
   - Resource limits
   - Monitoring

## ASP.NET Core Mitigation Details

### 1. Secure XML Processing

```csharp
public class SecureXmlProcessor
{
    private readonly ILogger<SecureXmlProcessor> _logger;
    
    public XmlDocument LoadXmlSecurely(string xml)
    {
        try
        {
            // Create secure settings
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = 1024 * 1024, // 1MB
                MaxCharactersFromEntities = 1024,
                ValidationType = ValidationType.Schema,
                ValidationFlags = 
                    XmlSchemaValidationFlags.ProcessIdentityConstraints
            };
            
            // Add schema
            settings.Schemas.Add(null, 
                "path/to/schema.xsd");
            
            // Create secure reader
            using var stringReader = new StringReader(xml);
            using var reader = XmlReader.Create(
                stringReader, settings);
            
            // Load document
            var doc = new XmlDocument();
            doc.PreserveWhitespace = false;
            doc.Load(reader);
            
            return doc;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Error processing XML document");
            throw new SecurityException(
                "XML processing error", ex);
        }
    }
}
```

### 2. Secure Document Processing

```csharp
public class Document
{
    private readonly SecureXmlProcessor _xmlProcessor;
    private readonly ILogger<Document> _logger;
    
    public async Task<DocumentResult> ImportFromXml(
        string xml,
        string userId)
    {
        try
        {
            // Validate input
            if (string.IsNullOrEmpty(xml))
                return DocumentResult.InvalidInput();
                
            if (xml.Length > 1024 * 1024) // 1MB
                return DocumentResult.ContentTooLarge();
                
            // Process XML securely
            var doc = _xmlProcessor.LoadXmlSecurely(xml);
            
            // Extract content
            Content = doc.SelectSingleNode("//content")
                ?.InnerText ?? string.Empty;
            Title = doc.SelectSingleNode("//title")
                ?.InnerText ?? string.Empty;
                
            // Update metadata
            LastModified = DateTime.UtcNow;
            ModifiedBy = userId;
            
            return DocumentResult.Success();
        }
        catch (SecurityException ex)
        {
            _logger.LogWarning(ex,
                "Security violation during XML import");
            return DocumentResult.SecurityViolation();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Error importing XML document");
            return DocumentResult.Error();
        }
    }
}
```

### 3. Secure Configuration Processing

```csharp
public class ConfigurationProcessor
{
    private readonly SecureXmlProcessor _xmlProcessor;
    private readonly ILogger<ConfigurationProcessor> _logger;
    
    public async Task<ConfigResult> LoadConfiguration(
        string configXml)
    {
        try
        {
            // Process XML securely
            var doc = _xmlProcessor.LoadXmlSecurely(configXml);
            
            // Validate configuration
            if (!ValidateConfiguration(doc))
                return ConfigResult.InvalidConfig();
                
            // Extract settings
            var config = new AppConfiguration
            {
                Settings = ExtractSettings(doc),
                LastUpdated = DateTime.UtcNow
            };
            
            // Verify required settings
            if (!config.Validate())
                return ConfigResult.MissingRequired();
                
            return ConfigResult.Success(config);
        }
        catch (SecurityException ex)
        {
            _logger.LogWarning(ex,
                "Security violation in configuration");
            return ConfigResult.SecurityViolation();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Error processing configuration");
            return ConfigResult.Error();
        }
    }
    
    private bool ValidateConfiguration(XmlDocument doc)
    {
        // Implement configuration validation logic
        return true;
    }
    
    private Dictionary<string, string> ExtractSettings(
        XmlDocument doc)
    {
        var settings = new Dictionary<string, string>();
        
        var nodes = doc.SelectNodes("//setting");
        if (nodes != null)
        {
            foreach (XmlNode node in nodes)
            {
                var key = node.Attributes?["key"]?.Value;
                var value = node.Attributes?["value"]?.Value;
                
                if (!string.IsNullOrEmpty(key) && 
                    !string.IsNullOrEmpty(value))
                {
                    settings[key] = value;
                }
            }
        }
        
        return settings;
    }
}
```

## Sample Test Payloads

### 1. File Disclosure Tests

```xml
<!-- Test file disclosure attempt -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<document>
  <content>&xxe;</content>
</document>

<!-- Expected: XML processing error -->
```

### 2. SSRF via XXE Tests

```xml
<!-- Test SSRF attempt -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://internal-service/admin">
]>
<document>
  <content>&xxe;</content>
</document>

<!-- Expected: XML processing error -->
```

### 3. DoS Attack Tests

```xml
<!-- Test billion laughs attack -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;">
]>
<document>
  <content>&lol4;</content>
</document>

<!-- Expected: XML processing error -->
```

### 4. Entity Expansion Tests

```csharp
[Fact]
public void LoadXmlSecurely_BlocksEntityExpansion()
{
    var processor = new SecureXmlProcessor();
    var xml = @"
        <?xml version='1.0'?>
        <!DOCTYPE root [
            <!ENTITY test SYSTEM 'file:///etc/passwd'>
        ]>
        <root>&test;</root>";
        
    Assert.Throws<SecurityException>(() => 
        processor.LoadXmlSecurely(xml));
}
```

### 5. Schema Validation Tests

```csharp
[Fact]
public async Task ImportFromXml_ValidatesAgainstSchema()
{
    var document = new Document();
    var xml = @"
        <?xml version='1.0'?>
        <document>
            <invalid>Content</invalid>
        </document>";
        
    var result = await document.ImportFromXml(xml, "userId");
    
    Assert.False(result.Success);
    Assert.Equal("Schema validation failed", result.Error);
}
```
