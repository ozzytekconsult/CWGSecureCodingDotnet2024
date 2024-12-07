# Malicious File Upload

## Overview

File upload vulnerabilities occur when web applications fail to properly validate, sanitize, and handle uploaded files. These vulnerabilities can lead to:

- Remote code execution through uploaded scripts
- Server-side malware execution
- Client-side attacks via stored XSS
- Denial of Service through large files
- Path traversal attacks
- File type exploits

In our application context, file uploads are used for:
- Document management
- Profile pictures
- Report attachments
- Data imports
- System configurations

## Technical Details

### Common Attack Vectors

1. **File Type Attacks**
   - Executable files disguised as images
   - Scripts with double extensions
   - MIME type spoofing
   - Null byte injection
   - Polyglot files

2. **Storage Attacks**
   - Path traversal in filenames
   - Symbolic link attacks
   - File overwrite
   - Disk space exhaustion
   - Race conditions

3. **Processing Attacks**
   - ZIP bombs
   - XML external entities
   - Image processing exploits
   - Memory exhaustion
   - Format string attacks

### Vulnerable Patterns in Our Domain

```csharp
// Vulnerable: No file type validation
public class DocumentUpload
{
    public async Task<string> SaveFile(IFormFile file)
    {
        var fileName = file.FileName; // Unsafe
        var path = Path.Combine("uploads", fileName);
        using var stream = File.Create(path);
        await file.CopyToAsync(stream);
        return path;
    }
}

// Vulnerable: No size limits
public class ProfilePicture
{
    public async Task Upload(Stream fileStream)
    {
        using var destination = File.Create("profile.jpg");
        await fileStream.CopyToAsync(destination);
    }
}

// Vulnerable: Unsafe file type check
public class ReportAttachment
{
    public bool IsValidFile(string filename)
    {
        return filename.EndsWith(".pdf"); // Unsafe
    }
}
```

## OWASP Mitigation Details

1. **File Validation**
   - Content type verification
   - File extension whitelist
   - Magic number checking
   - Size limitations
   - Antivirus scanning

2. **Storage Security**
   - Secure file paths
   - Random file names
   - Proper permissions
   - Isolated storage
   - Metadata stripping

3. **Processing Security**
   - Safe file handling
   - Resource limits
   - Synchronous operations
   - Format validation
   - Error handling

4. **Access Control**
   - File permissions
   - User authorization
   - Download restrictions
   - Temporary access
   - Audit logging

## ASP.NET Core Mitigation Details

### 1. Secure File Upload Service

```csharp
public class SecureFileUploadService
{
    private readonly ILogger<SecureFileUploadService> _logger;
    private readonly IConfiguration _config;
    private readonly IAntivirusScanner _scanner;
    
    private readonly string[] _allowedExtensions = 
        { ".jpg", ".png", ".pdf", ".docx" };
    private readonly string[] _allowedMimeTypes = 
    {
        "image/jpeg",
        "image/png",
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    };
    
    public async Task<FileUploadResult> UploadFileAsync(
        IFormFile file, 
        string userId)
    {
        try
        {
            // Validate file
            await ValidateFileAsync(file);
            
            // Generate secure filename
            var secureFileName = GenerateSecureFileName(
                file.FileName);
            
            // Get storage path
            var storagePath = GetSecureStoragePath(
                userId, secureFileName);
            
            // Save file
            await SaveFileSecurelyAsync(
                file, storagePath);
            
            // Scan for malware
            var scanResult = await _scanner
                .ScanFileAsync(storagePath);
            if (!scanResult.IsClean)
            {
                await DeleteFileAsync(storagePath);
                throw new SecurityException(
                    "Malware detected");
            }
            
            return new FileUploadResult
            {
                Success = true,
                FilePath = storagePath,
                FileId = Guid.NewGuid().ToString()
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "File upload failed");
            return new FileUploadResult
            {
                Success = false,
                Error = "Upload failed: " + ex.Message
            };
        }
    }
    
    private async Task ValidateFileAsync(IFormFile file)
    {
        // Check if file exists
        if (file == null || file.Length == 0)
            throw new ArgumentException(
                "No file provided");
        
        // Check file size
        var maxSize = _config.GetValue<long>(
            "FileUpload:MaxSize");
        if (file.Length > maxSize)
            throw new ArgumentException(
                "File too large");
        
        // Validate extension
        var ext = Path.GetExtension(file.FileName)
            .ToLowerInvariant();
        if (!_allowedExtensions.Contains(ext))
            throw new ArgumentException(
                "Invalid file type");
        
        // Validate MIME type
        if (!_allowedMimeTypes.Contains(
            file.ContentType.ToLowerInvariant()))
            throw new ArgumentException(
                "Invalid content type");
        
        // Validate file content
        using var stream = file.OpenReadStream();
        if (!await ValidateFileContentAsync(
            stream, ext))
            throw new ArgumentException(
                "Invalid file content");
    }
    
    private string GenerateSecureFileName(
        string originalName)
    {
        var ext = Path.GetExtension(originalName)
            .ToLowerInvariant();
        return $"{Guid.NewGuid()}{ext}";
    }
    
    private string GetSecureStoragePath(
        string userId, 
        string fileName)
    {
        var basePath = _config.GetValue<string>(
            "FileUpload:StoragePath");
        var userPath = Path.Combine(
            basePath, 
            userId);
            
        // Create user directory if not exists
        Directory.CreateDirectory(userPath);
        
        return Path.Combine(userPath, fileName);
    }
    
    private async Task SaveFileSecurelyAsync(
        IFormFile file, 
        string path)
    {
        using var stream = new FileStream(
            path,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            4096,
            FileOptions.Asynchronous);
            
        await file.CopyToAsync(stream);
    }
}
```

### 2. Secure File Download Service

```csharp
public class SecureFileDownloadService
{
    private readonly ILogger<SecureFileDownloadService> _logger;
    private readonly IUserAuthorizationService _authService;
    
    public async Task<FileDownloadResult> DownloadFileAsync(
        string fileId, 
        string userId)
    {
        try
        {
            // Validate access
            if (!await _authService.CanAccessFile(
                userId, fileId))
                throw new UnauthorizedAccessException();
            
            // Get file path
            var filePath = await GetSecureFilePath(
                fileId);
            
            // Validate file exists
            if (!File.Exists(filePath))
                throw new FileNotFoundException();
            
            // Get file info
            var info = new FileInfo(filePath);
            
            // Stream file
            var stream = new FileStream(
                filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                4096,
                FileOptions.Asynchronous);
            
            return new FileDownloadResult
            {
                Stream = stream,
                ContentType = GetContentType(info.Extension),
                FileName = info.Name
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "File download failed");
            throw;
        }
    }
    
    private string GetContentType(string extension)
    {
        // Implement secure content type mapping
        return "application/octet-stream";
    }
}
```

### 3. File Processing Service

```csharp
public class SecureFileProcessingService
{
    private readonly ILogger<SecureFileProcessingService> _logger;
    
    public async Task ProcessImageAsync(
        string filePath,
        ImageProcessingOptions options)
    {
        try
        {
            // Validate file exists
            if (!File.Exists(filePath))
                throw new FileNotFoundException();
            
            // Validate image
            using var image = await Image.LoadAsync(
                filePath);
            
            // Apply size limits
            if (image.Width > options.MaxWidth ||
                image.Height > options.MaxHeight)
                throw new ArgumentException(
                    "Image too large");
            
            // Process safely
            await ProcessImageSafelyAsync(
                image, options);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, 
                "Image processing failed");
            throw;
        }
    }
    
    private async Task ProcessImageSafelyAsync(
        Image image,
        ImageProcessingOptions options)
    {
        // Implement secure image processing
    }
}
```

## Sample Test Payloads

### 1. File Type Tests

```csharp
[Fact]
public async Task Upload_BlocksExecutableFiles()
{
    var file = CreateTestFile("test.exe");
    
    await Assert.ThrowsAsync<ArgumentException>(() =>
        _uploadService.UploadFileAsync(file, "user1"));
}
```

### 2. File Size Tests

```csharp
[Fact]
public async Task Upload_BlocksLargeFiles()
{
    var largeFile = CreateLargeFile(100 * 1024 * 1024);
    
    await Assert.ThrowsAsync<ArgumentException>(() =>
        _uploadService.UploadFileAsync(largeFile, "user1"));
}
```

### 3. MIME Type Tests

```csharp
[Fact]
public async Task Upload_ValidatesMimeType()
{
    var file = CreateTestFile(
        "malicious.jpg", 
        "application/x-msdownload");
    
    await Assert.ThrowsAsync<ArgumentException>(() =>
        _uploadService.UploadFileAsync(file, "user1"));
}
```

### 4. Path Traversal Tests

```csharp
[Fact]
public async Task Upload_BlocksPathTraversal()
{
    var file = CreateTestFile("../../../etc/passwd");
    
    await Assert.ThrowsAsync<ArgumentException>(() =>
        _uploadService.UploadFileAsync(file, "user1"));
}
```

### 5. Content Validation Tests

```csharp
[Fact]
public async Task Upload_ValidatesContent()
{
    var file = CreateFakeImage();
    
    await Assert.ThrowsAsync<ArgumentException>(() =>
        _uploadService.UploadFileAsync(file, "user1"));
}
```
