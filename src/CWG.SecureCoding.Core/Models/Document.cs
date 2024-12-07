using CWG.SecureCoding.Core.Models.Identity;
using System.ComponentModel.DataAnnotations;

namespace CWG.SecureCoding.Core.Models;

public enum StorageType
{
    Database,
    FileSystem
}

public class Document
{
    public int Id { get; set; }
    
    [Required]
    public string UserId { get; set; } = default!;
    
    [Required]
    [MaxLength(200)]
    [RegularExpression(@"^[\w\s-'.()]{1,200}$", ErrorMessage = "Filename contains invalid characters")]
    public string FileName { get; set; } = default!;
    
    [Required]
    [MaxLength(100)]
    public string ContentType { get; set; } = default!;
    
    [Required]
    public StorageType StorageType { get; set; }
    
    // For FileSystem storage
    [MaxLength(1000)]
    public string? StoragePath { get; set; }
    
    // For Database storage
    public byte[]? FileContent { get; set; }
    
    [Range(1, 104857600)] // Max 100MB
    public long FileSize { get; set; }
    
    [MaxLength(50)]
    public string? DocumentType { get; set; }
    
    [Required]
    [MaxLength(64)]
    public string FileHash { get; set; } = default!;
    
    public bool IsEncrypted { get; set; }
    
    [MaxLength(32)]
    public string? EncryptionIV { get; set; }
    
    [MaxLength(32)]
    public string? EncryptionKey { get; set; }
    
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    
    public DateTimeOffset? LastAccessedAt { get; set; }
    
    [MaxLength(256)]
    public string? LastAccessedByIP { get; set; }
    
    public int DownloadCount { get; set; }
    
    public bool IsPublic { get; set; }
    
    public DateTimeOffset? ExpiresAt { get; set; }
    
    // Navigation property
    public virtual ApplicationUser User { get; set; } = default!;
    
    // Computed property for storage location
    public string StorageLocation => StorageType == StorageType.Database ? 
        "Database" : StoragePath ?? string.Empty;
}
