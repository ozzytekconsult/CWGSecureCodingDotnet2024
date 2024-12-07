using CWG.SecureCoding.Core.DTOs.Common;
using System.ComponentModel.DataAnnotations;

namespace CWG.SecureCoding.Core.DTOs.Documents;

public class DocumentDto : AuditableDto
{
    public int Id { get; set; }
    public string FileName { get; set; } = default!;
    public string ContentType { get; set; } = default!;
    public long FileSize { get; set; }
    public string Path { get; set; } = default!;
    public string Category { get; set; } = default!;
    public Dictionary<string, string> Metadata { get; set; } = new();
    public bool IsPublic { get; set; }
    public string? Description { get; set; }
    public string Hash { get; set; } = default!;
    public bool IsVerified { get; set; }
}

public class UploadDocumentDto
{
    [Required]
    [MaxLength(255)]
    [RegularExpression(@"^[\w\-. ]+$", ErrorMessage = "Filename contains invalid characters")]
    public string FileName { get; set; } = default!;

    [Required]
    [MaxLength(100)]
    public string ContentType { get; set; } = default!;

    [Required]
    [Range(1, 104857600)] // Max 100MB
    public long FileSize { get; set; }

    [Required]
    [MaxLength(50)]
    public string Category { get; set; } = default!;

    public Dictionary<string, string> Metadata { get; set; } = new();

    public bool IsPublic { get; set; }

    [MaxLength(500)]
    public string? Description { get; set; }
}

public class UpdateDocumentDto
{
    [MaxLength(50)]
    public string? Category { get; set; }

    public Dictionary<string, string>? Metadata { get; set; }

    public bool? IsPublic { get; set; }

    [MaxLength(500)]
    public string? Description { get; set; }
}

public class DocumentSearchDto
{
    public string? SearchTerm { get; set; }
    public string? Category { get; set; }
    public string? ContentType { get; set; }
    public DateTime? UploadedAfter { get; set; }
    public DateTime? UploadedBefore { get; set; }
    public bool? IsPublic { get; set; }
    public bool? IsVerified { get; set; }
    public long? MinSize { get; set; }
    public long? MaxSize { get; set; }
    public string? UploadedBy { get; set; }
    public string? SortBy { get; set; }
    public bool SortDescending { get; set; }
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 20;
}

public class DocumentVerificationDto
{
    [Required]
    public int DocumentId { get; set; }

    [Required]
    public string Hash { get; set; } = default!;

    [Required]
    public string VerificationType { get; set; } = default!;

    public Dictionary<string, string> VerificationMetadata { get; set; } = new();
}

public class DocumentSharingDto
{
    [Required]
    public int DocumentId { get; set; }

    [Required]
    public List<string> SharedWithUserIds { get; set; } = new();

    public DateTime? ExpiresAt { get; set; }

    [MaxLength(500)]
    public string? ShareMessage { get; set; }

    public Dictionary<string, string> SharingMetadata { get; set; } = new();
}

public class DocumentScanResultDto
{
    public int DocumentId { get; set; }
    public bool IsClean { get; set; }
    public string? ThreatType { get; set; }
    public string? ScanEngine { get; set; }
    public DateTime ScanDate { get; set; }
    public Dictionary<string, string> ScanMetadata { get; set; } = new();
}
