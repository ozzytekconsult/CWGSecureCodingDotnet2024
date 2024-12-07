namespace CWG.SecureCoding.Core.DTOs.Common;

public abstract class BaseDto
{
    public int Id { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? UpdatedAt { get; set; }
}

public abstract class AuditableDto : BaseDto
{
    public string CreatedBy { get; set; } = default!;
    public string? UpdatedBy { get; set; }
}
