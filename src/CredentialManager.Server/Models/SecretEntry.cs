namespace CredentialManager.Server.Models;

/// <summary>Represents a stored credential secret.</summary>
public sealed class SecretEntry
{
    /// <summary>Unique name / key for this secret (e.g. "CustomerA/DbPassword").</summary>
    public required string Name { get; init; }

    /// <summary>The AES-256-GCM encrypted value (ENC: prefix).</summary>
    public required string EncryptedValue { get; init; }

    /// <summary>Optional description for the service department.</summary>
    public string? Description { get; init; }

    /// <summary>UTC timestamp when this entry was last updated.</summary>
    public DateTimeOffset UpdatedAt { get; init; } = DateTimeOffset.UtcNow;
}
