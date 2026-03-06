namespace CredentialManager.Server.Models;

/// <summary>API key record used to authenticate client applications.</summary>
public sealed class ApiKeyRecord
{
    /// <summary>The raw API key value (stored as a SHA-256 hash in production).</summary>
    public required string HashedKey { get; init; }

    /// <summary>Human-readable label for the key (e.g. "CustomerA-App").</summary>
    public required string Label { get; init; }

    /// <summary>Roles granted by this key (e.g. "read", "admin").</summary>
    public required IReadOnlyList<string> Roles { get; init; }

    /// <summary>Whether this key is still valid.</summary>
    public bool IsActive { get; init; } = true;
}
