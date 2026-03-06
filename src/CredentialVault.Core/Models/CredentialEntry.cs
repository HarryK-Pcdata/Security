using System;
using System.Text.Json.Serialization;

namespace CredentialVault.Core.Models;

/// <summary>
/// Represents an encrypted credential entry stored in the vault.
/// </summary>
public sealed class CredentialEntry
{
    /// <summary>Unique identifier for this credential entry.</summary>
    public Guid Id { get; init; } = Guid.NewGuid();

    /// <summary>
    /// Application or service name this credential belongs to.
    /// E.g. "CRM", "ERP", "LegacyApp1".
    /// </summary>
    public string Application { get; init; } = string.Empty;

    /// <summary>
    /// Logical key/name for the credential within the application.
    /// E.g. "DatabaseConnectionString", "ApiKey", "AdminPassword".
    /// </summary>
    public string Key { get; init; } = string.Empty;

    /// <summary>
    /// The encrypted credential value, stored as a Base64-encoded string.
    /// The underlying bytes are: nonce (12) + GCM tag (16) + AES-256-GCM ciphertext.
    /// </summary>
    public string EncryptedValue { get; set; } = string.Empty;

    /// <summary>
    /// PBKDF2 salt used when deriving the encryption key from the master password.
    /// Stored as Base64. Only present when key is password-derived; null when a raw key is used.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? KeyDerivationSalt { get; set; }

    /// <summary>Timestamp when this entry was created.</summary>
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Timestamp when this entry was last updated.</summary>
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// Optional description for this credential, useful for the service department.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Description { get; set; }
}
