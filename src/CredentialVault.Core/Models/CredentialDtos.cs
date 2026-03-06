using System.ComponentModel.DataAnnotations;

namespace CredentialVault.Core.Models;

/// <summary>Request DTO for storing a credential in the vault.</summary>
public sealed class StoreCredentialRequest
{
    /// <summary>Application or service name.</summary>
    [Required]
    [MaxLength(200)]
    public string Application { get; init; } = string.Empty;

    /// <summary>Logical key/name for the credential.</summary>
    [Required]
    [MaxLength(200)]
    public string Key { get; init; } = string.Empty;

    /// <summary>The plaintext credential value to encrypt and store.</summary>
    [Required]
    public string PlainTextValue { get; init; } = string.Empty;

    /// <summary>Optional description for this credential.</summary>
    [MaxLength(500)]
    public string? Description { get; init; }
}

/// <summary>Response DTO returned when retrieving a credential from the vault.</summary>
public sealed class CredentialResponse
{
    /// <summary>Application or service name.</summary>
    public string Application { get; init; } = string.Empty;

    /// <summary>Logical key/name for the credential.</summary>
    public string Key { get; init; } = string.Empty;

    /// <summary>The decrypted plaintext credential value.</summary>
    public string Value { get; init; } = string.Empty;

    /// <summary>Optional description.</summary>
    public string? Description { get; init; }
}
