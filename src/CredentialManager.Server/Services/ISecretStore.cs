using CredentialManager.Server.Models;

namespace CredentialManager.Server.Services;

/// <summary>Persists and retrieves encrypted secret entries.</summary>
public interface ISecretStore
{
    /// <summary>Returns the secret entry for <paramref name="name"/>, or <c>null</c> if not found.</summary>
    Task<SecretEntry?> GetAsync(string name, CancellationToken ct = default);

    /// <summary>Returns all secret names.</summary>
    Task<IReadOnlyList<string>> ListNamesAsync(CancellationToken ct = default);

    /// <summary>Creates or replaces a secret entry.</summary>
    Task UpsertAsync(SecretEntry entry, CancellationToken ct = default);

    /// <summary>Removes a secret entry. Returns <c>true</c> if it existed.</summary>
    Task<bool> DeleteAsync(string name, CancellationToken ct = default);
}
