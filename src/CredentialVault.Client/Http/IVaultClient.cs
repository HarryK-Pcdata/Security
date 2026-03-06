using System.Threading;
using System.Threading.Tasks;

namespace CredentialVault.Client.Http;

/// <summary>
/// Abstraction over the credential vault, allowing easy mocking in tests
/// and alternative implementations (e.g. local encrypted file fallback).
/// </summary>
public interface IVaultClient
{
    /// <summary>
    /// Retrieves a decrypted credential value from the vault.
    /// </summary>
    /// <param name="application">Application or service name (e.g. "CRM").</param>
    /// <param name="key">Credential key (e.g. "DatabaseConnectionString").</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The decrypted credential value, or null if not found.</returns>
    Task<string?> GetCredentialAsync(
        string application,
        string key,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Stores (creates or updates) a credential in the vault.
    /// </summary>
    /// <param name="application">Application or service name.</param>
    /// <param name="key">Credential key.</param>
    /// <param name="value">The plaintext credential value to store.</param>
    /// <param name="description">Optional description visible to the service department.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task StoreCredentialAsync(
        string application,
        string key,
        string value,
        string? description = null,
        CancellationToken cancellationToken = default);
}
