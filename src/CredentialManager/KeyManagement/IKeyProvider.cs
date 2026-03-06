namespace CredentialManager.KeyManagement;

/// <summary>
/// Resolves the master encryption key from the configured source.
/// Implementations may read from an environment variable, a key file,
/// or a remote Credential Vault server.
/// </summary>
public interface IKeyProvider
{
    /// <summary>Returns the 32-byte AES-256 master key.</summary>
    Task<byte[]> GetKeyAsync(CancellationToken cancellationToken = default);
}
