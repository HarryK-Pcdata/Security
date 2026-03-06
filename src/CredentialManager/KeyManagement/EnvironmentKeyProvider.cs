using CredentialManager.Encryption;

namespace CredentialManager.KeyManagement;

/// <summary>
/// Reads the master key from the environment variable <c>CREDENTIAL_MASTER_KEY</c>.
/// The value must be a Base64-encoded 32-byte key.
/// </summary>
/// <remarks>
/// This provider is suitable for container and CI environments where secrets are
/// injected as environment variables rather than stored on disk.
/// </remarks>
public sealed class EnvironmentKeyProvider : IKeyProvider
{
    /// <summary>Name of the environment variable that holds the Base64-encoded key.</summary>
    public const string EnvironmentVariableName = "CREDENTIAL_MASTER_KEY";

    private readonly string _variableName;

    /// <param name="variableName">
    /// Optional override of the environment variable name.
    /// Defaults to <see cref="EnvironmentVariableName"/>.
    /// </param>
    public EnvironmentKeyProvider(string variableName = EnvironmentVariableName)
    {
        ArgumentException.ThrowIfNullOrEmpty(variableName);
        _variableName = variableName;
    }

    /// <inheritdoc />
    public Task<byte[]> GetKeyAsync(CancellationToken cancellationToken = default)
    {
        string? value = Environment.GetEnvironmentVariable(_variableName);
        if (string.IsNullOrWhiteSpace(value))
            throw new InvalidOperationException(
                $"Environment variable '{_variableName}' is not set. " +
                "Set it to a Base64-encoded 32-byte AES-256 key.");

        byte[] key;
        try
        {
            key = Convert.FromBase64String(value.Trim());
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException(
                $"Environment variable '{_variableName}' does not contain a valid Base64 string.", ex);
        }

        if (key.Length != AesGcmEncryptor.KeySizeBytes)
            throw new InvalidOperationException(
                $"Environment variable '{_variableName}' must decode to exactly " +
                $"{AesGcmEncryptor.KeySizeBytes} bytes (currently {key.Length}).");

        return Task.FromResult(key);
    }
}
