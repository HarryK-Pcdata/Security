using CredentialManager.Encryption;
using CredentialManager.KeyManagement;
using Microsoft.Extensions.Logging;

namespace CredentialManager.Client;

/// <summary>
/// High-level facade for reading credentials from encrypted config/ini files at runtime.
/// Use this class from both C# and (via P/Invoke or COM) from Delphi applications.
/// </summary>
public sealed class CredentialReader
{
    private readonly IKeyProvider _keyProvider;
    private readonly ILogger<CredentialReader>? _logger;

    /// <param name="keyProvider">Source of the AES-256 master key.</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    public CredentialReader(IKeyProvider keyProvider, ILogger<CredentialReader>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(keyProvider);
        _keyProvider = keyProvider;
        _logger = logger;
    }

    /// <summary>
    /// Returns the decrypted value of a credential.
    /// If the value is not encrypted it is returned as-is, allowing a gradual
    /// migration from plaintext to encrypted configs.
    /// </summary>
    /// <param name="encryptedOrPlainValue">
    /// The value read directly from the config/ini file.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<string> ReadAsync(
        string encryptedOrPlainValue,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(encryptedOrPlainValue);

        byte[] key = await _keyProvider.GetKeyAsync(cancellationToken);
        var encryptor = new AesGcmEncryptor(key);

        if (!encryptor.IsEncrypted(encryptedOrPlainValue))
        {
            _logger?.LogWarning(
                "Credential value is not encrypted. " +
                "Run 'credmgr encrypt' to secure the configuration file.");
            return encryptedOrPlainValue;
        }

        return encryptor.Decrypt(encryptedOrPlainValue);
    }

    /// <summary>
    /// Synchronous variant of <see cref="ReadAsync"/> for use in environments
    /// that cannot use async/await (e.g. application startup or Delphi COM interop).
    /// </summary>
    public string Read(string encryptedOrPlainValue) =>
        ReadAsync(encryptedOrPlainValue).GetAwaiter().GetResult();
}
