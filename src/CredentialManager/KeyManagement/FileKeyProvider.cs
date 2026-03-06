using CredentialManager.Encryption;

namespace CredentialManager.KeyManagement;

/// <summary>
/// Reads the master key from a protected key file on disk.
/// The file must contain a Base64-encoded 32-byte key as its sole content.
/// </summary>
/// <remarks>
/// On Windows the file should be protected by NTFS ACLs so that only the
/// service account and administrators can read it.  On Linux, set permissions
/// to 0600 (owner read/write only).
/// </remarks>
public sealed class FileKeyProvider : IKeyProvider
{
    private readonly string _keyFilePath;

    /// <param name="keyFilePath">Absolute path to the key file.</param>
    public FileKeyProvider(string keyFilePath)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyFilePath);
        _keyFilePath = keyFilePath;
    }

    /// <inheritdoc />
    public async Task<byte[]> GetKeyAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(_keyFilePath))
            throw new FileNotFoundException(
                $"Key file not found at '{_keyFilePath}'. " +
                "Run 'credmgr generate-key' and store the result in a protected file.", _keyFilePath);

        string base64 = (await File.ReadAllTextAsync(_keyFilePath, cancellationToken)).Trim();

        byte[] key;
        try
        {
            key = Convert.FromBase64String(base64);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException(
                $"Key file at '{_keyFilePath}' does not contain a valid Base64 string.", ex);
        }

        if (key.Length != AesGcmEncryptor.KeySizeBytes)
            throw new InvalidOperationException(
                $"Key file at '{_keyFilePath}' must decode to exactly " +
                $"{AesGcmEncryptor.KeySizeBytes} bytes (currently {key.Length}).");

        return key;
    }
}
