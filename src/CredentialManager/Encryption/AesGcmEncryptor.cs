using System.Security.Cryptography;
using System.Text;

namespace CredentialManager.Encryption;

/// <summary>
/// Provides AES-256-GCM authenticated encryption for credential values.
/// AES-GCM is an AEAD (Authenticated Encryption with Associated Data) scheme
/// that provides both confidentiality and integrity protection.
/// </summary>
public sealed class AesGcmEncryptor : IEncryptor
{
    // AES-256 requires a 32-byte key.
    public const int KeySizeBytes = 32;

    // AES-GCM standard nonce size.
    private const int NonceSizeBytes = 12;

    // AES-GCM produces a 16-byte authentication tag.
    private const int TagSizeBytes = 16;

    // Prefix used in encrypted values to distinguish them from plaintext.
    public const string EncryptedPrefix = "ENC:";

    private readonly byte[] _key;

    /// <summary>
    /// Initialises the encryptor with the provided 256-bit key.
    /// </summary>
    /// <param name="key">A 32-byte AES-256 key.</param>
    public AesGcmEncryptor(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != KeySizeBytes)
            throw new ArgumentException($"Key must be exactly {KeySizeBytes} bytes for AES-256.", nameof(key));

        _key = (byte[])key.Clone();
    }

    /// <inheritdoc />
    public string Encrypt(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] nonce = new byte[NonceSizeBytes];
        byte[] tag = new byte[TagSizeBytes];
        byte[] ciphertext = new byte[plaintextBytes.Length];

        RandomNumberGenerator.Fill(nonce);

        using var aesGcm = new AesGcm(_key, TagSizeBytes);
        aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag);

        // Layout: nonce (12 bytes) | tag (16 bytes) | ciphertext (n bytes)
        byte[] combined = new byte[NonceSizeBytes + TagSizeBytes + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, combined, 0, NonceSizeBytes);
        Buffer.BlockCopy(tag, 0, combined, NonceSizeBytes, TagSizeBytes);
        Buffer.BlockCopy(ciphertext, 0, combined, NonceSizeBytes + TagSizeBytes, ciphertext.Length);

        return EncryptedPrefix + Convert.ToBase64String(combined);
    }

    /// <inheritdoc />
    public string Decrypt(string ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        if (!ciphertext.StartsWith(EncryptedPrefix, StringComparison.Ordinal))
            throw new ArgumentException("Value does not appear to be encrypted by this library.", nameof(ciphertext));

        byte[] combined = Convert.FromBase64String(ciphertext[EncryptedPrefix.Length..]);

        if (combined.Length < NonceSizeBytes + TagSizeBytes)
            throw new CryptographicException("Encrypted data is too short to be valid.");

        byte[] nonce = combined[..NonceSizeBytes];
        byte[] tag = combined[NonceSizeBytes..(NonceSizeBytes + TagSizeBytes)];
        byte[] encryptedBytes = combined[(NonceSizeBytes + TagSizeBytes)..];
        byte[] plaintextBytes = new byte[encryptedBytes.Length];

        using var aesGcm = new AesGcm(_key, TagSizeBytes);
        aesGcm.Decrypt(nonce, encryptedBytes, tag, plaintextBytes);

        return Encoding.UTF8.GetString(plaintextBytes);
    }

    /// <inheritdoc />
    public bool IsEncrypted(string value) =>
        !string.IsNullOrEmpty(value) && value.StartsWith(EncryptedPrefix, StringComparison.Ordinal);

    /// <summary>
    /// Derives a 32-byte AES-256 key from a password using PBKDF2-HMAC-SHA256.
    /// </summary>
    /// <param name="password">The master password.</param>
    /// <param name="salt">
    /// A stable, non-secret salt (e.g. an application or installation identifier).
    /// Must be at least 16 bytes.
    /// </param>
    /// <param name="iterations">Number of PBKDF2 iterations (minimum 100 000).</param>
    /// <returns>A 32-byte derived key.</returns>
    public static byte[] DeriveKeyFromPassword(string password, byte[] salt, int iterations = 600_000)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        ArgumentNullException.ThrowIfNull(salt);
        if (salt.Length < 16)
            throw new ArgumentException("Salt must be at least 16 bytes.", nameof(salt));
        if (iterations < 100_000)
            throw new ArgumentOutOfRangeException(nameof(iterations), "Iteration count must be at least 100 000.");

        return Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            KeySizeBytes);
    }

    /// <summary>
    /// Generates a cryptographically random 32-byte key.
    /// </summary>
    public static byte[] GenerateKey()
    {
        byte[] key = new byte[KeySizeBytes];
        RandomNumberGenerator.Fill(key);
        return key;
    }
}
