using System.Security.Cryptography;
using System.Text;

namespace CredentialVault.Core.Encryption;

/// <summary>
/// Encrypts and decrypts string values using AES-256-GCM.
/// Encrypted values are stored with an <c>ENC:</c> prefix followed by a
/// Base64-encoded payload of <c>nonce[12] || tag[16] || ciphertext[n]</c>.
/// </summary>
public sealed class AesGcmEncryptor
{
    private const string EncPrefix = "ENC:";
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32; // AES-256

    private readonly byte[] _key;

    /// <summary>
    /// Initialises the encryptor from a raw 32-byte key.
    /// </summary>
    public AesGcmEncryptor(byte[] key)
    {
        if (key is null || key.Length != KeySize)
            throw new ArgumentException($"Key must be exactly {KeySize} bytes.", nameof(key));
        _key = (byte[])key.Clone();
    }

    /// <summary>
    /// Derives an encryptor from a passphrase using PBKDF2-SHA256 with a
    /// fixed salt derived from the passphrase itself (deterministic).  This
    /// is intentionally simple so the same passphrase always produces the
    /// same key; production deployments should manage key rotation externally.
    /// </summary>
    public static AesGcmEncryptor FromPassphrase(string passphrase)
    {
        if (string.IsNullOrEmpty(passphrase))
            throw new ArgumentException("Passphrase must not be empty.", nameof(passphrase));

        // Derive a stable salt from the passphrase (SHA-256 of UTF-8 bytes).
        var salt = SHA256.HashData(Encoding.UTF8.GetBytes(passphrase));
        var key = Rfc2898DeriveBytes.Pbkdf2(
            password: Encoding.UTF8.GetBytes(passphrase),
            salt: salt,
            iterations: 100_000,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: KeySize);
        return new AesGcmEncryptor(key);
    }

    /// <summary>
    /// Returns <c>true</c> when <paramref name="value"/> looks like an
    /// already-encrypted token (starts with <c>ENC:</c>).
    /// </summary>
    public static bool IsEncrypted(string value) =>
        value is not null && value.StartsWith(EncPrefix, StringComparison.Ordinal);

    /// <summary>Encrypts <paramref name="plaintext"/> and returns an <c>ENC:…</c> token.</summary>
    public string Encrypt(string plaintext)
    {
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(_key, TagSize);
        aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

        // Layout: nonce || tag || ciphertext
        var payload = new byte[NonceSize + TagSize + ciphertext.Length];
        nonce.CopyTo(payload, 0);
        tag.CopyTo(payload, NonceSize);
        ciphertext.CopyTo(payload, NonceSize + TagSize);

        return EncPrefix + Convert.ToBase64String(payload);
    }

    /// <summary>
    /// Decrypts a token returned by <see cref="Encrypt"/>.
    /// If <paramref name="token"/> does not start with <c>ENC:</c> it is
    /// returned unchanged (pass-through for unencrypted plain values).
    /// </summary>
    public string Decrypt(string token)
    {
        if (!IsEncrypted(token))
            return token;

        var payload = Convert.FromBase64String(token[EncPrefix.Length..]);
        if (payload.Length < NonceSize + TagSize)
            throw new CryptographicException("Invalid encrypted token: payload too short.");

        var nonce = payload[..NonceSize];
        var tag = payload[NonceSize..(NonceSize + TagSize)];
        var ciphertext = payload[(NonceSize + TagSize)..];
        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(_key, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);

        return Encoding.UTF8.GetString(plaintext);
    }
}
