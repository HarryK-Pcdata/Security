using System;
using System.Security.Cryptography;
using System.Text;

namespace CredentialVault.Core.Encryption;

/// <summary>
/// Derives cryptographic keys from passwords or passphrases using PBKDF2-SHA256.
/// Used to convert human-readable master passwords into AES keys.
/// </summary>
public static class SecretKeyDerivation
{
    /// <summary>Number of PBKDF2 iterations (OWASP 2023 recommendation for PBKDF2-SHA256).</summary>
    public const int Iterations = 600_000;

    /// <summary>Size of the random salt in bytes (256 bits).</summary>
    public const int SaltSize = 32;

    /// <summary>
    /// Derives a 256-bit AES key from a password and salt using PBKDF2-SHA256.
    /// </summary>
    /// <param name="password">The password or passphrase.</param>
    /// <param name="salt">A random salt (use <see cref="GenerateSalt"/> to create one).</param>
    /// <returns>A 256-bit key suitable for use with AES-256-GCM.</returns>
    public static byte[] DeriveKey(string password, byte[] salt)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        ArgumentNullException.ThrowIfNull(salt);

        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            Iterations,
            HashAlgorithmName.SHA256,
            AesGcmEncryptor.KeySize);
    }

    /// <summary>
    /// Generates a cryptographically random salt.
    /// </summary>
    public static byte[] GenerateSalt()
    {
        return RandomNumberGenerator.GetBytes(SaltSize);
    }
}
