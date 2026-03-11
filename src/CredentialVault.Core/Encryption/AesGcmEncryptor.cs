using System;
using System.Security.Cryptography;

namespace CredentialVault.Core.Encryption;

/// <summary>
/// Provides authenticated encryption and decryption using AES-256-GCM.
/// AES-256-GCM is an AEAD (Authenticated Encryption with Associated Data) cipher
/// that provides both confidentiality and integrity/authenticity guarantees.
/// </summary>
public static class AesGcmEncryptor
{
    /// <summary>Size of the AES key in bytes (256 bits).</summary>
    public const int KeySize = 32;

    /// <summary>Size of the GCM nonce in bytes (96 bits, the recommended size).</summary>
    public const int NonceSize = 12;

    /// <summary>Size of the GCM authentication tag in bytes (128 bits).</summary>
    public const int TagSize = 16;

    /// <summary>
    /// Generates a cryptographically random 256-bit AES key.
    /// </summary>
    public static byte[] GenerateKey()
    {
        return RandomNumberGenerator.GetBytes(KeySize);
    }

    /// <summary>
    /// Encrypts plaintext using AES-256-GCM.
    /// Returns a combined byte array: nonce (12 bytes) + tag (16 bytes) + ciphertext.
    /// </summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <param name="key">A 256-bit (32-byte) AES key.</param>
    /// <returns>Combined nonce + tag + ciphertext.</returns>
    public static byte[] Encrypt(byte[] plaintext, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(key);

        if (key.Length != KeySize)
            throw new ArgumentException($"Key must be {KeySize} bytes ({KeySize * 8} bits).", nameof(key));

        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] tag = new byte[TagSize];
        byte[] ciphertext = new byte[plaintext.Length];

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        // Layout: [nonce (12)] [tag (16)] [ciphertext (n)]
        byte[] result = new byte[NonceSize + TagSize + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
        Buffer.BlockCopy(tag, 0, result, NonceSize, TagSize);
        Buffer.BlockCopy(ciphertext, 0, result, NonceSize + TagSize, ciphertext.Length);
        return result;
    }

    /// <summary>
    /// Decrypts a ciphertext produced by <see cref="Encrypt"/>.
    /// </summary>
    /// <param name="encryptedData">Combined nonce + tag + ciphertext as returned by Encrypt.</param>
    /// <param name="key">The 256-bit key used for encryption.</param>
    /// <returns>The original plaintext bytes.</returns>
    public static byte[] Decrypt(byte[] encryptedData, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(encryptedData);
        ArgumentNullException.ThrowIfNull(key);

        if (key.Length != KeySize)
            throw new ArgumentException($"Key must be {KeySize} bytes ({KeySize * 8} bits).", nameof(key));

        int minimumLength = NonceSize + TagSize;
        if (encryptedData.Length < minimumLength)
            throw new ArgumentException("Encrypted data is too short to be valid.", nameof(encryptedData));

        byte[] nonce = encryptedData[..NonceSize];
        byte[] tag = encryptedData[NonceSize..(NonceSize + TagSize)];
        byte[] ciphertext = encryptedData[(NonceSize + TagSize)..];
        byte[] plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }
}
