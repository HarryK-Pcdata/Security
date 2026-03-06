using System;
using System.Text;
using CredentialVault.Core.Encryption;
using Xunit;

namespace CredentialVault.Tests.Core;

public sealed class AesGcmEncryptorTests
{
    [Fact]
    public void GenerateKey_Returns32Bytes()
    {
        byte[] key = AesGcmEncryptor.GenerateKey();
        Assert.Equal(AesGcmEncryptor.KeySize, key.Length);
    }

    [Fact]
    public void GenerateKey_ReturnsDifferentKeyEachTime()
    {
        byte[] key1 = AesGcmEncryptor.GenerateKey();
        byte[] key2 = AesGcmEncryptor.GenerateKey();
        Assert.NotEqual(key1, key2);
    }

    [Theory]
    [InlineData("Hello, World!")]
    [InlineData("Password@123!")]
    [InlineData("Server=db01;Database=Prod;User Id=sa;Password=Secret;")]
    [InlineData("")]
    public void EncryptDecrypt_RoundTrip_ReturnsOriginalPlaintext(string plaintext)
    {
        byte[] key = AesGcmEncryptor.GenerateKey();
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

        byte[] encrypted = AesGcmEncryptor.Encrypt(plaintextBytes, key);
        byte[] decrypted = AesGcmEncryptor.Decrypt(encrypted, key);

        Assert.Equal(plaintextBytes, decrypted);
    }

    [Fact]
    public void Encrypt_SamePlaintext_ProducesDifferentCiphertextEachTime()
    {
        byte[] key = AesGcmEncryptor.GenerateKey();
        byte[] plaintext = Encoding.UTF8.GetBytes("same plaintext");

        byte[] enc1 = AesGcmEncryptor.Encrypt(plaintext, key);
        byte[] enc2 = AesGcmEncryptor.Encrypt(plaintext, key);

        // Different nonces produce different ciphertexts (IND-CPA property)
        Assert.NotEqual(enc1, enc2);
    }

    [Fact]
    public void Encrypt_OutputLength_IsNoncePlusTagPlusCiphertext()
    {
        byte[] key = AesGcmEncryptor.GenerateKey();
        byte[] plaintext = Encoding.UTF8.GetBytes("test");

        byte[] encrypted = AesGcmEncryptor.Encrypt(plaintext, key);

        int expected = AesGcmEncryptor.NonceSize + AesGcmEncryptor.TagSize + plaintext.Length;
        Assert.Equal(expected, encrypted.Length);
    }

    [Fact]
    public void Decrypt_WithWrongKey_ThrowsCryptographicException()
    {
        byte[] correctKey = AesGcmEncryptor.GenerateKey();
        byte[] wrongKey = AesGcmEncryptor.GenerateKey();
        byte[] plaintext = Encoding.UTF8.GetBytes("secret");

        byte[] encrypted = AesGcmEncryptor.Encrypt(plaintext, correctKey);

        // Use ThrowsAny because .NET may throw a subclass (AuthenticationTagMismatchException)
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(
            () => AesGcmEncryptor.Decrypt(encrypted, wrongKey));
    }

    [Fact]
    public void Decrypt_WithTamperedCiphertext_ThrowsCryptographicException()
    {
        byte[] key = AesGcmEncryptor.GenerateKey();
        byte[] encrypted = AesGcmEncryptor.Encrypt(Encoding.UTF8.GetBytes("secret"), key);

        // Tamper with the ciphertext portion (after nonce + tag)
        encrypted[AesGcmEncryptor.NonceSize + AesGcmEncryptor.TagSize] ^= 0xFF;

        // Use ThrowsAny because .NET may throw a subclass (AuthenticationTagMismatchException)
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(
            () => AesGcmEncryptor.Decrypt(encrypted, key));
    }

    [Fact]
    public void Encrypt_NullPlaintext_ThrowsArgumentNullException()
    {
        byte[] key = AesGcmEncryptor.GenerateKey();
        Assert.Throws<ArgumentNullException>(() => AesGcmEncryptor.Encrypt(null!, key));
    }

    [Fact]
    public void Encrypt_NullKey_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => AesGcmEncryptor.Encrypt([], null!));
    }

    [Fact]
    public void Encrypt_WrongKeySize_ThrowsArgumentException()
    {
        byte[] badKey = new byte[16]; // 128-bit instead of 256-bit
        Assert.Throws<ArgumentException>(() => AesGcmEncryptor.Encrypt([], badKey));
    }

    [Fact]
    public void Decrypt_TooShortData_ThrowsArgumentException()
    {
        byte[] key = AesGcmEncryptor.GenerateKey();
        byte[] tooShort = new byte[5];

        Assert.Throws<ArgumentException>(() => AesGcmEncryptor.Decrypt(tooShort, key));
    }
}
