using System.Security.Cryptography;
using CredentialManager.Encryption;
using Xunit;

namespace CredentialManager.Tests;

public sealed class AesGcmEncryptorTests
{
    private static AesGcmEncryptor CreateEncryptor()
    {
        byte[] key = AesGcmEncryptor.GenerateKey();
        return new AesGcmEncryptor(key);
    }

    [Fact]
    public void Encrypt_ReturnsEncPrefixedString()
    {
        var enc = CreateEncryptor();
        string result = enc.Encrypt("s3cr3t");
        Assert.StartsWith(AesGcmEncryptor.EncryptedPrefix, result);
    }

    [Fact]
    public void RoundTrip_PlaintextIsRecovered()
    {
        var enc = CreateEncryptor();
        const string plaintext = "Pa$$w0rd!";
        string encrypted = enc.Encrypt(plaintext);
        string decrypted = enc.Decrypt(encrypted);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void RoundTrip_EmptyString()
    {
        var enc = CreateEncryptor();
        string encrypted = enc.Encrypt(string.Empty);
        string decrypted = enc.Decrypt(encrypted);
        Assert.Equal(string.Empty, decrypted);
    }

    [Fact]
    public void RoundTrip_UnicodeValue()
    {
        var enc = CreateEncryptor();
        const string plaintext = "Wachtw00rd!@#€£¥";
        string decrypted = enc.Decrypt(enc.Encrypt(plaintext));
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_ProducesUniqueOutputEachCall()
    {
        var enc = CreateEncryptor();
        string a = enc.Encrypt("same");
        string b = enc.Encrypt("same");
        Assert.NotEqual(a, b);   // nonces differ
    }

    [Fact]
    public void IsEncrypted_ReturnsTrueForEncryptedValue()
    {
        var enc = CreateEncryptor();
        Assert.True(enc.IsEncrypted(enc.Encrypt("test")));
    }

    [Fact]
    public void IsEncrypted_ReturnsFalseForPlaintext()
    {
        var enc = CreateEncryptor();
        Assert.False(enc.IsEncrypted("plaintext"));
    }

    [Fact]
    public void Decrypt_ThrowsForNonEncryptedValue()
    {
        var enc = CreateEncryptor();
        Assert.Throws<ArgumentException>(() => enc.Decrypt("not-encrypted"));
    }

    [Fact]
    public void Decrypt_ThrowsForTamperedCiphertext()
    {
        var enc = CreateEncryptor();
        string good = enc.Encrypt("value");
        // Flip one byte in the ciphertext portion
        byte[] raw = Convert.FromBase64String(good[AesGcmEncryptor.EncryptedPrefix.Length..]);
        raw[^1] ^= 0xFF;
        string tampered = AesGcmEncryptor.EncryptedPrefix + Convert.ToBase64String(raw);

        Assert.Throws<AuthenticationTagMismatchException>(() => enc.Decrypt(tampered));
    }

    [Fact]
    public void WrongKey_CannotDecrypt()
    {
        var enc1 = CreateEncryptor();
        var enc2 = CreateEncryptor();
        string encrypted = enc1.Encrypt("secret");

        Assert.Throws<AuthenticationTagMismatchException>(() => enc2.Decrypt(encrypted));
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(0)]
    public void Constructor_ThrowsForWrongKeyLength(int keyLength)
    {
        byte[] badKey = new byte[keyLength];
        Assert.Throws<ArgumentException>(() => new AesGcmEncryptor(badKey));
    }

    [Fact]
    public void GenerateKey_ReturnsCorrectLength()
    {
        byte[] key = AesGcmEncryptor.GenerateKey();
        Assert.Equal(AesGcmEncryptor.KeySizeBytes, key.Length);
    }

    [Fact]
    public void DeriveKeyFromPassword_ReturnsCorrectLength()
    {
        byte[] salt = new byte[32];
        byte[] key = AesGcmEncryptor.DeriveKeyFromPassword("P@ssw0rd!", salt);
        Assert.Equal(AesGcmEncryptor.KeySizeBytes, key.Length);
    }

    [Fact]
    public void DeriveKeyFromPassword_IsDeterministic()
    {
        byte[] salt = new byte[32];
        byte[] key1 = AesGcmEncryptor.DeriveKeyFromPassword("same", salt);
        byte[] key2 = AesGcmEncryptor.DeriveKeyFromPassword("same", salt);
        Assert.Equal(key1, key2);
    }

    [Fact]
    public void DeriveKeyFromPassword_DifferentPasswordsDifferentKeys()
    {
        byte[] salt = new byte[32];
        byte[] key1 = AesGcmEncryptor.DeriveKeyFromPassword("password1", salt);
        byte[] key2 = AesGcmEncryptor.DeriveKeyFromPassword("password2", salt);
        Assert.NotEqual(key1, key2);
    }

    [Fact]
    public void DeriveKeyFromPassword_ThrowsForShortSalt()
    {
        Assert.Throws<ArgumentException>(() =>
            AesGcmEncryptor.DeriveKeyFromPassword("pw", new byte[15]));
    }

    [Fact]
    public void DeriveKeyFromPassword_ThrowsForLowIterations()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            AesGcmEncryptor.DeriveKeyFromPassword("pw", new byte[32], 99_999));
    }
}
