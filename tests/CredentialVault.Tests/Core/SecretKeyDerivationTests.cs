using System;
using System.Text;
using CredentialVault.Core.Encryption;
using Xunit;

namespace CredentialVault.Tests.Core;

public sealed class SecretKeyDerivationTests
{
    [Fact]
    public void GenerateSalt_Returns32Bytes()
    {
        byte[] salt = SecretKeyDerivation.GenerateSalt();
        Assert.Equal(SecretKeyDerivation.SaltSize, salt.Length);
    }

    [Fact]
    public void GenerateSalt_ReturnsDifferentSaltEachTime()
    {
        byte[] s1 = SecretKeyDerivation.GenerateSalt();
        byte[] s2 = SecretKeyDerivation.GenerateSalt();
        Assert.NotEqual(s1, s2);
    }

    [Fact]
    public void DeriveKey_SamePasswordAndSalt_ProducesSameKey()
    {
        byte[] salt = SecretKeyDerivation.GenerateSalt();
        byte[] key1 = SecretKeyDerivation.DeriveKey("MyPassword", salt);
        byte[] key2 = SecretKeyDerivation.DeriveKey("MyPassword", salt);

        Assert.Equal(key1, key2);
        Assert.Equal(AesGcmEncryptor.KeySize, key1.Length);
    }

    [Fact]
    public void DeriveKey_DifferentPasswords_ProduceDifferentKeys()
    {
        byte[] salt = SecretKeyDerivation.GenerateSalt();
        byte[] key1 = SecretKeyDerivation.DeriveKey("Password1", salt);
        byte[] key2 = SecretKeyDerivation.DeriveKey("Password2", salt);

        Assert.NotEqual(key1, key2);
    }

    [Fact]
    public void DeriveKey_SamePasswordDifferentSalts_ProduceDifferentKeys()
    {
        byte[] salt1 = SecretKeyDerivation.GenerateSalt();
        byte[] salt2 = SecretKeyDerivation.GenerateSalt();

        byte[] key1 = SecretKeyDerivation.DeriveKey("SamePassword", salt1);
        byte[] key2 = SecretKeyDerivation.DeriveKey("SamePassword", salt2);

        Assert.NotEqual(key1, key2);
    }

    [Fact]
    public void DeriveKey_DerivedKeyWorksWithEncryptor()
    {
        byte[] salt = SecretKeyDerivation.GenerateSalt();
        byte[] key = SecretKeyDerivation.DeriveKey("MyMasterPassword!", salt);

        byte[] plaintext = Encoding.UTF8.GetBytes("my secret credential");
        byte[] encrypted = AesGcmEncryptor.Encrypt(plaintext, key);
        byte[] decrypted = AesGcmEncryptor.Decrypt(encrypted, key);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void DeriveKey_EmptyPassword_ThrowsArgumentException()
    {
        byte[] salt = SecretKeyDerivation.GenerateSalt();
        Assert.Throws<ArgumentException>(() => SecretKeyDerivation.DeriveKey(string.Empty, salt));
    }

    [Fact]
    public void DeriveKey_NullPassword_ThrowsArgumentNullException()
    {
        byte[] salt = SecretKeyDerivation.GenerateSalt();
        Assert.Throws<ArgumentNullException>(() => SecretKeyDerivation.DeriveKey(null!, salt));
    }

    [Fact]
    public void DeriveKey_NullSalt_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => SecretKeyDerivation.DeriveKey("password", null!));
    }
}
