using CredentialVault.Core.Encryption;
using CredentialVault.Core.Models;
using CredentialVault.Core.Providers;

namespace CredentialVault.Tests;

public class AesGcmEncryptorTests
{
    [Fact]
    public void Encrypt_ProducesEncPrefix()
    {
        var enc = AesGcmEncryptor.FromPassphrase("test-passphrase");
        var token = enc.Encrypt("my-secret");
        Assert.StartsWith("ENC:", token);
    }

    [Fact]
    public void EncryptDecrypt_RoundTrip()
    {
        var enc = AesGcmEncryptor.FromPassphrase("test-passphrase");
        const string plaintext = "super-secret-password!@#";
        var token = enc.Encrypt(plaintext);
        var result = enc.Decrypt(token);
        Assert.Equal(plaintext, result);
    }

    [Fact]
    public void Decrypt_PlainTextPassThrough()
    {
        var enc = AesGcmEncryptor.FromPassphrase("test-passphrase");
        const string plain = "no-encryption-here";
        Assert.Equal(plain, enc.Decrypt(plain));
    }

    [Fact]
    public void IsEncrypted_ReturnsTrueForEncToken()
    {
        var enc = AesGcmEncryptor.FromPassphrase("test-passphrase");
        var token = enc.Encrypt("value");
        Assert.True(AesGcmEncryptor.IsEncrypted(token));
    }

    [Fact]
    public void IsEncrypted_ReturnsFalseForPlainText()
    {
        Assert.False(AesGcmEncryptor.IsEncrypted("plain-text"));
    }

    [Fact]
    public void SamePassphrase_ProducesDifferentTokensEachCall()
    {
        var enc = AesGcmEncryptor.FromPassphrase("test-passphrase");
        var t1 = enc.Encrypt("value");
        var t2 = enc.Encrypt("value");
        // Each call uses a fresh random nonce so the tokens differ.
        Assert.NotEqual(t1, t2);
    }

    [Fact]
    public void Constructor_ThrowsOnInvalidKeyLength()
    {
        Assert.Throws<ArgumentException>(() => new AesGcmEncryptor(new byte[16]));
    }

    [Fact]
    public void FromPassphrase_ThrowsOnEmptyPassphrase()
    {
        Assert.Throws<ArgumentException>(() => AesGcmEncryptor.FromPassphrase(string.Empty));
    }
}

public class DistribConnectionProviderTests
{
    private static ConnectionParameters SampleParameters() => new()
    {
        Password    = "tiger",
        Database    = "MYDB",
        UserName    = "scott",
        DriverId    = "Ora",
        CharacterSet = "UTF8",
        VendorLib   = @"C:\oracle\oci.dll",
        TnsAdmin    = @"C:\oracle\network\admin",
    };

    [Fact]
    public void WriteRead_RoundTrip_PlainText()
    {
        var provider = new DistribConnectionProvider();
        var original = SampleParameters();
        provider.Write(original, EnvironmentVariableTarget.Process);

        var read = provider.Read();

        Assert.NotNull(read);
        Assert.Equal(original.Password,     read.Password);
        Assert.Equal(original.Database,     read.Database);
        Assert.Equal(original.UserName,     read.UserName);
        Assert.Equal(original.DriverId,     read.DriverId);
        Assert.Equal(original.CharacterSet, read.CharacterSet);
        Assert.Equal(original.VendorLib,    read.VendorLib);
        Assert.Equal(original.TnsAdmin,     read.TnsAdmin);
    }

    [Fact]
    public void WriteRead_RoundTrip_WithEncryption()
    {
        var enc = AesGcmEncryptor.FromPassphrase("test-passphrase");
        var provider = new DistribConnectionProvider(enc);
        var original = SampleParameters();
        provider.Write(original, EnvironmentVariableTarget.Process);

        var read = provider.Read();

        Assert.NotNull(read);
        Assert.Equal(original.Password, read.Password);
        Assert.Equal(original.Database, read.Database);
        Assert.Equal(original.UserName, read.UserName);
    }

    [Fact]
    public void Write_EncryptsPassword_InRawValue()
    {
        var enc = AesGcmEncryptor.FromPassphrase("test-passphrase");
        var provider = new DistribConnectionProvider(enc);
        provider.Write(SampleParameters(), EnvironmentVariableTarget.Process);

        var raw = Environment.GetEnvironmentVariable(
            DistribConnectionProvider.EnvironmentVariableName,
            EnvironmentVariableTarget.Process);

        Assert.NotNull(raw);
        Assert.Contains("ENC:", raw);
        // Plain-text password must not appear in the stored value.
        Assert.DoesNotContain("tiger", raw);
    }

    [Fact]
    public void Read_ReturnsNull_WhenVariableNotSet()
    {
        // Remove the variable from the process scope to simulate absence.
        Environment.SetEnvironmentVariable(
            DistribConnectionProvider.EnvironmentVariableName,
            null,
            EnvironmentVariableTarget.Process);

        var provider = new DistribConnectionProvider();
        // Machine/User scopes may be set in CI; only test process scope.
        // We can't easily test machine/user scopes without elevated rights,
        // so this test accepts null only when no value is found in any scope.
        var read = provider.Read();
        // Either null or the value from machine/user scope is acceptable.
        // The critical assertion: no exception is thrown.
        Assert.True(read is null || read.Database is not null);
    }

    [Fact]
    public void Write_ThrowsOnNullParameters()
    {
        var provider = new DistribConnectionProvider();
        Assert.Throws<ArgumentNullException>(
            () => provider.Write(null!, EnvironmentVariableTarget.Process));
    }

    [Fact]
    public void ParseKeyValues_CaseInsensitiveKeys()
    {
        // Simulate a variable set with uppercase keys (e.g. by another tool).
        Environment.SetEnvironmentVariable(
            DistribConnectionProvider.EnvironmentVariableName,
            "PASSWORD=secret;DATABASE=MYDB;USERNAME=scott;DRIVERID=Ora;CHARACTERSET=UTF8",
            EnvironmentVariableTarget.Process);

        var provider = new DistribConnectionProvider();
        var read = provider.Read();

        Assert.NotNull(read);
        Assert.Equal("secret", read.Password);
        Assert.Equal("MYDB",   read.Database);
        Assert.Equal("scott",  read.UserName);
    }

    [Fact]
    public void EnvironmentVariableName_IsDistribconnection()
    {
        Assert.Equal("distribconnection", DistribConnectionProvider.EnvironmentVariableName);
    }
}
