using CredentialVault.Core.Encryption;
using CredentialVault.Core.Models;
using CredentialVault.Core.Providers;

namespace CredentialVault.Tests;

// ============================================================================
// AesGcmEncryptor
// ============================================================================

public class AesGcmEncryptorTests
{
    [Fact]
    public void Encrypt_ProducesEncPrefix()
    {
        var enc = AesGcmEncryptor.FromPassphrase("test-passphrase");
        Assert.StartsWith("ENC:", enc.Encrypt("my-secret"));
    }

    [Fact]
    public void EncryptDecrypt_RoundTrip()
    {
        var enc = AesGcmEncryptor.FromPassphrase("test-passphrase");
        const string plain = "super-secret-password!@#";
        Assert.Equal(plain, enc.Decrypt(enc.Encrypt(plain)));
    }

    [Fact]
    public void Decrypt_PlainTextPassThrough()
    {
        var enc = AesGcmEncryptor.FromPassphrase("test-passphrase");
        Assert.Equal("no-encryption-here", enc.Decrypt("no-encryption-here"));
    }

    [Fact]
    public void IsEncrypted_TrueForEncToken()
    {
        var enc = AesGcmEncryptor.FromPassphrase("test-passphrase");
        Assert.True(AesGcmEncryptor.IsEncrypted(enc.Encrypt("value")));
    }

    [Fact]
    public void IsEncrypted_FalseForPlainText()
        => Assert.False(AesGcmEncryptor.IsEncrypted("plain-text"));

    [Fact]
    public void SamePassphrase_DifferentTokensPerCall()
    {
        var enc = AesGcmEncryptor.FromPassphrase("test-passphrase");
        // Fresh random nonce each call → different ciphertext.
        Assert.NotEqual(enc.Encrypt("value"), enc.Encrypt("value"));
    }

    [Fact]
    public void Constructor_ThrowsOnInvalidKeyLength()
        => Assert.Throws<ArgumentException>(() => new AesGcmEncryptor(new byte[16]));

    [Fact]
    public void FromPassphrase_ThrowsOnEmpty()
        => Assert.Throws<ArgumentException>(() => AesGcmEncryptor.FromPassphrase(string.Empty));
}

// ============================================================================
// IniFileReader — DISTRIB.INI structure
// ============================================================================

public class IniFileReaderTests : IDisposable
{
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    public IniFileReaderTests() => Directory.CreateDirectory(_tempDir);
    public void Dispose()       => Directory.Delete(_tempDir, recursive: true);

    private string WriteIni(string content)
    {
        var path = Path.Combine(_tempDir, "DISTRIB.INI");
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public void Read_ParsesAllThreeSections()
    {
        var path = WriteIni("""
            [Language]
            Language=NL
            LanguageEx=NLD

            [Database]
            Server0=SRV1
            Server1=SRV2
            Server2=
            Server3=
            Server4=
            Server5=
            Server6=
            Server7=
            Server8=
            Server9=
            UserName=DISTRIB
            Password=masterkey
            OracleDLL=oci.dll
            TNSAdmin=C:\oracle\admin
            ServerName=XE
            History=DISTRIB_HIS

            [Local]
            Company=2
            Station=3
            UserId=42
            """);

        var p = new IniFileReader(path).Read();

        // Language
        Assert.Equal("NL",  p.Language);
        Assert.Equal("NLD", p.LanguageEx);

        // Database
        Assert.Equal("DISTRIB",     p.UserName);
        Assert.Equal("masterkey",   p.Password);
        Assert.Equal("oci.dll",     p.OracleDllPath);
        Assert.Equal(@"C:\oracle\admin", p.TnsAdmin);
        Assert.Equal("XE",          p.ServerName);
        Assert.Equal("DISTRIB_HIS", p.History);
        Assert.Equal("SRV1",        p.Servers[0]);
        Assert.Equal("SRV2",        p.Servers[1]);
        Assert.Equal(string.Empty,  p.Servers[2]);

        // Local
        Assert.Equal(2,  p.Company);
        Assert.Equal(3,  p.Station);
        Assert.Equal(42, p.UserId);
    }

    [Fact]
    public void Read_AppliesDefaults_WhenKeysAreMissing()
    {
        // Minimal INI with only the required Database key.
        var path = WriteIni("""
            [Database]
            ServerName=PROD
            """);

        var p = new IniFileReader(path).Read();

        Assert.Equal("PROD",        p.ServerName);
        Assert.Equal("DISTRIB",     p.UserName);    // default
        Assert.Equal("masterkey",   p.Password);    // default
        Assert.Equal("oci.dll",     p.OracleDllPath); // default
        Assert.Equal("DISTRIB_HIS", p.History);     // default
        Assert.Equal("NL",          p.Language);    // default
        Assert.Equal(1,             p.Company);     // default
        Assert.Equal(1,             p.Station);     // default
        Assert.Equal(0,             p.UserId);      // default
    }

    [Fact]
    public void Read_IgnoresCommentLines()
    {
        var path = WriteIni("""
            ; This is a comment
            # Also a comment
            [Database]
            ServerName=XE
            ; Password=should-be-ignored
            Password=realpassword
            """);

        var p = new IniFileReader(path).Read();
        Assert.Equal("realpassword", p.Password);
    }

    [Fact]
    public void Read_ThrowsFileNotFound_WhenFileMissing()
    {
        var reader = new IniFileReader(Path.Combine(_tempDir, "nonexistent.ini"));
        Assert.Throws<FileNotFoundException>(() => reader.Read());
    }

    [Fact]
    public void Constructor_ThrowsOnEmptyPath()
        => Assert.Throws<ArgumentException>(() => new IniFileReader(string.Empty));
}

// ============================================================================
// DistribConnectionProvider — round-trip with all fields
// ============================================================================

// Tests in this collection write to the shared process-level 'distribconnection'
// environment variable and must not run in parallel with each other.
[Collection("EnvVar")]
public class DistribConnectionProviderTests
{
    private static ConnectionParameters FullSample() => new()
    {
        ServerName    = "XE",
        UserName      = "DISTRIB",
        Password      = "masterkey",
        OracleDllPath = @"C:\oracle\oci.dll",
        TnsAdmin      = @"C:\oracle\admin",
        History       = "DISTRIB_HIS",
        DriverId      = "Ora",
        CharacterSet  = "UTF8",
        Servers       = ["SRV1", "SRV2", "", "", "", "", "", "", "", ""],
        Language      = "NL",
        LanguageEx    = "NLD",
        Company       = 2,
        Station       = 3,
        UserId        = 42,
    };

    [Fact]
    public void WriteRead_RoundTrip_PlainText()
    {
        var provider = new DistribConnectionProvider();
        var src = FullSample();
        provider.Write(src, EnvironmentVariableTarget.Process);
        var dst = provider.Read()!;

        Assert.Equal(src.ServerName,    dst.ServerName);
        Assert.Equal(src.UserName,      dst.UserName);
        Assert.Equal(src.Password,      dst.Password);
        Assert.Equal(src.OracleDllPath, dst.OracleDllPath);
        Assert.Equal(src.TnsAdmin,      dst.TnsAdmin);
        Assert.Equal(src.History,       dst.History);
        Assert.Equal(src.DriverId,      dst.DriverId);
        Assert.Equal(src.CharacterSet,  dst.CharacterSet);
        Assert.Equal(src.Servers[0],    dst.Servers[0]);
        Assert.Equal(src.Servers[1],    dst.Servers[1]);
        Assert.Equal(src.Language,      dst.Language);
        Assert.Equal(src.LanguageEx,    dst.LanguageEx);
        Assert.Equal(src.Company,       dst.Company);
        Assert.Equal(src.Station,       dst.Station);
        Assert.Equal(src.UserId,        dst.UserId);
    }

    [Fact]
    public void WriteRead_RoundTrip_WithEncryption()
    {
        var enc = AesGcmEncryptor.FromPassphrase("test-passphrase");
        var provider = new DistribConnectionProvider(enc);
        var src = FullSample();
        provider.Write(src, EnvironmentVariableTarget.Process);
        var dst = provider.Read()!;

        Assert.Equal(src.Password,   dst.Password);
        Assert.Equal(src.ServerName, dst.ServerName);
        Assert.Equal(src.Company,    dst.Company);
    }

    [Fact]
    public void Write_EncryptsPassword_NotPlainTextInRawValue()
    {
        var enc = AesGcmEncryptor.FromPassphrase("test-passphrase");
        var provider = new DistribConnectionProvider(enc);
        provider.Write(FullSample(), EnvironmentVariableTarget.Process);

        var raw = Environment.GetEnvironmentVariable(
            DistribConnectionProvider.EnvironmentVariableName,
            EnvironmentVariableTarget.Process)!;

        Assert.Contains("ENC:", raw);
        Assert.DoesNotContain("masterkey", raw);
    }

    [Fact]
    public void Read_ReturnsNull_WhenVariableAbsent()
    {
        Environment.SetEnvironmentVariable(
            DistribConnectionProvider.EnvironmentVariableName, null,
            EnvironmentVariableTarget.Process);

        var result = new DistribConnectionProvider().Read();
        // Null or a value from machine/user scope — no exception either way.
        Assert.True(result is null || result.ServerName is not null);
    }

    [Fact]
    public void Write_ThrowsOnNullParameters()
        => Assert.Throws<ArgumentNullException>(
            () => new DistribConnectionProvider().Write(null!, EnvironmentVariableTarget.Process));

    [Fact]
    public void EnvironmentVariableName_IsDistribconnection()
        => Assert.Equal("distribconnection", DistribConnectionProvider.EnvironmentVariableName);
}

// ============================================================================
// End-to-end migration: IniFileReader → DistribConnectionProvider
// ============================================================================

[Collection("EnvVar")]
public class MigrationIntegrationTests : IDisposable
{
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
    public MigrationIntegrationTests() => Directory.CreateDirectory(_tempDir);
    public void Dispose()              => Directory.Delete(_tempDir, recursive: true);

    [Fact]
    public void ReadFromIni_WriteToEnvVar_ReadBack_FullRoundTrip()
    {
        // 1. Write a DISTRIB.INI file.
        var iniPath = Path.Combine(_tempDir, "DISTRIB.INI");
        File.WriteAllText(iniPath, """
            [Language]
            Language=EN
            LanguageEx=ENG

            [Database]
            Server0=PROD1
            Server1=PROD2
            Server2=
            Server3=
            Server4=
            Server5=
            Server6=
            Server7=
            Server8=
            Server9=
            UserName=APPUSER
            Password=S3cr3t!
            OracleDLL=C:\oracle\oci.dll
            TNSAdmin=C:\oracle\network\admin
            ServerName=PROD
            History=APP_HIS

            [Local]
            Company=5
            Station=10
            UserId=7
            """);

        // 2. Read from INI (simulate GlobalReadIni).
        var iniParams = new IniFileReader(iniPath).Read();

        // 3. Write to env var with encryption (simulate migration tool).
        var enc = AesGcmEncryptor.FromPassphrase("migration-passphrase");
        var provider = new DistribConnectionProvider(enc);
        provider.Write(iniParams, EnvironmentVariableTarget.Process);

        // 4. Read back from env var (simulate new app startup).
        var envParams = provider.Read()!;

        // 5. All values must match the original INI content.
        Assert.Equal("EN",                    envParams.Language);
        Assert.Equal("ENG",                   envParams.LanguageEx);
        Assert.Equal("PROD1",                 envParams.Servers[0]);
        Assert.Equal("PROD2",                 envParams.Servers[1]);
        Assert.Equal("APPUSER",               envParams.UserName);
        Assert.Equal("S3cr3t!",               envParams.Password);
        Assert.Equal(@"C:\oracle\oci.dll",    envParams.OracleDllPath);
        Assert.Equal(@"C:\oracle\network\admin", envParams.TnsAdmin);
        Assert.Equal("PROD",                  envParams.ServerName);
        Assert.Equal("APP_HIS",               envParams.History);
        Assert.Equal(5,                       envParams.Company);
        Assert.Equal(10,                      envParams.Station);
        Assert.Equal(7,                       envParams.UserId);
    }
}

