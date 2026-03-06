using CredentialManager.Configuration;
using CredentialManager.Encryption;
using Xunit;

namespace CredentialManager.Tests;

public sealed class IniFileProcessorTests : IDisposable
{
    private readonly AesGcmEncryptor _encryptor;
    private readonly IniFileProcessor _processor;
    private readonly string _tempDir;

    public IniFileProcessorTests()
    {
        _encryptor = new AesGcmEncryptor(AesGcmEncryptor.GenerateKey());
        _processor = new IniFileProcessor(_encryptor);
        _tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose() => Directory.Delete(_tempDir, recursive: true);

    private static readonly string[] SampleIni =
    [
        "[Database]",
        "Server=db.company.local",
        "Port=5432",
        "Username=app_user",
        "Password=s3cr3t",
        "",
        "[API]",
        "; comment line",
        "Endpoint=https://api.example.com",
        "ApiKey=my-api-key"
    ];

    [Fact]
    public void ProcessLines_Encrypt_EncryptsCredentialKeys()
    {
        (string[] result, int count) = _processor.ProcessLines(SampleIni, encrypt: true);

        Assert.Equal(2, count);  // Password, ApiKey
        Assert.Equal("Server=db.company.local", result[1]);  // untouched
        Assert.StartsWith("Password=ENC:", result[4]);
        Assert.StartsWith("ApiKey=ENC:", result[9]);
    }

    [Fact]
    public void ProcessLines_Encrypt_DoesNotDoubleEncrypt()
    {
        (string[] first, _) = _processor.ProcessLines(SampleIni, encrypt: true);
        (_, int secondCount) = _processor.ProcessLines(first, encrypt: true);
        Assert.Equal(0, secondCount);
    }

    [Fact]
    public void RoundTrip_EncryptThenDecrypt()
    {
        (string[] encrypted, _) = _processor.ProcessLines(SampleIni, encrypt: true);
        (string[] decrypted, _) = _processor.ProcessLines(encrypted, encrypt: false);

        Assert.Equal("Password=s3cr3t", decrypted[4]);
        Assert.Equal("ApiKey=my-api-key", decrypted[9]);
    }

    [Fact]
    public void ProcessLines_PreservesComments()
    {
        (string[] result, _) = _processor.ProcessLines(SampleIni, encrypt: true);
        Assert.Equal("; comment line", result[7]);
    }

    [Fact]
    public void ProcessLines_PreservesSectionHeaders()
    {
        (string[] result, _) = _processor.ProcessLines(SampleIni, encrypt: true);
        Assert.Equal("[Database]", result[0]);
        Assert.Equal("[API]", result[6]);
    }

    [Fact]
    public void EncryptFile_WritesEncryptedFile()
    {
        string path = Path.Combine(_tempDir, "app.ini");
        File.WriteAllLines(path, SampleIni);

        int count = _processor.EncryptFile(path);

        Assert.True(count > 0);
        string content = File.ReadAllText(path);
        Assert.Contains("ENC:", content);
    }

    [Fact]
    public void EncryptFile_ThenDecryptFile_RestoresOriginalValues()
    {
        string path = Path.Combine(_tempDir, "app.ini");
        File.WriteAllLines(path, SampleIni);

        _processor.EncryptFile(path);
        _processor.DecryptFile(path);

        string[] lines = File.ReadAllLines(path);
        Assert.Equal("Password=s3cr3t", lines[4]);
    }
}
