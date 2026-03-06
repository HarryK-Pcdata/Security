using System.Xml.Linq;
using CredentialManager.Configuration;
using CredentialManager.Encryption;
using Xunit;

namespace CredentialManager.Tests;

public sealed class AppConfigProcessorTests : IDisposable
{
    private readonly AesGcmEncryptor _encryptor;
    private readonly AppConfigProcessor _processor;
    private readonly string _tempDir;

    public AppConfigProcessorTests()
    {
        _encryptor = new AesGcmEncryptor(AesGcmEncryptor.GenerateKey());
        _processor = new AppConfigProcessor(_encryptor);
        _tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose() => Directory.Delete(_tempDir, recursive: true);

    private string WriteConfig(string xml)
    {
        string path = Path.Combine(_tempDir, "app.config");
        File.WriteAllText(path, xml);
        return path;
    }

    private const string SampleConfig = """
        <?xml version="1.0" encoding="utf-8"?>
        <configuration>
          <appSettings>
            <add key="ApiEndpoint" value="https://api.example.com" />
            <add key="DatabasePassword" value="s3cr3t" />
            <add key="ApiKey" value="my-api-key-value" />
          </appSettings>
          <connectionStrings>
            <add name="MainDb" connectionString="Server=db;Database=app;User=sa;Password=p@ss;" />
          </connectionStrings>
        </configuration>
        """;

    [Fact]
    public void EncryptDocument_EncryptsCredentialKeys()
    {
        var doc = XDocument.Parse(SampleConfig);
        int count = _processor.EncryptDocument(doc);

        Assert.Equal(3, count);  // DatabasePassword, ApiKey, connectionString

        var adds = doc.Descendants("appSettings").Elements("add").ToList();
        string endpoint = (string)adds.First(a => (string?)a.Attribute("key") == "ApiEndpoint").Attribute("value")!;
        string dbPwd = (string)adds.First(a => (string?)a.Attribute("key") == "DatabasePassword").Attribute("value")!;
        string apiKey = (string)adds.First(a => (string?)a.Attribute("key") == "ApiKey").Attribute("value")!;
        string cs = (string)doc.Descendants("connectionStrings").Elements("add").First().Attribute("connectionString")!;

        Assert.Equal("https://api.example.com", endpoint);  // not a credential key
        Assert.StartsWith("ENC:", dbPwd);
        Assert.StartsWith("ENC:", apiKey);
        Assert.StartsWith("ENC:", cs);
    }

    [Fact]
    public void EncryptDocument_DoesNotDoubleEncrypt()
    {
        var doc = XDocument.Parse(SampleConfig);
        _processor.EncryptDocument(doc);
        int secondCount = _processor.EncryptDocument(doc);
        Assert.Equal(0, secondCount);
    }

    [Fact]
    public void RoundTrip_AppSettingsAndConnectionStrings()
    {
        var doc = XDocument.Parse(SampleConfig);
        _processor.EncryptDocument(doc);
        _processor.DecryptDocument(doc);

        var adds = doc.Descendants("appSettings").Elements("add").ToList();
        string dbPwd = (string)adds.First(a => (string?)a.Attribute("key") == "DatabasePassword").Attribute("value")!;
        string cs = (string)doc.Descendants("connectionStrings").Elements("add").First().Attribute("connectionString")!;

        Assert.Equal("s3cr3t", dbPwd);
        Assert.Equal("Server=db;Database=app;User=sa;Password=p@ss;", cs);
    }

    [Fact]
    public void EncryptFile_WritesEncryptedFileAndReturnsCount()
    {
        string path = WriteConfig(SampleConfig);
        int count = _processor.EncryptFile(path);
        Assert.True(count > 0);

        string content = File.ReadAllText(path);
        Assert.Contains("ENC:", content);
    }

    [Fact]
    public void EncryptFile_ThenDecryptFile_RestoresOriginalValues()
    {
        string path = WriteConfig(SampleConfig);
        _processor.EncryptFile(path);
        _processor.DecryptFile(path);

        var doc = XDocument.Load(path);
        var adds = doc.Descendants("appSettings").Elements("add").ToList();
        string dbPwd = (string)adds.First(a => (string?)a.Attribute("key") == "DatabasePassword").Attribute("value")!;
        Assert.Equal("s3cr3t", dbPwd);
    }
}
