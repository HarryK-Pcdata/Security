using CredentialManager.Encryption;
using CredentialManager.KeyManagement;
using Xunit;

namespace CredentialManager.Tests;

public sealed class EnvironmentKeyProviderTests
{
    [Fact]
    public async Task GetKeyAsync_ReturnsKeyFromEnvironmentVariable()
    {
        byte[] key = AesGcmEncryptor.GenerateKey();
        string varName = "TEST_CM_KEY_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(varName, Convert.ToBase64String(key));

        try
        {
            var provider = new EnvironmentKeyProvider(varName);
            byte[] result = await provider.GetKeyAsync();
            Assert.Equal(key, result);
        }
        finally
        {
            Environment.SetEnvironmentVariable(varName, null);
        }
    }

    [Fact]
    public async Task GetKeyAsync_ThrowsWhenVariableNotSet()
    {
        string varName = "TEST_CM_MISSING_" + Guid.NewGuid().ToString("N");
        var provider = new EnvironmentKeyProvider(varName);
        await Assert.ThrowsAsync<InvalidOperationException>(() => provider.GetKeyAsync());
    }

    [Fact]
    public async Task GetKeyAsync_ThrowsForInvalidBase64()
    {
        string varName = "TEST_CM_BAD_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(varName, "!!!not-base64!!!");
        try
        {
            var provider = new EnvironmentKeyProvider(varName);
            await Assert.ThrowsAsync<InvalidOperationException>(() => provider.GetKeyAsync());
        }
        finally
        {
            Environment.SetEnvironmentVariable(varName, null);
        }
    }

    [Fact]
    public async Task GetKeyAsync_ThrowsForWrongKeySize()
    {
        string varName = "TEST_CM_SHORT_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(varName, Convert.ToBase64String(new byte[16]));
        try
        {
            var provider = new EnvironmentKeyProvider(varName);
            await Assert.ThrowsAsync<InvalidOperationException>(() => provider.GetKeyAsync());
        }
        finally
        {
            Environment.SetEnvironmentVariable(varName, null);
        }
    }
}

public sealed class FileKeyProviderTests : IDisposable
{
    private readonly string _tempDir;

    public FileKeyProviderTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose() => Directory.Delete(_tempDir, recursive: true);

    [Fact]
    public async Task GetKeyAsync_ReturnsKeyFromFile()
    {
        byte[] key = AesGcmEncryptor.GenerateKey();
        string path = Path.Combine(_tempDir, "master.key");
        await File.WriteAllTextAsync(path, Convert.ToBase64String(key));

        var provider = new FileKeyProvider(path);
        byte[] result = await provider.GetKeyAsync();
        Assert.Equal(key, result);
    }

    [Fact]
    public async Task GetKeyAsync_ThrowsWhenFileNotFound()
    {
        var provider = new FileKeyProvider(Path.Combine(_tempDir, "missing.key"));
        await Assert.ThrowsAsync<FileNotFoundException>(() => provider.GetKeyAsync());
    }
}
