using System.Text;
using CredentialVault.Core.Encryption;
using CredentialVault.Server.Services;
using Xunit;

namespace CredentialVault.Tests.Server;

public sealed class VaultStoreTests
{
    private static VaultStore CreateStore() =>
        new VaultStore(AesGcmEncryptor.GenerateKey());

    [Fact]
    public void Store_AndRetrieve_ReturnsOriginalValue()
    {
        var store = CreateStore();
        store.Store("MyApp", "DatabasePassword", "SuperSecret123!");

        string? retrieved = store.Retrieve("MyApp", "DatabasePassword");

        Assert.Equal("SuperSecret123!", retrieved);
    }

    [Fact]
    public void Retrieve_NonExistentKey_ReturnsNull()
    {
        var store = CreateStore();

        string? retrieved = store.Retrieve("MyApp", "NonExistent");

        Assert.Null(retrieved);
    }

    [Fact]
    public void Store_OverwritesExistingEntry()
    {
        var store = CreateStore();
        store.Store("MyApp", "Password", "OldPassword");
        store.Store("MyApp", "Password", "NewPassword");

        string? retrieved = store.Retrieve("MyApp", "Password");

        Assert.Equal("NewPassword", retrieved);
    }

    [Fact]
    public void Delete_RemovesEntry()
    {
        var store = CreateStore();
        store.Store("MyApp", "Key1", "Value1");

        bool deleted = store.Delete("MyApp", "Key1");

        Assert.True(deleted);
        Assert.Null(store.Retrieve("MyApp", "Key1"));
    }

    [Fact]
    public void Delete_NonExistentEntry_ReturnsFalse()
    {
        var store = CreateStore();

        bool deleted = store.Delete("MyApp", "NonExistent");

        Assert.False(deleted);
    }

    [Fact]
    public void ListByApplication_ReturnsOnlyMatchingEntries()
    {
        var store = CreateStore();
        store.Store("App1", "Key1", "Value1");
        store.Store("App1", "Key2", "Value2");
        store.Store("App2", "Key3", "Value3");

        var entries = store.ListByApplication("App1");

        Assert.Equal(2, entries.Count);
        Assert.All(entries, e => Assert.Equal("App1", e.Application));
    }

    [Fact]
    public void ListAll_ReturnsAllEntries()
    {
        var store = CreateStore();
        store.Store("App1", "Key1", "V1");
        store.Store("App2", "Key2", "V2");
        store.Store("App3", "Key3", "V3");

        var all = store.ListAll();

        Assert.Equal(3, all.Count);
    }

    [Fact]
    public void StoredEntry_EncryptedValueIsNotPlaintext()
    {
        var store = CreateStore();
        store.Store("MyApp", "Password", "SuperSecret");

        var entries = store.ListAll();
        Assert.Single(entries);

        // The stored EncryptedValue should NOT contain the plaintext
        Assert.DoesNotContain("SuperSecret", entries[0].EncryptedValue);
    }

    [Fact]
    public void Store_LookupIsCaseInsensitive()
    {
        var store = CreateStore();
        store.Store("MyApp", "DatabasePassword", "Secret");

        string? retrieved = store.Retrieve("MYAPP", "databasepassword");

        Assert.Equal("Secret", retrieved);
    }

    [Fact]
    public void Store_WithDescription_PersistsDescription()
    {
        var store = CreateStore();
        store.Store("MyApp", "ApiKey", "key123", description: "Production API key");

        var entries = store.ListByApplication("MyApp");
        Assert.Single(entries);
        Assert.Equal("Production API key", entries[0].Description);
    }
}
