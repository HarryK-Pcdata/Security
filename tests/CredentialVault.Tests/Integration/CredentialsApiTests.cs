using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using CredentialVault.Core.Encryption;
using CredentialVault.Core.Models;
using CredentialVault.Server.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace CredentialVault.Tests.Integration;

/// <summary>
/// Integration tests for the Credentials REST API.
/// Uses WebApplicationFactory to spin up the full ASP.NET Core pipeline in-memory.
/// </summary>
public sealed class CredentialsApiTests : IClassFixture<CredentialsApiTests.VaultWebAppFactory>
{
    private readonly VaultWebAppFactory _factory;
    private readonly HttpClient _appClient;
    private readonly HttpClient _serviceClient;

    public CredentialsApiTests(VaultWebAppFactory factory)
    {
        _factory = factory;
        _appClient = factory.CreateClientWithApiKey("test-app-key");
        _serviceClient = factory.CreateClientWithApiKey("test-service-key");
    }

    // ---------------------------------------------------------------------------
    // Store (PUT /api/credentials)
    // ---------------------------------------------------------------------------

    [Fact]
    public async Task Put_StoreCredential_Returns200()
    {
        var request = new StoreCredentialRequest
        {
            Application = "TestApp",
            Key = "DbPassword",
            PlainTextValue = "Secret@123",
            Description = "Database password"
        };

        var response = await _appClient.PutAsJsonAsync("/api/credentials", request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Put_InvalidRequest_Returns400()
    {
        var request = new { Application = "", Key = "", PlainTextValue = "" };

        var response = await _appClient.PutAsJsonAsync("/api/credentials", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // ---------------------------------------------------------------------------
    // Get (GET /api/credentials/{app}/{key})
    // ---------------------------------------------------------------------------

    [Fact]
    public async Task Get_ExistingCredential_ReturnsDecryptedValue()
    {
        await _appClient.PutAsJsonAsync("/api/credentials", new StoreCredentialRequest
        {
            Application = "GetTestApp",
            Key = "ConnectionString",
            PlainTextValue = "Server=prod;User=sa;Password=Pa$$w0rd"
        });

        var response = await _appClient.GetAsync("/api/credentials/GetTestApp/ConnectionString");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var cred = await response.Content.ReadFromJsonAsync<CredentialResponse>();
        Assert.NotNull(cred);
        Assert.Equal("Server=prod;User=sa;Password=Pa$$w0rd", cred.Value);
    }

    [Fact]
    public async Task Get_NonExistentCredential_Returns404()
    {
        var response = await _appClient.GetAsync("/api/credentials/NoSuchApp/NoSuchKey");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    // ---------------------------------------------------------------------------
    // Delete (DELETE /api/credentials/{app}/{key})
    // ---------------------------------------------------------------------------

    [Fact]
    public async Task Delete_ExistingCredential_Returns204()
    {
        await _appClient.PutAsJsonAsync("/api/credentials", new StoreCredentialRequest
        {
            Application = "DeleteApp",
            Key = "ToDelete",
            PlainTextValue = "willbedeleted"
        });

        var response = await _appClient.DeleteAsync("/api/credentials/DeleteApp/ToDelete");

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var getResponse = await _appClient.GetAsync("/api/credentials/DeleteApp/ToDelete");
        Assert.Equal(HttpStatusCode.NotFound, getResponse.StatusCode);
    }

    [Fact]
    public async Task Delete_NonExistentCredential_Returns404()
    {
        var response = await _appClient.DeleteAsync("/api/credentials/NoApp/NoKey");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    // ---------------------------------------------------------------------------
    // List (GET /api/credentials/{app})
    // ---------------------------------------------------------------------------

    [Fact]
    public async Task ListByApplication_ReturnsEntriesWithoutValues()
    {
        await _serviceClient.PutAsJsonAsync("/api/credentials", new StoreCredentialRequest
        {
            Application = "ListTestApp",
            Key = "Key1",
            PlainTextValue = "Value1"
        });

        var response = await _serviceClient.GetAsync("/api/credentials/ListTestApp");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        Assert.Contains("Key1", json);
        Assert.DoesNotContain("Value1", json); // Values must NOT be in listing
    }

    // ---------------------------------------------------------------------------
    // Authentication
    // ---------------------------------------------------------------------------

    [Fact]
    public async Task Request_WithoutApiKey_Returns401()
    {
        // Create a client via the factory (bound to test server) with no API key header
        using var unauthenticatedClient = _factory.CreateClient();

        var response = await unauthenticatedClient.GetAsync("/api/credentials/App/Key");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Request_WithInvalidApiKey_Returns401()
    {
        using var badKeyClient = _factory.CreateClient();
        badKeyClient.DefaultRequestHeaders.Add("X-Api-Key", "invalid-key-xyz");

        var response = await badKeyClient.GetAsync("/api/credentials/App/Key");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ---------------------------------------------------------------------------
    // Test factory
    // ---------------------------------------------------------------------------

    public sealed class VaultWebAppFactory : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureServices(services =>
            {
                // Replace the VaultStore singleton with a test instance using a known key
                byte[] testKey = new byte[AesGcmEncryptor.KeySize]; // all-zeros key for testing
                services.RemoveAll<VaultStore>();
                services.AddSingleton(new VaultStore(testKey));

                // Replace the ApiKeyRegistry with test keys
                var keys = new List<ApiKeyEntry>
                {
                    new() { Name = "TestApp",     Key = "test-app-key",     Role = "Application" },
                    new() { Name = "ServiceDept", Key = "test-service-key", Role = "ServiceDepartment" }
                };
                services.RemoveAll<ApiKeyRegistry>();
                services.AddSingleton(new ApiKeyRegistry(keys));
            });
        }

        public HttpClient CreateClientWithApiKey(string apiKey)
        {
            var client = CreateClient();
            client.DefaultRequestHeaders.Add("X-Api-Key", apiKey);
            return client;
        }
    }
}
