using CredentialManager.Encryption;
using CredentialManager.KeyManagement;
using CredentialManager.Server.Auth;
using CredentialManager.Server.Endpoints;
using CredentialManager.Server.Models;
using CredentialManager.Server.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

// -------------------------------------------------------------------------
// Master key – loaded from configuration (environment variable or key file)
// -------------------------------------------------------------------------
string? masterKeyB64 = builder.Configuration["Vault:MasterKeyBase64"]
    ?? Environment.GetEnvironmentVariable(EnvironmentKeyProvider.EnvironmentVariableName);

if (string.IsNullOrWhiteSpace(masterKeyB64))
    throw new InvalidOperationException(
        "Vault master key is not configured. " +
        $"Set 'Vault:MasterKeyBase64' in appsettings.json or the " +
        $"'{EnvironmentKeyProvider.EnvironmentVariableName}' environment variable.");

byte[] masterKey = Convert.FromBase64String(masterKeyB64);
IEncryptor encryptor = new AesGcmEncryptor(masterKey);
builder.Services.AddSingleton(encryptor);

// -------------------------------------------------------------------------
// API Key authentication
// -------------------------------------------------------------------------
var apiKeyRecords = builder.Configuration
    .GetSection("Vault:ApiKeys")
    .Get<List<ApiKeyRecord>>() ?? [];

builder.Services.AddSingleton(new ApiKeyAuthService(apiKeyRecords));

builder.Services
    .AddAuthentication(ApiKeyAuthenticationHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(
        ApiKeyAuthenticationHandler.SchemeName, _ => { });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ApiKeyPolicy", policy =>
        policy.RequireAuthenticatedUser());

    options.AddPolicy("AdminPolicy", policy =>
        policy.RequireAuthenticatedUser()
              .RequireRole("admin"));
});

// -------------------------------------------------------------------------
// Secret store
// -------------------------------------------------------------------------
string storePath = builder.Configuration["Vault:StorePath"]
    ?? Path.Combine(AppContext.BaseDirectory, "data", "secrets.json");

builder.Services.AddMemoryCache();
builder.Services.AddSingleton<ISecretStore>(sp =>
    new SecretStore(encryptor, sp.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>(), storePath));

// -------------------------------------------------------------------------
// OpenAPI / Swagger
// -------------------------------------------------------------------------
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "Credential Vault API", Version = "v1" });
    c.AddSecurityDefinition("ApiKey", new()
    {
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Name = "Authorization",
        Description = "Enter: ApiKey {your-api-key}"
    });
    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new() { Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme, Id = "ApiKey" }
            },
            Array.Empty<string>()
        }
    });
});

// -------------------------------------------------------------------------
// Build pipeline
// -------------------------------------------------------------------------
var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapSecretEndpoints();
app.MapKeyEndpoint();

app.Run();
