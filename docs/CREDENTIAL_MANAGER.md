# Credential Manager – Security Solution for Legacy Applications

## Problem

Legacy C# and Delphi applications store user credentials and database passwords
in plain text inside `.config` and `.ini` files. This solution replaces that
practice with **AES-256-GCM** authenticated encryption and a central **Credential
Vault** server.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Customer Network                         │
│                                                             │
│  ┌──────────────┐    REST/HTTPS    ┌───────────────────┐   │
│  │  C# / Delphi │ ──────────────▶ │  Credential Vault  │   │
│  │  Application │                  │  (central server)  │   │
│  └──────────────┘                  └───────────────────┘   │
│         │                                    │              │
│  Reads encrypted                    Stores encrypted        │
│  .config / .ini                     secrets on disk         │
│         │                           (AES-256-GCM)           │
│         ▼                                                    │
│  Decrypts at runtime                                         │
│  using master key                                            │
└─────────────────────────────────────────────────────────────┘

Service Department: one service account → one API key → access to all customers
```

### Key components

| Component | Description |
|---|---|
| `CredentialManager` | Core library: AES-256-GCM encryption, .config/.ini processors, key providers |
| `CredentialManager.CLI` (`credmgr`) | CLI tool: encrypt/decrypt files, generate keys |
| `CredentialManager.Server` | Central Credential Vault REST API |
| `samples/delphi/` | Delphi integration unit using Windows CNG (BCrypt) API |

---

## Encryption

- **Algorithm**: AES-256-GCM (AEAD – provides both confidentiality and integrity)
- **Key size**: 256-bit (32 bytes)
- **Nonce**: 96-bit (12 bytes), randomly generated per value
- **Tag**: 128-bit (16 bytes) – detects any tampering
- **Format**: `ENC:<base64(nonce || tag || ciphertext)>`
- **Key derivation**: PBKDF2-HMAC-SHA256 with ≥ 600 000 iterations when deriving
  from a password

---

## Quick Start

### 1. Generate a master key

```bash
# Generate a random key and save to a file
credmgr generate-key --out /etc/myapp/master.key

# Or derive a key from a password (requires a stable salt)
credmgr generate-key --from-password "MyMasterPassword" --out /etc/myapp/master.key
```

**Protect the key file**: on Windows restrict to the service account with NTFS
ACLs; on Linux set `chmod 600`.

### 2. Encrypt a configuration file

```bash
# .config (C# / .NET)
credmgr encrypt C:\MyApp\app.config --key-file C:\Secrets\master.key

# .ini (Delphi)
credmgr encrypt C:\MyApp\myapp.ini --key-file C:\Secrets\master.key
```

Only keys whose names contain credential-related words (password, pwd, secret,
apikey, token, connectionstring…) are encrypted. Other settings are left
untouched.

### 3. Read credentials at runtime (C#)

```csharp
// Program startup (C# / .NET)
using CredentialManager.Client;
using CredentialManager.KeyManagement;

// Option A – key file
var keyProvider = new FileKeyProvider(@"C:\Secrets\master.key");

// Option B – environment variable CREDENTIAL_MASTER_KEY
var keyProvider = new EnvironmentKeyProvider();

// Option C – central Credential Vault server
var keyProvider = new VaultKeyProvider("https://vault.company.local", apiKey);

var reader = new CredentialReader(keyProvider);

// Read from config (IConfiguration integration)
string rawPassword = Configuration["DatabasePassword"];  // still ENC:...
string password = await reader.ReadAsync(rawPassword);
```

### 4. Read credentials at runtime (Delphi)

```delphi
uses CredentialManager;

var
  Reader: TCredentialReader;
  Password: string;
begin
  // Key file approach
  Reader := TCredentialReader.CreateWithKeyFile('C:\Secrets\master.key');
  try
    Password := Reader.ReadFromIni('myapp.ini', 'Database', 'Password');
  finally
    Reader.Free;
  end;
end;
```

### 5. Troubleshooting (service department)

```bash
# Decrypt a single value to see its plaintext
credmgr decrypt-value "ENC:..." --key-file master.key

# Decrypt a whole config file temporarily for inspection
credmgr decrypt C:\Customer\app.config --vault-url https://vault.company.local --vault-api-key <key>
```

---

## Central Credential Vault Server

The vault server is an ASP.NET Core 8 minimal-API application that:

- Stores secrets encrypted on disk (JSON file, AES-256-GCM)
- Authenticates clients via API keys (`Authorization: ApiKey <key>`)
- Provides the master key to authorised applications via `GET /api/key`
- Allows the service department to manage secrets via REST (admin role)

### Configuration (`appsettings.json`)

```json
{
  "Vault": {
    "MasterKeyBase64": "<base64-encoded 32-byte key>",
    "StorePath": "data/secrets.json",
    "ApiKeys": [
      {
        "HashedKey": "<sha256-hex of service-dept key>",
        "Label": "ServiceDepartment",
        "Roles": ["admin", "read"],
        "IsActive": true
      },
      {
        "HashedKey": "<sha256-hex of customer-app key>",
        "Label": "CustomerA-App",
        "Roles": ["read"],
        "IsActive": true
      }
    ]
  }
}
```

Generate the SHA-256 hash of a raw API key:

```bash
echo -n "my-raw-api-key" | sha256sum
```

### API endpoints

| Method | Path | Role | Description |
|--------|------|------|-------------|
| `GET` | `/api/key` | read | Returns the master key (Base64) |
| `GET` | `/api/secrets` | read | Lists all secret names |
| `GET` | `/api/secrets/{name}` | read | Returns a decrypted secret |
| `PUT` | `/api/secrets/{name}` | admin | Creates/updates a secret |
| `DELETE` | `/api/secrets/{name}` | admin | Deletes a secret |

### Running the server

```bash
# Set the master key via environment variable
export CREDENTIAL_MASTER_KEY="<base64 key>"

dotnet run --project src/CredentialManager.Server
```

---

## Service Department Access

A single service-department API key with the `admin` role grants access across
**all** customer installations. No per-customer credentials are required:

1. The vault server runs centrally (or one instance per customer site on the
   secure network).
2. The service department uses the single admin API key with the CLI:

   ```bash
   credmgr decrypt app.config \
     --vault-url https://vault.customerA.company.local \
     --vault-api-key <service-dept-key>
   ```

3. Or reads a specific secret directly:

   ```bash
   curl -H "Authorization: ApiKey <service-dept-key>" \
        https://vault.customerA.company.local/api/secrets/Database/Password
   ```

---

## Key Management Best Practices

| Concern | Recommendation |
|---------|----------------|
| Key storage | Key file protected by OS ACLs (NTFS / chmod 600) or environment variable injected at deploy time |
| Key rotation | Generate a new key with `credmgr generate-key`, re-encrypt all files, update the vault |
| Key backup | Store in an offline, encrypted backup (e.g. encrypted USB in a safe) |
| Master password | Use a strong passphrase (≥ 16 characters); store in a password manager |
| Audit | The vault server logs all reads and writes with the API key label |

---

## Security Considerations

- **AES-256-GCM** provides authenticated encryption: any tampering with the
  ciphertext or tag is detected and throws an exception.
- Each value is encrypted with a **unique random nonce** so identical plaintexts
  produce different ciphertexts (no pattern leakage).
- API keys are stored as **SHA-256 hashes** in the server configuration so the
  raw key is never at rest on the server.
- The `credmgr decrypt` command should only be used by authorised personnel and
  its output should not be persisted.
- The Vault server should be deployed behind HTTPS (TLS 1.2+).

---

## Project Structure

```
Security/
├── src/
│   ├── CredentialManager/                 # Core library
│   │   ├── Encryption/
│   │   │   ├── IEncryptor.cs
│   │   │   └── AesGcmEncryptor.cs         # AES-256-GCM implementation
│   │   ├── KeyManagement/
│   │   │   ├── IKeyProvider.cs
│   │   │   ├── EnvironmentKeyProvider.cs  # Key from env var
│   │   │   ├── FileKeyProvider.cs         # Key from file
│   │   │   └── VaultKeyProvider.cs        # Key from central server
│   │   ├── Configuration/
│   │   │   ├── AppConfigProcessor.cs      # .config file processor
│   │   │   └── IniFileProcessor.cs        # .ini file processor
│   │   └── Client/
│   │       └── CredentialReader.cs        # High-level reader
│   ├── CredentialManager.CLI/             # CLI tool (credmgr)
│   │   └── Program.cs
│   └── CredentialManager.Server/          # Central Credential Vault
│       ├── Auth/
│       │   └── ApiKeyAuthenticationHandler.cs
│       ├── Endpoints/
│       │   └── SecretEndpoints.cs
│       ├── Models/
│       │   ├── ApiKeyRecord.cs
│       │   └── SecretEntry.cs
│       ├── Services/
│       │   ├── ApiKeyAuthService.cs
│       │   ├── ISecretStore.cs
│       │   └── SecretStore.cs
│       └── Program.cs
├── tests/
│   └── CredentialManager.Tests/           # xUnit tests
└── samples/
    └── delphi/
        ├── CredentialManager.pas          # Delphi integration unit
        └── SampleApp.dpr                  # Sample Delphi application
```
