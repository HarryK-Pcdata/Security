# Security – CredentialVault

Securely manage Oracle database connection parameters for legacy Delphi applications using the **`distribconnection`** Windows environment variable.

## Problem

A Delphi application calls `SetDBParams` to populate a `TFDConnection` with Oracle credentials:

```delphi
procedure SetDBParams(ADatabase: TFDConnection; driver: TFDPhysOracleDriverLink);
begin
  ADatabase.Params.Clear;
  ADatabase.Params.Add('PASSWORD='     + GlobalPassword);
  ADatabase.Params.Add('Database='     + GlobalServerName);
  ADatabase.Params.Add('USER_NAME='    + GlobalUserName);
  ADatabase.Params.Add('DriverID=9133');
  ADatabase.Params.Add('CharacterSet=UTF8');
  driver.VendorLib  := GlobalOracleDLLPath;
  driver.TNSAdmin   := GlobalTNSAdminPath;
end;
```

Instead of hard-coding these values, **CredentialVault** stores them in the `distribconnection` environment variable (optionally AES-256-GCM encrypted) so they can be managed centrally and read securely at runtime.

---

## Repository structure

```
CredentialVault.slnx
src/
  CredentialVault.Core/            – shared library (models, encryption, provider)
    Models/ConnectionParameters.cs
    Encryption/AesGcmEncryptor.cs
    Providers/DistribConnectionProvider.cs
  CredentialVault.ConfigMigrator/  – CLI tool for managing the env var
    Program.cs
tests/
  CredentialVault.Tests/           – xUnit tests
    CredentialVaultTests.cs
```

---

## Build & Test

```bash
dotnet build
dotnet test tests/CredentialVault.Tests/
```

---

## CLI usage

```
dotnet run --project src/CredentialVault.ConfigMigrator -- <command> [options]
```

### `set` – write connection parameters

| Option | Description | Default |
|---|---|---|
| `--database` | Oracle TNS alias or server name | *(required)* |
| `--username` | Database user name | |
| `--password` | Database password | |
| `--driver-id` | FireDAC driver ID | `Ora` |
| `--charset` | Oracle character set | `UTF8` |
| `--vendor-lib` | Full path to Oracle client DLL | |
| `--tns-admin` | Directory containing `tnsnames.ora` | |
| `--scope` | `machine` \| `user` \| `process` | `process` |
| `--passphrase` | Encrypt the password with AES-256-GCM | *(plain text if omitted)* |

```bash
# Write parameters to the current user's environment (persists across restarts)
dotnet run --project src/CredentialVault.ConfigMigrator -- set \
  --database  MYDB \
  --username  scott \
  --password  tiger \
  --vendor-lib  "C:\oracle\oci.dll" \
  --tns-admin   "C:\oracle\network\admin" \
  --scope     user \
  --passphrase  MySecret
```

### `get` – display current parameters

```bash
dotnet run --project src/CredentialVault.ConfigMigrator -- get --passphrase MySecret
```

### `test` – verify the variable can be parsed

```bash
dotnet run --project src/CredentialVault.ConfigMigrator -- test --passphrase MySecret
```

---

## Reading the variable in Delphi

In your Delphi application, replace the global variables with a call to
`GetEnvironmentVariable('distribconnection')` and parse the semicolon-delimited
`key=value` pairs:

```delphi
uses
  System.SysUtils;

procedure LoadFromDistribconnection;
var
  raw, pair, key, val: string;
  parts: TArray<string>;
begin
  raw := GetEnvironmentVariable('distribconnection');
  if raw = '' then
    raise Exception.Create('distribconnection environment variable is not set');

  parts := raw.Split([';']);
  for pair in parts do
  begin
    if pair = '' then Continue;
    key := pair.Substring(0, pair.IndexOf('='));
    val := pair.Substring(pair.IndexOf('=') + 1);
    if SameText(key, 'Password')     then GlobalPassword       := val;
    if SameText(key, 'Database')     then GlobalServerName     := val;
    if SameText(key, 'UserName')     then GlobalUserName       := val;
    if SameText(key, 'VendorLib')    then GlobalOracleDLLPath  := val;
    if SameText(key, 'TnsAdmin')     then GlobalTNSAdminPath   := val;
  end;
end;
```

---

## Encryption

When `--passphrase` is supplied, the password field is stored as:

```
ENC:<Base64( nonce[12] || tag[16] || ciphertext[n] )>
```

using AES-256-GCM with a fresh random nonce per write.  The same passphrase
must be supplied to `get` / `test` for decryption.

> **Tip:** store the passphrase itself in a separate secure location (e.g. Windows
> Credential Manager, a secrets manager, or a second environment variable with
> restricted ACLs) rather than embedding it in your application.
