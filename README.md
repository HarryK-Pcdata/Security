# Security – Credential Encryption for Legacy Applications

This repository implements a solution for encrypting credentials stored in `.config`
and `.ini` files used by legacy C# and Delphi applications.

## Overview

Plain-text passwords and connection strings in configuration files are replaced
with **AES-256-GCM** encrypted values. A central **Credential Vault** server
provides a single point of access for the service department without requiring
per-customer credentials.

## Documentation

See [docs/CREDENTIAL_MANAGER.md](docs/CREDENTIAL_MANAGER.md) for full details including:

- Architecture overview
- Quick-start guide (generate key, encrypt file, read at runtime)
- C# and Delphi integration examples
- Central Vault server setup and API reference
- Service department access workflow
- Key management best practices

## Quick example

```bash
# Generate a 256-bit key
credmgr generate-key --out master.key

# Encrypt credentials in a .config or .ini file
credmgr encrypt app.config --key-file master.key
credmgr encrypt myapp.ini  --key-file master.key

# Service department: decrypt for inspection
credmgr decrypt app.config --key-file master.key
```

## Solution structure

| Project | Description |
|---------|-------------|
| `src/CredentialManager` | Core library: AES-256-GCM, .config/.ini processors, key providers |
| `src/CredentialManager.CLI` | `credmgr` command-line tool |
| `src/CredentialManager.Server` | Central Credential Vault REST API |
| `tests/CredentialManager.Tests` | Unit tests |
| `samples/delphi/` | Delphi integration unit |
