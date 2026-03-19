# Security – CredentialVault

Replaces the **`DISTRIB.INI`** file used by a legacy Delphi application with a
single **`distribconnection`** Windows environment variable, keeping all
connection credentials out of the file system and optionally encrypting the
password with AES-256-GCM.

---

## Problem

The Delphi application reads its configuration from `DISTRIB.INI` via
`GlobalReadIni`:

```delphi
procedure GlobalReadIni;
var
  Ini: TXIniFile;
  i: integer;
begin
  Ini := TXIniFile.Create(ExtractFilePath(ParamStr(0)) + '\DISTRIB.INI');
  Ini.Encryption := GlobalEncryption;

  // [Language]
  GlobalLanguage   := Ini.ReadString(IniSectionLanguage, IniKeyLanguage,   'NL');
  GlobalLanguageEx := Ini.ReadString(IniSectionLanguage, IniKeyLanguageEx, 'NLD');

  // [Database]
  for i := 0 to 9 do
    GlobalServers[i] := Ini.ReadString(IniSectionDatabase, IniKeyServer + IntToStr(i), '');
  GlobalUserName      := Ini.ReadString(IniSectionDatabase, IniKeyDatabaseUN,      'DISTRIB');
  GlobalPassword      := Ini.ReadString(IniSectionDatabase, IniKeyDatabasePW,      'masterkey');
  GlobalOracleDLLPath := Ini.ReadString(IniSectionDatabase, IniKeyDatabaseDLL,     'oci.dll');
  GlobalTNSAdminPath  := Ini.ReadString(IniSectionDatabase, IniKeyTNSAdmin,        '');
  GlobalServerName    := Ini.ReadString(IniSectionDatabase, IniKeyServerName,      'XE');
  GlobalHistory       := Ini.ReadString(IniSectionDatabase, IniKeyDatabaseHistory, 'DISTRIB_HIS');

  // [Local]
  GlobalCompany := Ini.ReadInteger(IniSectionLocal, IniKeyCompany,  1);
  GlobalStation := Ini.ReadInteger(IniSectionLocal, IniKeyStation,  1);
  GlobalUserId  := Ini.ReadInteger(IniSectionLocal, IniKeyUserId,   0);

  FreeAndNil(Ini);
  GlobalIniCompany := GlobalCompany;
  GlobalIniStation := GlobalStation;
end;
```

**CredentialVault** migrates all of these values into the `distribconnection`
environment variable so the INI file (and the password it contains) no longer
needs to live on disk.

---

## Repository structure

```
CredentialVault.slnx
src/
  CredentialVault.Core/
    Models/ConnectionParameters.cs       – all GlobalReadIni fields as one object
    Encryption/AesGcmEncryptor.cs        – AES-256-GCM, ENC: prefix
    Providers/IniFileReader.cs           – reads DISTRIB.INI
    Providers/DistribConnectionProvider.cs – reads/writes distribconnection env var
  CredentialVault.ConfigMigrator/
    Program.cs                           – CLI: migrate | set | get | test
tests/
  CredentialVault.Tests/
    CredentialVaultTests.cs              – 20 xUnit tests
```

---

## Build & Test

```bash
dotnet build
dotnet test tests/CredentialVault.Tests/
```

---

## Migration — one-time step

> **Before running:** if `DISTRIB.INI` uses `TXIniFile` encryption
> (`Ini.Encryption := GlobalEncryption`), disable it temporarily and save an
> unencrypted copy, or export the plain values first.  This tool reads
> standard plain-text INI files.

```bash
# Read DISTRIB.INI and write everything to the current user's environment.
# --passphrase encrypts the password with AES-256-GCM.
dotnet run --project src/CredentialVault.ConfigMigrator -- migrate \
  --ini-file  "C:\MyApp\DISTRIB.INI" \
  --scope     user \
  --passphrase MySecret
```

Expected output:

```
Migration complete: DISTRIB.INI → distribconnection [User] (password encrypted with AES-256-GCM)
  [Database]
    ServerName   : XE
    UserName     : DISTRIB
    Password     : *********
    OracleDllPath: oci.dll
    TnsAdmin     :
    History      : DISTRIB_HIS
    DriverId     : Ora
    CharacterSet : UTF8
    Server0      : SRV1
  [Language]
    Language     : NL
    LanguageEx   : NLD
  [Local]
    Company      : 1
    Station      : 1
    UserId       : 0
```

After migration, verify:

```bash
dotnet run --project src/CredentialVault.ConfigMigrator -- get --passphrase MySecret
dotnet run --project src/CredentialVault.ConfigMigrator -- test
```

---

## Reading the variable in Delphi

Replace `GlobalReadIni` with the following:

```delphi
uses
  System.SysUtils;

procedure GlobalReadEnv;
var
  raw, pair, key, val: string;
  parts: TArray<string>;
  i: integer;
begin
  raw := GetEnvironmentVariable('distribconnection');
  if raw = '' then
    raise Exception.Create(
      'distribconnection environment variable is not set. ' +
      'Run CredentialVault.ConfigMigrator migrate first.');

  parts := raw.Split([';']);
  for pair in parts do
  begin
    if pair = '' then Continue;
    if pair.IndexOf('=') <= 0 then Continue;  // skip malformed segments
    key := pair.Substring(0, pair.IndexOf('='));
    val := pair.Substring(pair.IndexOf('=') + 1);

    if SameText(key, 'ServerName')    then GlobalServerName    := val;
    if SameText(key, 'UserName')      then GlobalUserName      := val;
    if SameText(key, 'Password')      then GlobalPassword      := val;
    if SameText(key, 'OracleDllPath') then GlobalOracleDLLPath := val;
    if SameText(key, 'TnsAdmin')      then GlobalTNSAdminPath  := val;
    if SameText(key, 'History')       then GlobalHistory       := val;
    if SameText(key, 'Language')      then GlobalLanguage      := val;
    if SameText(key, 'LanguageEx')    then GlobalLanguageEx    := val;
    if SameText(key, 'Company')       then GlobalCompany       := StrToIntDef(val, 1);
    if SameText(key, 'Station')       then GlobalStation       := StrToIntDef(val, 1);
    if SameText(key, 'UserId')        then GlobalUserId        := StrToIntDef(val, 0);

    for i := 0 to 9 do
      if SameText(key, 'Server' + IntToStr(i)) then
        GlobalServers[i] := val;
  end;

  GlobalIniCompany := GlobalCompany;
  GlobalIniStation := GlobalStation;
end;
```

> **Note on password encryption:** when the migration tool was run with
> `--passphrase`, the `Password` value in the env var is an `ENC:…` token.
> You will need a small .NET helper (or call the ConfigMigrator `get` command)
> to decrypt it before passing it to `SetDBParams`, or run the migration
> without `--passphrase` and rely on OS-level ACLs on the environment variable
> instead.

---

## Environment variable format

The variable contains semicolon-delimited `key=value` pairs (all fields always
present):

```
ServerName=XE;UserName=DISTRIB;Password=ENC:…;OracleDllPath=oci.dll;
TnsAdmin=;History=DISTRIB_HIS;DriverId=Ora;CharacterSet=UTF8;
Server0=SRV1;Server1=;…;Server9=;
Language=NL;LanguageEx=NLD;
Company=1;Station=1;UserId=0
```

---

## Encryption details

When `--passphrase` is supplied the password is stored as:

```
ENC:<Base64( nonce[12] || tag[16] || ciphertext[n] )>
```

using **AES-256-GCM** with a fresh random nonce per write (PBKDF2-SHA256,
100 000 iterations). The same passphrase must be supplied to `get` / `test`
for decryption.

> Store the passphrase in Windows Credential Manager, a secrets manager, or a
> separate environment variable with restricted ACLs — never hard-code it.

---

## CLI reference

| Command | Description |
|---|---|
| `migrate --ini-file <path>` | **One-shot migration** from DISTRIB.INI to env var |
| `set` | Write individual parameters without an INI file |
| `get` | Display current parameters (password masked) |
| `test` | Verify the variable is set and parseable |

All commands accept `--scope machine|user|process` (default: `process`) and
`--passphrase <phrase>` for password encryption/decryption.

