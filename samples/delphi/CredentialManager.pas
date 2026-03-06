unit CredentialManager;

{
  CredentialManager.pas - Delphi integration unit for reading AES-256-GCM
  encrypted credentials from .ini files protected by the CredentialManager
  system.

  Usage:
    1. Encrypt your .ini file with the credmgr CLI:
         credmgr encrypt myapp.ini --key-file C:\Secrets\master.key
       or using the central vault:
         credmgr encrypt myapp.ini --vault-url https://vault.company.local --vault-api-key <key>

    2. In your Delphi application, use TCredentialReader to decrypt at runtime:

         var
           Reader: TCredentialReader;
           Password: string;
         begin
           Reader := TCredentialReader.CreateWithKeyFile('C:\Secrets\master.key');
           try
             Password := Reader.ReadFromIni('myapp.ini', 'Database', 'Password');
           finally
             Reader.Free;
           end;
         end;

  Requirements:
    - Delphi 10.2 Tokyo or later (uses TNetHTTPClient for vault access)
    - DCPcrypt2 or OpenSSL via the IdSSLOpenSSL component (for AES-GCM)

  NOTE: The pure-Delphi AES-GCM implementation below uses the Windows CNG API
  (BCrypt) which is available on Windows Vista and later. No third-party library
  is required.

  Alternatively, applications can call the CredentialManager.CLI .NET tool via
  ShellExecute to decrypt a single value and capture the output.
}

interface

uses
  System.SysUtils, System.Classes, System.IniFiles, System.NetEncoding,
  Winapi.Windows, Winapi.Bcrypt;

const
  ENC_PREFIX = 'ENC:';

type
  ECredentialManagerError = class(Exception);

  /// <summary>
  /// Reads credentials from AES-256-GCM encrypted INI files.
  /// The master key is loaded from a protected key file or from the
  /// CREDENTIAL_MASTER_KEY environment variable.
  /// </summary>
  TCredentialReader = class
  private
    FMasterKey: TBytes;

    procedure LoadKeyFromFile(const KeyFilePath: string);
    procedure LoadKeyFromEnvironment;
    function IsEncrypted(const Value: string): Boolean;
    function DecryptValue(const EncryptedValue: string): string;
    function DecryptAesGcm(const Key, Nonce, Tag, CipherText: TBytes): TBytes;
  public
    /// <summary>Creates a reader that loads the key from a file.</summary>
    constructor CreateWithKeyFile(const KeyFilePath: string);

    /// <summary>
    /// Creates a reader that loads the key from the
    /// CREDENTIAL_MASTER_KEY environment variable.
    /// </summary>
    constructor CreateWithEnvironmentKey;

    destructor Destroy; override;

    /// <summary>
    /// Reads a value from an INI file, decrypting it if necessary.
    /// Returns the plaintext value, whether it was encrypted or not.
    /// </summary>
    function ReadFromIni(const IniFilePath, Section, Key: string;
      const Default: string = ''): string;

    /// <summary>
    /// Decrypts a single ENC:... value. Returns the input unchanged if
    /// it is not prefixed with ENC:.
    /// </summary>
    function Read(const EncryptedOrPlainValue: string): string;
  end;

implementation

uses
  System.Math;

// ---------------------------------------------------------------------------
// TCredentialReader
// ---------------------------------------------------------------------------

constructor TCredentialReader.CreateWithKeyFile(const KeyFilePath: string);
begin
  inherited Create;
  LoadKeyFromFile(KeyFilePath);
end;

constructor TCredentialReader.CreateWithEnvironmentKey;
begin
  inherited Create;
  LoadKeyFromEnvironment;
end;

destructor TCredentialReader.Destroy;
begin
  // Zero out the key material before freeing
  if Length(FMasterKey) > 0 then
    FillChar(FMasterKey[0], Length(FMasterKey), 0);
  inherited;
end;

procedure TCredentialReader.LoadKeyFromFile(const KeyFilePath: string);
var
  SL: TStringList;
  Base64: string;
begin
  if not FileExists(KeyFilePath) then
    raise ECredentialManagerError.CreateFmt(
      'Key file not found: %s', [KeyFilePath]);

  SL := TStringList.Create;
  try
    SL.LoadFromFile(KeyFilePath);
    Base64 := Trim(SL.Text);
  finally
    SL.Free;
  end;

  FMasterKey := TNetEncoding.Base64.DecodeStringToBytes(Base64);
  if Length(FMasterKey) <> 32 then
    raise ECredentialManagerError.CreateFmt(
      'Key file must contain a 32-byte (256-bit) Base64-encoded key. ' +
      'Got %d bytes.', [Length(FMasterKey)]);
end;

procedure TCredentialReader.LoadKeyFromEnvironment;
const
  ENV_VAR = 'CREDENTIAL_MASTER_KEY';
var
  Base64: string;
begin
  Base64 := GetEnvironmentVariable(ENV_VAR);
  if Base64 = '' then
    raise ECredentialManagerError.CreateFmt(
      'Environment variable %s is not set.', [ENV_VAR]);

  FMasterKey := TNetEncoding.Base64.DecodeStringToBytes(Trim(Base64));
  if Length(FMasterKey) <> 32 then
    raise ECredentialManagerError.CreateFmt(
      'Environment variable %s must decode to exactly 32 bytes. ' +
      'Got %d bytes.', [ENV_VAR, Length(FMasterKey)]);
end;

function TCredentialReader.IsEncrypted(const Value: string): Boolean;
begin
  Result := Value.StartsWith(ENC_PREFIX);
end;

function TCredentialReader.Read(const EncryptedOrPlainValue: string): string;
begin
  if IsEncrypted(EncryptedOrPlainValue) then
    Result := DecryptValue(EncryptedOrPlainValue)
  else
    Result := EncryptedOrPlainValue;
end;

function TCredentialReader.ReadFromIni(const IniFilePath, Section, Key: string;
  const Default: string): string;
var
  Ini: TIniFile;
  RawValue: string;
begin
  Ini := TIniFile.Create(IniFilePath);
  try
    RawValue := Ini.ReadString(Section, Key, Default);
  finally
    Ini.Free;
  end;
  Result := Read(RawValue);
end;

function TCredentialReader.DecryptValue(const EncryptedValue: string): string;
const
  NONCE_SIZE = 12;
  TAG_SIZE   = 16;
var
  Base64Part: string;
  Combined, Nonce, Tag, CipherText, PlainText: TBytes;
begin
  Base64Part := Copy(EncryptedValue, Length(ENC_PREFIX) + 1, MaxInt);
  Combined   := TNetEncoding.Base64.DecodeStringToBytes(Base64Part);

  if Length(Combined) < NONCE_SIZE + TAG_SIZE then
    raise ECredentialManagerError.Create('Encrypted data is too short to be valid.');

  // Layout: nonce (12) | tag (16) | ciphertext (n)
  SetLength(Nonce,      NONCE_SIZE);
  SetLength(Tag,        TAG_SIZE);
  SetLength(CipherText, Length(Combined) - NONCE_SIZE - TAG_SIZE);

  Move(Combined[0],                    Nonce[0],      NONCE_SIZE);
  Move(Combined[NONCE_SIZE],           Tag[0],        TAG_SIZE);
  Move(Combined[NONCE_SIZE + TAG_SIZE], CipherText[0], Length(CipherText));

  PlainText := DecryptAesGcm(FMasterKey, Nonce, Tag, CipherText);
  Result    := TEncoding.UTF8.GetString(PlainText);
end;

/// <summary>
/// Decrypts using AES-256-GCM via the Windows CNG (BCrypt) API.
/// Raises ECredentialManagerError if authentication fails (tampered data).
/// </summary>
function TCredentialReader.DecryptAesGcm(
  const Key, Nonce, Tag, CipherText: TBytes): TBytes;
var
  hAlg, hKey: BCRYPT_ALG_HANDLE;
  KeyObj: TBytes;
  KeyObjSize, DataSize, PlainSize: DWORD;
  AuthInfo: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;
  Status: NTSTATUS;
begin
  Result := nil;

  OleCheck(BCryptOpenAlgorithmProvider(hAlg, 'AES', nil, 0));
  try
    OleCheck(BCryptSetProperty(hAlg, 'ChainingMode',
      @BCRYPT_CHAIN_MODE_GCM[1], Length(BCRYPT_CHAIN_MODE_GCM) * 2, 0));

    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, @KeyObjSize, SizeOf(DWORD), DataSize, 0);
    SetLength(KeyObj, KeyObjSize);

    OleCheck(BCryptGenerateSymmetricKey(hAlg, hKey, @KeyObj[0], KeyObjSize,
      @Key[0], Length(Key), 0));
    try
      FillChar(AuthInfo, SizeOf(AuthInfo), 0);
      AuthInfo.cbSize    := SizeOf(AuthInfo);
      AuthInfo.dwInfoVersion := BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
      AuthInfo.pbNonce   := @Nonce[0];
      AuthInfo.cbNonce   := Length(Nonce);
      AuthInfo.pbTag     := @Tag[0];
      AuthInfo.cbTag     := Length(Tag);

      SetLength(Result, Length(CipherText));
      Status := BCryptDecrypt(hKey, @CipherText[0], Length(CipherText),
        @AuthInfo, nil, 0, @Result[0], Length(Result), PlainSize, 0);

      if Status = STATUS_AUTH_TAG_MISMATCH then
        raise ECredentialManagerError.Create(
          'Authentication tag mismatch: data may have been tampered with.');

      if Status <> 0 then
        raise ECredentialManagerError.CreateFmt(
          'BCryptDecrypt failed with status 0x%x', [Status]);

      SetLength(Result, PlainSize);
    finally
      BCryptDestroyKey(hKey);
    end;
  finally
    BCryptCloseAlgorithmProvider(hAlg, 0);
  end;
end;

end.
