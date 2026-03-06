program DelphiSampleApp;

{
  Sample Delphi console application demonstrating how to read encrypted
  credentials from an INI file using the CredentialManager unit.

  Steps to run this sample:
  1. Generate a master key:
       credmgr generate-key --out master.key

  2. Create a sample INI file (sample.ini):
       [Database]
       Server=db.company.local
       Password=s3cr3t

  3. Encrypt it:
       credmgr encrypt sample.ini --key-file master.key

  4. Set the key environment variable (or keep using --key-file):
       set CREDENTIAL_MASTER_KEY=<contents of master.key>

  5. Compile and run this program.
}

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  CredentialManager in 'CredentialManager.pas';

begin
  try
    var Reader := TCredentialReader.CreateWithEnvironmentKey;
    try
      var Server   := Reader.ReadFromIni('sample.ini', 'Database', 'Server');
      var Password := Reader.ReadFromIni('sample.ini', 'Database', 'Password');

      WriteLn('Server:   ', Server);
      WriteLn('Password: ', Password);
    finally
      Reader.Free;
    end;
  except
    on E: Exception do
    begin
      WriteLn('Error: ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
