<#
.SYNOPSIS
    Stores a database connection string in the Windows environment variable 'distribDB'.

.DESCRIPTION
    Prompts for a database connection string (input is masked) and saves it as a
    Windows Machine-level environment variable named 'distribDB'.
    Requires Administrator privileges to set a Machine-scoped variable.

.PARAMETER ConnectionString
    The database connection string to store. If omitted, the script will prompt
    for it securely (input is hidden).

.PARAMETER Scope
    The environment variable scope: Machine (default, requires Admin) or User.

.EXAMPLE
    .\Set-DistribDB.ps1

.EXAMPLE
    .\Set-DistribDB.ps1 -Scope User

.EXAMPLE
    .\Set-DistribDB.ps1 -ConnectionString "Server=myserver;Database=mydb;User Id=<username>;Password=<password>;"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ConnectionString,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Machine', 'User')]
    [string]$Scope = 'Machine'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Require Administrator rights when targeting the Machine scope
if ($Scope -eq 'Machine') {
    $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "Setting a Machine-scoped environment variable requires Administrator privileges. " +
              "Re-run this script as Administrator, or use -Scope User."
    }
}

# Prompt for the connection string if not supplied
if (-not $ConnectionString) {
    $secureInput = Read-Host -Prompt "Enter the database connection string for 'distribDB'" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureInput)
    try {
        $ConnectionString = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

if ([string]::IsNullOrWhiteSpace($ConnectionString)) {
    throw "Connection string must not be empty."
}

# Store the connection string in the environment variable
[System.Environment]::SetEnvironmentVariable('distribDB', $ConnectionString, $Scope)

Write-Host "Environment variable 'distribDB' has been set successfully (Scope: $Scope)."
Write-Host "The variable will be available to new processes. Restart any open shells or applications to pick up the change."
