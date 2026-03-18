# Security
Security in legacy applications

## Store Database Credentials (`distribDB`)

`Set-DistribDB.ps1` stores a database connection string in a Windows environment
variable called **`distribDB`**.

### Requirements

* Windows PowerShell 5.1+ or PowerShell 7+
* **Administrator** privileges when using the default `Machine` scope

### Usage

```powershell
# Prompt for the connection string (input is hidden)
.\Set-DistribDB.ps1

# Store in the current User scope only (no Admin required)
.\Set-DistribDB.ps1 -Scope User

# Pass the connection string directly (use only in trusted, non-interactive contexts)
.\Set-DistribDB.ps1 -ConnectionString "Server=myserver;Database=mydb;User Id=<username>;Password=<password>;"
```

After the script runs, `distribDB` is available to all new processes. Restart any
open shells or applications to pick up the change.

### Parameters

| Parameter          | Required | Default   | Description |
|--------------------|----------|-----------|-------------|
| `-ConnectionString`| No       | *(prompt)*| The connection string to store. If omitted the script prompts securely. |
| `-Scope`           | No       | `Machine` | `Machine` (system-wide, requires Admin) or `User` (current user only). |
