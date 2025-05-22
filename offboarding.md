# Automated User Offboarding Script (Microsoft Graph Only)

This script automates user offboarding in Entra ID (Azure AD) and Intune using only the Microsoft.Graph module.

## Features

- Disable user account in Entra ID  
- Reset user password (cloud-only accounts)  
- Revoke sign-in sessions  
- Delete authentication methods  
- Disable Windows devices in Entra ID  
- Reboot Windows devices via Intune  
- Retire Android, iOS, and macOS devices via Intune  

---

## Prerequisites

- PowerShell 7+ recommended  
- Install the Microsoft Graph module:

    ```powershell
    Install-Module Microsoft.Graph -Scope CurrentUser
    ```

- Sufficient admin permissions in Entra ID and Intune  
- Run PowerShell as administrator  

---

## Usage

1. Update the variables at the top of the script with the correct user and password information.
2. Run the script in a PowerShell session.

```powershell
# offboarding.ps1

# Prerequisites:
# Install-Module Microsoft.Graph -Scope CurrentUser

# Variables
$userUPN = "user@domain.com"           # User Principal Name in Entra ID
$newPassword = "NewP@ssw0rd!"          # New password for reset

# Connect to Microsoft Graph with required scopes
Connect-MgGraph -Scopes "User.ReadWrite.All","Device.ReadWrite.All","Directory.AccessAsUser.All"

# 1. Disable user in Entra ID (Azure AD)
Update-MgUser -UserId $userUPN -AccountEnabled:$false

# 2. Reset password in Entra ID (cloud-only accounts)
Update-MgUser -UserId $userUPN -PasswordProfile @{ Password = $newPassword; ForceChangePasswordNextSignIn = $true }

# 3. Revoke sign-in sessions
Revoke-MgUserSignInSession -UserId $userUPN

# 4. Delete authentication methods
Get-MgUserAuthenticationMethod -UserId $userUPN | ForEach-Object {
    Remove-MgUserAuthenticationMethod -UserId $userUPN -AuthenticationMethodId $_.Id
}

# 5. Find all devices owned by the user
$devices = Get-MgDevice -Filter "registeredOwners/any(o:o/userPrincipalName eq '$userUPN')"

# 6. Disable Windows devices in Entra ID
$windowsDevices = $devices | Where-Object { $_.OperatingSystem -eq "Windows" -and $_.AccountEnabled }
foreach ($device in $windowsDevices) {
    Update-MgDevice -DeviceId $device.Id -AccountEnabled:$false
}

# 7. Reboot Windows devices (Intune/Endpoint Manager)
$managedDevices = Get-MgDeviceManagementManagedDevice -Filter "userPrincipalName eq '$userUPN'"
$windowsManagedDevices = $managedDevices | Where-Object { $_.OperatingSystem -eq "Windows" }
foreach ($device in $windowsManagedDevices) {
    Invoke-MgDeviceManagementManagedDeviceRebootNow -ManagedDeviceId $device.Id
}

# 8. Retire Android, iOS, and macOS devices (Intune/Endpoint Manager)
$mobileDevices = $managedDevices | Where-Object { $_.OperatingSystem -in @("Android", "iOS", "macOS") }
foreach ($device in $mobileDevices) {
    Invoke-MgDeviceManagementManagedDeviceRetire -ManagedDeviceId $device.Id
}

Write-Host "User offboarding actions completed for $userUPN"
```

---

## Notes

- Password reset works for cloud-only accounts. For hybrid users, reset in on-prem AD.
- Device actions require Intune/Endpoint Manager licensing and permissions.
- Test in a non-production environment before using in production.
- Update variables as needed for your environment.

---
