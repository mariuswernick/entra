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
