# 100 Useful PowerShell Entra ID (Azure AD) Snippets

> Most snippets use the Microsoft Graph PowerShell SDK.  
> Connect first:  
> ```powershell
> Connect-MgGraph -Scopes "User.ReadWrite.All", "Group.ReadWrite.All", "Directory.ReadWrite.All"
> ```

---

### 1. List All Users
```powershell
Get-MgUser -All
```

### 2. Get User by UPN
```powershell
Get-MgUser -UserId "user@domain.com"
```

### 3. List All Groups
```powershell
Get-MgGroup -All
```

### 4. Create a New User
```powershell
New-MgUser -DisplayName "John Doe" -UserPrincipalName "johndoe@domain.com" -MailNickname "johndoe" -AccountEnabled $true -PasswordProfile @{ Password = "P@ssword1234"; ForceChangePasswordNextSignIn = $true }
```

### 5. Delete a User
```powershell
Remove-MgUser -UserId "user@domain.com"
```

### 6. Add User to Group
```powershell
Add-MgGroupMember -GroupId "group-id" -DirectoryObjectId "user-id"
```

### 7. List Group Members
```powershell
Get-MgGroupMember -GroupId "group-id"
```

### 8. Remove User from Group
```powershell
Remove-MgGroupMember -GroupId "group-id" -DirectoryObjectId "user-id"
```

### 9. Reset User Password
```powershell
Update-MgUser -UserId "user@domain.com" -PasswordProfile @{ Password = "NewPassword!23"; ForceChangePasswordNextSignIn = $true }
```

### 10. Get All Applications
```powershell
Get-MgApplication -All
```

### 11. List All Service Principals
```powershell
Get-MgServicePrincipal -All
```

### 12. Create a Group
```powershell
New-MgGroup -DisplayName "Test Group" -MailEnabled $false -MailNickname "testgroup" -SecurityEnabled $true
```

### 13. Delete a Group
```powershell
Remove-MgGroup -GroupId "group-id"
```

### 14. Update User Display Name
```powershell
Update-MgUser -UserId "user@domain.com" -DisplayName "New Name"
```

### 15. List All Devices
```powershell
Get-MgDevice -All
```

### 16. Get User’s Assigned Licenses
```powershell
Get-MgUserLicenseDetail -UserId "user@domain.com"
```

### 17. Assign License to User
```powershell
Set-MgUserLicense -UserId "user@domain.com" -AddLicenses @{SkuId="sku-guid"} -RemoveLicenses @()
```

### 18. Remove License from User
```powershell
Set-MgUserLicense -UserId "user@domain.com" -AddLicenses @() -RemoveLicenses @("sku-guid")
```

### 19. List All Directory Roles
```powershell
Get-MgDirectoryRole
```

### 20. Get Members of a Role
```powershell
Get-MgDirectoryRoleMember -DirectoryRoleId "role-id"
```

### 21. Add User to Directory Role
```powershell
Add-MgDirectoryRoleMember -DirectoryRoleId "role-id" -DirectoryObjectId "user-id"
```

### 22. Remove User from Role
```powershell
Remove-MgDirectoryRoleMember -DirectoryRoleId "role-id" -DirectoryObjectId "user-id"
```

### 23. List All Deleted Users
```powershell
Get-MgDirectoryDeletedItemUser -All
```

### 24. Restore Deleted User
```powershell
Restore-MgDirectoryDeletedItem -DirectoryObjectId "deleted-user-id"
```

### 25. Permanently Delete a Deleted User
```powershell
Remove-MgDirectoryDeletedItem -DirectoryObjectId "deleted-user-id"
```

### 26. Search Users by Display Name
```powershell
Get-MgUser -Filter "displayName eq 'John Doe'"
```

### 27. Get User MFA Status (requires MSOnline)
```powershell
Get-MsolUser -UserPrincipalName "user@domain.com" | Select-Object DisplayName, StrongAuthenticationMethods
```

### 28. Get User Sign-in Logs
```powershell
Get-MgAuditLogSignIn -Filter "userId eq 'user-guid'"
```

### 29. List User’s Groups
```powershell
Get-MgUserMemberOf -UserId "user@domain.com"
```

### 30. List Users with a Specific Domain
```powershell
Get-MgUser -Filter "endsWith(userPrincipalName,'@domain.com')"
```

### 31. Get User’s Manager
```powershell
Get-MgUserManager -UserId "user@domain.com"
```

### 32. Set User’s Manager
```powershell
Set-MgUserManagerByRef -UserId "user@domain.com" -Ref '@{ "@odata.id" = "https://graph.microsoft.com/v1.0/users/manager-id" }'
```

### 33. Remove User’s Manager
```powershell
Remove-MgUserManager -UserId "user@domain.com"
```

### 34. List All Guest Users
```powershell
Get-MgUser -Filter "userType eq 'Guest'"
```

### 35. List All Member Users
```powershell
Get-MgUser -Filter "userType eq 'Member'"
```

### 36. Bulk Import Users from CSV
```powershell
Import-Csv users.csv | ForEach-Object { New-MgUser -DisplayName $_.DisplayName -UserPrincipalName $_.UserPrincipalName -MailNickname $_.MailNickname -AccountEnabled $true -PasswordProfile @{ Password = $_.Password; ForceChangePasswordNextSignIn = $true } }
```

### 37. Export All Users to CSV
```powershell
Get-MgUser -All | Select-Object DisplayName,UserPrincipalName,Id | Export-Csv users.csv -NoTypeInformation
```

### 38. Get Group Owners
```powershell
Get-MgGroupOwner -GroupId "group-id"
```

### 39. Add Owner to Group
```powershell
Add-MgGroupOwner -GroupId "group-id" -DirectoryObjectId "user-id"
```

### 40. Remove Owner from Group
```powershell
Remove-MgGroupOwner -GroupId "group-id" -DirectoryObjectId "user-id"
```

### 41. List User’s Devices
```powershell
Get-MgUserRegisteredDevice -UserId "user@domain.com"
```

### 42. Get Device Details
```powershell
Get-MgDevice -DeviceId "device-id"
```

### 43. Disable a Device
```powershell
Update-MgDevice -DeviceId "device-id" -AccountEnabled $false
```

### 44. Enable a Device
```powershell
Update-MgDevice -DeviceId "device-id" -AccountEnabled $true
```

### 45. Delete a Device
```powershell
Remove-MgDevice -DeviceId "device-id"
```

### 46. List All Applications with AppId
```powershell
Get-MgApplication | Select-Object DisplayName,AppId
```

### 47. List All Service Principals with AppId
```powershell
Get-MgServicePrincipal | Select-Object DisplayName,AppId
```

### 48. Add Redirect URI to App
```powershell
Update-MgApplication -ApplicationId "app-id" -Web @{ RedirectUris = @("https://newuri") }
```

### 49. Remove Redirect URI from App
```powershell
Update-MgApplication -ApplicationId "app-id" -Web @{ RedirectUris = @() }
```

### 50. Assign Application to User
```powershell
New-MgUserAppRoleAssignment -UserId "user@domain.com" -PrincipalId "user-id" -ResourceId "service-principal-id" -AppRoleId "role-id"
```

---

### 51. List All App Registrations
```powershell
Get-MgApplication -All
```

### 52. List User’s App Role Assignments
```powershell
Get-MgUserAppRoleAssignment -UserId "user@domain.com"
```

### 53. List Directory Audit Logs
```powershell
Get-MgAuditLogDirectoryAudit
```

### 54. List Sign-in Logs for a User
```powershell
Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'user@domain.com'"
```

### 55. Find Expiring Passwords (if password policies apply)
```powershell
Get-MgUser -All | Where-Object { $_.PasswordPolicies -notlike "*DisablePasswordExpiration*" }
```

### 56. Set User Password Never Expires (with MSOnline)
```powershell
Set-MsolUser -UserPrincipalName "user@domain.com" -PasswordNeverExpires $true
```

### 57. Enable User Account
```powershell
Update-MgUser -UserId "user@domain.com" -AccountEnabled $true
```

### 58. Disable User Account
```powershell
Update-MgUser -UserId "user@domain.com" -AccountEnabled $false
```

### 59. Find All Disabled Users
```powershell
Get-MgUser -Filter "accountEnabled eq false"
```

### 60. Find All Enabled Users
```powershell
Get-MgUser -Filter "accountEnabled eq true"
```

### 61. List All Admin Roles
```powershell
Get-MgRoleManagementDirectoryRoleDefinition -Filter "isEnabled eq true"
```

### 62. List Tenant Details
```powershell
Get-MgOrganization
```

### 63. List All Domains
```powershell
Get-MgDomain
```

### 64. Get Domain Verification Status
```powershell
Get-MgDomain -DomainId "domain.com" | Select-Object AuthenticationType,IsVerified
```

### 65. List All Conditional Access Policies
```powershell
Get-MgIdentityConditionalAccessPolicy -All
```

### 66. List All External Users
```powershell
Get-MgUser -Filter "userType eq 'Guest'"
```

### 67. Get User Authentication Methods
```powershell
Get-MgUserAuthenticationMethod -UserId "user@domain.com"
```

### 68. Remove User Authentication Method
```powershell
Remove-MgUserAuthenticationMethod -UserId "user@domain.com" -AuthenticationMethodId "method-id"
```

### 69. List All Directory Objects
```powershell
Get-MgDirectoryObject -All
```

### 70. Find Users with No Assigned Licenses
```powershell
Get-MgUser -All | Where-Object { ($_.AssignedLicenses).Count -eq 0 }
```

### 71. Get Group Owners for All Groups
```powershell
Get-MgGroup -All | ForEach-Object { Get-MgGroupOwner -GroupId $_.Id }
```

### 72. Export All Groups to CSV
```powershell
Get-MgGroup -All | Select-Object DisplayName,Mail,Id | Export-Csv groups.csv -NoTypeInformation
```

### 73. Get All Dynamic Groups
```powershell
Get-MgGroup -Filter "groupTypes/any(c:c eq 'DynamicMembership')"
```

### 74. Get Dynamic Membership Rule for a Group
```powershell
(Get-MgGroup -GroupId "group-id").MembershipRule
```

### 75. List All Directory Deleted Items
```powershell
Get-MgDirectoryDeletedItem -All
```

### 76. Find All Users Created in Last 30 Days
```powershell
Get-MgUser -Filter "createdDateTime ge $(Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')"
```

### 77. List All Applications with a Specific Reply URL
```powershell
Get-MgApplication -Filter "web/redirectUris/any(s:s eq 'https://yoururl')"
```

### 78. List All Groups with a Specific Owner
```powershell
Get-MgGroup -Filter "owners/any(a:a eq 'user-id')"
```

### 79. List All Users with a Specific Department
```powershell
Get-MgUser -Filter "department eq 'IT'"
```

### 80. List Users with a Specific Job Title
```powershell
Get-MgUser -Filter "jobTitle eq 'Manager'"
```

### 81. Get User’s Assigned Roles
```powershell
Get-MgUserAppRoleAssignment -UserId "user@domain.com"
```

### 82. Force User Sign-Out
```powershell
Invoke-MgInvalidateUserRefreshToken -UserId "user@domain.com"
```

### 83. List All Groups a User is Member Of
```powershell
Get-MgUserMemberOf -UserId "user@domain.com"
```

### 84. List All Owners of Applications
```powershell
Get-MgApplication -All | ForEach-Object { Get-MgApplicationOwner -ApplicationId $_.Id }
```

### 85. Export All Service Principals to CSV
```powershell
Get-MgServicePrincipal -All | Select-Object DisplayName,AppId,Id | Export-Csv serviceprincipals.csv -NoTypeInformation
```

### 86. List All Federated Domains
```powershell
Get-MgDomain | Where-Object { $_.AuthenticationType -eq "Federated" }
```

### 87. Find All Users with MFA Enabled (using MSOnline)
```powershell
Get-MsolUser -All | Where-Object { $_.StrongAuthenticationMethods.Count -gt 0 }
```

### 88. Find All Users with MFA Disabled (using MSOnline)
```powershell
Get-MsolUser -All | Where-Object { $_.StrongAuthenticationMethods.Count -eq 0 }
```

### 89. List All Conditional Access Named Locations
```powershell
Get-MgIdentityConditionalAccessNamedLocation
```

### 90. List All Enterprise Applications
```powershell
Get-MgServicePrincipal -All | Where-Object { $_.ServicePrincipalType -eq "EnterpriseApp" }
```

### 91. Remove a User’s App Role Assignment
```powershell
Remove-MgUserAppRoleAssignment -UserId "user@domain.com" -AppRoleAssignmentId "assignment-id"
```

### 92. List All Consent Grants
```powershell
Get-MgOauth2PermissionGrant
```

### 93. List All Applications with a Certificate Credential
```powershell
Get-MgApplication -All | Where-Object { ($_.KeyCredentials | Where-Object { $_.Type -eq "AsymmetricX509Cert" }).Count -gt 0 }
```

### 94. List All Applications with a Client Secret
```powershell
Get-MgApplication -All | Where-Object { ($_.PasswordCredentials).Count -gt 0 }
```

### 95. List All Users with Admin Roles
```powershell
Get-MgDirectoryRole | ForEach-Object { Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id }
```

### 96. Get User’s Assigned Devices
```powershell
Get-MgUserRegisteredDevice -UserId "user@domain.com"
```

### 97. Get All Users with Specific UPN Suffix
```powershell
Get-MgUser -Filter "endsWith(userPrincipalName, '@yourdomain.com')"
```

### 98. Find All Security Groups (non-mail enabled)
```powershell
Get-MgGroup -Filter "securityEnabled eq true and mailEnabled eq false"
```

### 99. Find All Mail-enabled Security Groups
```powershell
Get-MgGroup -Filter "securityEnabled eq true and mailEnabled eq true"
```

### 100. Disconnect from Microsoft Graph
```powershell
Disconnect-MgGraph
```

---

**Tip:**  
- Prefer Microsoft.Graph PowerShell SDK for new scripts.
- For legacy scenarios, AzureAD or MSOnline modules may be required (marked above).
- Always check the [official Microsoft Graph docs](https://docs.microsoft.com/powershell/microsoftgraph/introduction) for more info and updates.