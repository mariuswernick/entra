# Entra ID PowerShell Scripts and Tools

This repository contains a collection of PowerShell scripts and tools for managing Microsoft Entra ID (formerly Azure AD) environments. These scripts are designed to help administrators automate common tasks, implement security best practices, and manage their Entra ID tenant efficiently.

## 🚀 Features

- Automated tenant provisioning with security best practices
- User offboarding automation
- PowerShell snippets for common Entra ID tasks
- Zero Trust security group implementation
- Break glass account management

## 📂 Repository Contents

### PowerShell Scripts


#### offboarding.ps1
Automates the user offboarding process with:
- License removal
- Group membership cleanup
- Device unassignment
- Account security measures
- Audit logging

#### entra-powershell-snippets.md
A collection of useful PowerShell snippets for:
- Common Entra ID management tasks
- Security configurations
- Group management
- License assignment
- User management

## 📋 Prerequisites

- PowerShell 5.1 or higher
- Microsoft Graph PowerShell SDK
- Appropriate Entra ID administrator permissions
- Microsoft.Graph.Identity.DirectoryManagement module
- Microsoft.Graph.Groups module
- Microsoft.Graph.Users module

## 🔒 Security Features

- Implements Zero Trust principles
- Secure break glass account management
- Dynamic group membership rules
- Role-based access control
- Conditional Access policy foundations
- Audit logging and monitoring

## 🚦 Getting Started

1. Clone this repository
2. Install required PowerShell modules:
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```
3. Connect to Microsoft Graph:
```powershell
Connect-MgGraph -Scopes "Directory.ReadWrite.All", "Group.ReadWrite.All"
```
4. Customize the scripts according to your organization's needs
5. Run the desired scripts with appropriate permissions

## ⚠️ Important Notes

- Always review and test scripts in a non-production environment first
- Keep break glass account credentials secure
- Regularly review and update group memberships and policies
- Follow the principle of least privilege when assigning permissions
- Document any customizations made to the scripts

## 📚 Documentation

Each script contains detailed documentation and comments explaining its functionality. For more detailed information about specific scripts, please refer to the comments within each file.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
