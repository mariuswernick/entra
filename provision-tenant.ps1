# Entra ID (Azure AD) Tenant Provisioning Script - CORRECTED VERSION
# Prerequisites:
# Install-Module Microsoft.Graph -Scope CurrentUser -RequiredVersion 2.25.0 -Force
# Note: Pinned to v2.25.0 due to known issues in v2.26/v2.26.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantDomain = "yourdomain.com",  # Replace with your actual domain
    
    [Parameter(Mandatory = $false)]
    [string]$LocationId = "USA",  # Replace with your location
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf = $false,  # Preview mode - doesn't create anything
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:TEMP\EntraProvisioning-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
)

# Initialize logging
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry -ForegroundColor $(
        switch ($Level) {
            "ERROR" { "Red" }
            "WARN" { "Yellow" }
            "SUCCESS" { "Green" }
            default { "White" }
        }
    )
    Add-Content -Path $LogPath -Value $logEntry
}

Write-Log "Starting Entra ID Tenant Provisioning Script"
Write-Log "Log file: $LogPath"

# Validate parameters
if ($TenantDomain -eq "yourdomain.com") {
    Write-Log "WARNING: Using default tenant domain. Please update the TenantDomain parameter." -Level "WARN"
}

# Required scopes for Microsoft Graph
$RequiredScopes = @(
    "Group.ReadWrite.All",
    "Directory.ReadWrite.All", 
    "RoleManagement.ReadWrite.Directory",
    "DeviceManagementManagedDevices.ReadWrite.All",
    "DeviceManagementServiceConfig.ReadWrite.All",
    "User.ReadWrite.All"
)

Write-Log "Connecting to Microsoft Graph with required scopes..."
try {
    Connect-MgGraph -Scopes $RequiredScopes -ErrorAction Stop
    Write-Log "Successfully connected to Microsoft Graph" -Level "SUCCESS"
}
catch {
    Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Function to generate a cryptographically secure random password
function New-SecureRandomPassword {
    param(
        [int]$Length = 32
    )
    
    try {
        $symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        $numbers = '0123456789'
        $lowerCase = 'abcdefghijklmnopqrstuvwxyz'
        $upperCase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        $allChars = $symbols + $numbers + $lowerCase + $upperCase
        
        # Use modern .NET cryptography
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $bytes = New-Object byte[] $Length
        $rng.GetBytes($bytes)
        
        # Ensure at least one character from each required type
        $password = @()
        $password += $symbols[($bytes[0] % $symbols.Length)]
        $password += $numbers[($bytes[1] % $numbers.Length)]
        $password += $lowerCase[($bytes[2] % $lowerCase.Length)]
        $password += $upperCase[($bytes[3] % $upperCase.Length)]
        
        # Fill remaining positions
        for ($i = 4; $i -lt $Length; $i++) {
            $password += $allChars[($bytes[$i] % $allChars.Length)]
        }
        
        # Properly shuffle the password array
        for ($i = $password.Length - 1; $i -gt 0; $i--) {
            $randomIndex = $bytes[$i] % ($i + 1)
            $temp = $password[$i]
            $password[$i] = $password[$randomIndex]
            $password[$randomIndex] = $temp
        }
        
        $rng.Dispose()
        return -join $password
    }
    catch {
        Write-Log "Error generating secure password: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Helper function to create a group if it doesn't exist
function New-EntraGroup {
    param (
        [string]$DisplayName,
        [string]$Description,
        [string]$MailNickname,
        [bool]$SecurityEnabled = $true,
        [bool]$MailEnabled = $false,
        [string[]]$Labels = @(),
        [string]$MembershipRule,
        [bool]$MembershipRuleProcessingState = $true
    )
    
    try {
        # Check if group already exists
        $existingGroup = Get-MgGroup -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
        if ($existingGroup) {
            Write-Log "Group '$DisplayName' already exists with ID: $($existingGroup.Id)" -Level "WARN"
            return $existingGroup
        }

        if ($WhatIf) {
            Write-Log "WHATIF: Would create group '$DisplayName'" -Level "INFO"
            return $null
        }

        # Prepare group parameters
        $params = @{
            DisplayName = $DisplayName
            Description = $Description
            MailNickname = $MailNickname
            SecurityEnabled = $SecurityEnabled
            MailEnabled = $MailEnabled
        }

        # Handle dynamic membership
        if ($MembershipRule) {
            $params.GroupTypes = @("DynamicMembership")
            $params.MembershipRule = $MembershipRule
            $params.MembershipRuleProcessingState = if ($MembershipRuleProcessingState) { "On" } else { "Off" }
        } else {
            $params.GroupTypes = @()  # Empty array for security groups
        }

        # Add labels if provided
        if ($Labels.Count -gt 0) {
            # Note: Labels are not directly supported in New-MgGroup, but we can add them via description or other means
            $params.Description += " [Labels: $($Labels -join ', ')]"
        }

        $newGroup = New-MgGroup @params
        Write-Log "Created group '$DisplayName' with ID: $($newGroup.Id)" -Level "SUCCESS"
        
        # Add a small delay to prevent throttling
        Start-Sleep -Milliseconds 500
        
        return $newGroup
    }
    catch {
        Write-Log "Failed to create group '$DisplayName': $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

# 1. Create base organizational structure
Write-Log "=== Creating Base Organizational Structure ===" -Level "INFO"

$groups = @(
    @{
        DisplayName = "All Users"
        Description = "Contains all users in the organization"
        MailNickname = "all-users"
        Labels = @("core", "users")
        MembershipRule = 'user.userType -eq "Member"'
    },
    @{
        DisplayName = "All Devices"
        Description = "Contains all managed devices"
        MailNickname = "all-devices"
        Labels = @("core", "devices")
        MembershipRule = 'device.deviceId -ne null'
    }
)

$baseGroups = @{}
foreach ($group in $groups) {
    $newGroup = New-EntraGroup @group
    if ($newGroup) {
        $baseGroups[$group.DisplayName] = $newGroup
    }
}

# 2. Create Intune device groups with CORRECTED OS types and properties
Write-Log "=== Creating Intune Device Groups ===" -Level "INFO"

# Known MDM App IDs
$IntuneAppId = "0000000a-0000-0000-c000-000000000000"
$SCCMAppId = "54b943f8-d761-4f8d-951e-9cea1846db5a"

$intuneGroups = @(
    @{
        DisplayName = "Intune - Windows Devices"
        Description = "Windows devices managed by Intune"
        MailNickname = "intune-windows"
        Labels = @("intune", "windows")
        MembershipRule = "(device.deviceOSType -eq `"Windows`") and (device.deviceManagementAppId -eq `"$IntuneAppId`")"
    },
    @{
        DisplayName = "Intune - iPhone Devices"
        Description = "iPhone devices managed by Intune"
        MailNickname = "intune-iphone"
        Labels = @("intune", "iphone")
        MembershipRule = "(device.deviceOSType -eq `"iPhone`") and (device.deviceManagementAppId -eq `"$IntuneAppId`")"
    },
    @{
        DisplayName = "Intune - iPad Devices"
        Description = "iPad devices managed by Intune" 
        MailNickname = "intune-ipad"
        Labels = @("intune", "ipad")
        MembershipRule = "(device.deviceOSType -eq `"iPad`") and (device.deviceManagementAppId -eq `"$IntuneAppId`")"
    },
    @{
        DisplayName = "Intune - iOS Devices (All)"
        Description = "All iOS devices (iPhone and iPad) managed by Intune"
        MailNickname = "intune-ios-all"
        Labels = @("intune", "ios")
        MembershipRule = "((device.deviceOSType -eq `"iPhone`") or (device.deviceOSType -eq `"iPad`")) and (device.deviceManagementAppId -eq `"$IntuneAppId`")"
    },
    @{
        DisplayName = "Intune - Android Devices"
        Description = "Android devices managed by Intune"
        MailNickname = "intune-android"
        Labels = @("intune", "android")
        MembershipRule = "(device.deviceOSType -eq `"Android`") and (device.deviceManagementAppId -eq `"$IntuneAppId`")"
    },
    @{
        DisplayName = "Intune - macOS Devices"
        Description = "macOS devices managed by Intune"
        MailNickname = "intune-macos"
        Labels = @("intune", "macos")
        MembershipRule = "(device.deviceOSType -eq `"macOS`") and (device.deviceManagementAppId -eq `"$IntuneAppId`")"
    }
)

# Create Intune device groups
foreach ($group in $intuneGroups) {
    New-EntraGroup @group | Out-Null
}

# Create Autopilot groups with CORRECTED properties
Write-Log "=== Creating Autopilot Groups ===" -Level "INFO"

$autopilotGroups = @(
    @{
        DisplayName = "Autopilot - Windows Devices"
        Description = "Windows devices enrolled through Autopilot"
        MailNickname = "autopilot-windows"
        Labels = @("autopilot", "windows")
        MembershipRule = "(device.devicePhysicalIds -any _ -contains `"[ZTDId]`") and (device.deviceOSType -eq `"Windows`")"
    },
    @{
        DisplayName = "Autopilot - Corporate Devices"
        Description = "Corporate-owned Autopilot devices"
        MailNickname = "autopilot-corporate"
        Labels = @("autopilot", "corporate")
        MembershipRule = "(device.devicePhysicalIds -any _ -contains `"[ZTDId]`") and (device.deviceOwnership -eq `"Company`")"
    },
    @{
        DisplayName = "Autopilot - Hybrid Joined"
        Description = "Hybrid Azure AD joined Autopilot devices"
        MailNickname = "autopilot-hybrid"
        Labels = @("autopilot", "hybrid")
        MembershipRule = "(device.devicePhysicalIds -any _ -contains `"[ZTDId]`") and (device.deviceTrustType -eq `"ServerAD`")"
    },
    @{
        DisplayName = "Autopilot - Azure AD Joined"
        Description = "Pure Azure AD joined Autopilot devices"
        MailNickname = "autopilot-aad"
        Labels = @("autopilot", "aad")
        MembershipRule = "(device.devicePhysicalIds -any _ -contains `"[ZTDId]`") and (device.deviceTrustType -eq `"AzureAD`")"
    }
)

foreach ($group in $autopilotGroups) {
    New-EntraGroup @group | Out-Null
}

# Create additional device management groups with CORRECTED properties
Write-Log "=== Creating Device Management Groups ===" -Level "INFO"

$deviceManagementGroups = @(
    @{
        DisplayName = "Devices - Co-Managed (SCCM + Intune)"
        Description = "Devices co-managed by SCCM and Intune"
        MailNickname = "devices-co-managed"
        Labels = @("devices", "co-managed")
        MembershipRule = "(device.deviceOSType -eq `"Windows`") and (device.deviceManagementAppId -eq `"$SCCMAppId`")"
    },
    @{
        DisplayName = "Devices - Intune Only"
        Description = "Devices managed only by Intune"
        MailNickname = "devices-intune-only"
        Labels = @("devices", "intune-only")
        MembershipRule = "(device.deviceManagementAppId -eq `"$IntuneAppId`")"
    },
    @{
        DisplayName = "Devices - Corporate Owned"
        Description = "Corporate-owned devices"
        MailNickname = "devices-corporate"
        Labels = @("devices", "corporate")
        MembershipRule = "(device.deviceOwnership -eq `"Company`")"
    },
    @{
        DisplayName = "Devices - Personal Owned"
        Description = "Personal-owned devices"
        MailNickname = "devices-personal"
        Labels = @("devices", "personal")
        MembershipRule = "(device.deviceOwnership -eq `"Personal`")"
    },
    @{
        DisplayName = "Devices - Hybrid Joined"
        Description = "Hybrid Azure AD joined devices"
        MailNickname = "devices-hybrid-joined"
        Labels = @("devices", "hybrid")
        MembershipRule = "(device.deviceTrustType -eq `"ServerAD`")"
    },
    @{
        DisplayName = "Devices - Azure AD Joined"
        Description = "Pure Azure AD joined devices"
        MailNickname = "devices-aad-joined"
        Labels = @("devices", "aad")
        MembershipRule = "(device.deviceTrustType -eq `"AzureAD`")"
    },
    @{
        DisplayName = "Devices - Registered Only"
        Description = "Azure AD registered devices"
        MailNickname = "devices-registered"
        Labels = @("devices", "registered")
        MembershipRule = "(device.deviceTrustType -eq `"Workplace`")"
    },
    @{
        DisplayName = "Devices - Windows 10"
        Description = "Windows 10 devices"
        MailNickname = "devices-win10"
        Labels = @("devices", "windows10")
        MembershipRule = "(device.deviceOSType -eq `"Windows`") and (device.deviceOSVersion -startsWith `"10.0.1`")"
    },
    @{
        DisplayName = "Devices - Windows 11"
        Description = "Windows 11 devices"
        MailNickname = "devices-win11"
        Labels = @("devices", "windows11")
        MembershipRule = "(device.deviceOSType -eq `"Windows`") and (device.deviceOSVersion -startsWith `"10.0.2`")"
    }
)

foreach ($group in $deviceManagementGroups) {
    New-EntraGroup @group | Out-Null
}

# 3. Create software deployment groups
Write-Log "=== Creating Software Deployment Groups ===" -Level "INFO"

$softwareGroups = @(
    # Microsoft 365 Apps
    @{
        DisplayName = "SW - Microsoft 365 Apps Enterprise"
        Description = "Users assigned Microsoft 365 Apps Enterprise"
        MailNickname = "sw-m365-apps-enterprise"
        Labels = @("software", "office365", "enterprise")
    },
    @{
        DisplayName = "SW - Microsoft 365 Apps Business"
        Description = "Users assigned Microsoft 365 Apps Business"
        MailNickname = "sw-m365-apps-business"
        Labels = @("software", "office365", "business")
    },
    
    # Communication and Collaboration
    @{
        DisplayName = "SW - Microsoft Teams"
        Description = "Users assigned Microsoft Teams licenses"
        MailNickname = "sw-teams"
        Labels = @("software", "teams", "communication")
    },
    @{
        DisplayName = "SW - Microsoft Teams Phone"
        Description = "Users with Teams Phone System licenses"
        MailNickname = "sw-teams-phone"
        Labels = @("software", "teams", "voice")
    },
    
    # Business Intelligence
    @{
        DisplayName = "SW - Power BI Pro"
        Description = "Users assigned Power BI Pro licenses"
        MailNickname = "sw-powerbi-pro"
        Labels = @("software", "powerbi", "analytics")
    },
    @{
        DisplayName = "SW - Power BI Premium"
        Description = "Users assigned Power BI Premium licenses"
        MailNickname = "sw-powerbi-premium"
        Labels = @("software", "powerbi", "premium")
    },
    
    # Power Platform
    @{
        DisplayName = "SW - Power Apps"
        Description = "Users with Power Apps licenses"
        MailNickname = "sw-power-apps"
        Labels = @("software", "power-platform", "apps")
    },
    @{
        DisplayName = "SW - Power Automate"
        Description = "Users with Power Automate licenses"
        MailNickname = "sw-power-automate"
        Labels = @("software", "power-platform", "automation")
    },
    
    # Security and Compliance
    @{
        DisplayName = "SW - Microsoft Defender"
        Description = "Users with Microsoft Defender licenses"
        MailNickname = "sw-defender"
        Labels = @("software", "security", "defender")
    },
    @{
        DisplayName = "SW - Azure Information Protection"
        Description = "Users with AIP licenses"
        MailNickname = "sw-aip"
        Labels = @("software", "security", "aip")
    },
    
    # Enterprise Applications
    @{
        DisplayName = "SW - Project Plan 3"
        Description = "Users with Project Plan 3 licenses"
        MailNickname = "sw-project-p3"
        Labels = @("software", "project", "premium")
    },
    @{
        DisplayName = "SW - Visio Plan 2"
        Description = "Users with Visio Plan 2 licenses"
        MailNickname = "sw-visio-p2"
        Labels = @("software", "visio", "premium")
    },

    # Third-Party Applications
    @{
        DisplayName = "SW - Adobe Creative Cloud"
        Description = "Users with Adobe Creative Cloud licenses"
        MailNickname = "sw-adobe-cc"
        Labels = @("software", "adobe", "creative")
    },
    @{
        DisplayName = "SW - Zoom for Microsoft Teams"
        Description = "Users with Zoom integration for Teams"
        MailNickname = "sw-zoom"
        Labels = @("software", "zoom", "meetings")
    }
)

foreach ($group in $softwareGroups) {
    New-EntraGroup @group | Out-Null
}

# 4. Create user role groups
Write-Log "=== Creating User Role Groups ===" -Level "INFO"

$roleGroups = @(
    # IT Administration
    @{
        DisplayName = "Role - Global Administrators"
        Description = "Global administrators with full access"
        MailNickname = "role-global-admins"
        Labels = @("role", "it", "admin")
    },
    @{
        DisplayName = "Role - Security Administrators"
        Description = "Security administrators and analysts"
        MailNickname = "role-security-admins"
        Labels = @("role", "it", "security")
    },
    @{
        DisplayName = "Role - Intune Administrators"
        Description = "Intune endpoint managers"
        MailNickname = "role-intune-admins"
        Labels = @("role", "it", "intune")
    },
    @{
        DisplayName = "Role - Identity Administrators"
        Description = "Identity and access management admins"
        MailNickname = "role-identity-admins"
        Labels = @("role", "it", "identity")
    },
    @{
        DisplayName = "Role - Teams Administrators"
        Description = "Teams service administrators"
        MailNickname = "role-teams-admins"
        Labels = @("role", "it", "teams")
    },
    
    # Support Staff
    @{
        DisplayName = "Role - Help Desk L1"
        Description = "Level 1 help desk support"
        MailNickname = "role-helpdesk-l1"
        Labels = @("role", "support", "l1")
    },
    @{
        DisplayName = "Role - Help Desk L2"
        Description = "Level 2 technical support"
        MailNickname = "role-helpdesk-l2"
        Labels = @("role", "support", "l2")
    },
    
    # Security Groups
    @{
        DisplayName = "SEC - VPN Access"
        Description = "Users with VPN access"
        MailNickname = "sec-vpn-access"
        Labels = @("security", "network", "vpn")
    },
    @{
        DisplayName = "SEC - Cloud App Access"
        Description = "Users with access to cloud applications"
        MailNickname = "sec-cloud-apps"
        Labels = @("security", "cloud", "apps")
    },
    @{
        DisplayName = "SEC - Privileged Access"
        Description = "Users with privileged access rights"
        MailNickname = "sec-privileged"
        Labels = @("security", "privileged", "admin")
    },
    @{
        DisplayName = "SEC - MFA Exempt"
        Description = "Users exempt from MFA requirements"
        MailNickname = "sec-mfa-exempt"
        Labels = @("security", "mfa", "exempt")
    },
    
    # Management
    @{
        DisplayName = "Role - Executive Users"
        Description = "Executive staff members"
        MailNickname = "role-executives"
        Labels = @("role", "executive", "management")
    },
    @{
        DisplayName = "Role - Department Managers"
        Description = "Department managers and team leads"
        MailNickname = "role-managers"
        Labels = @("role", "management", "department")
    },
    @{
        DisplayName = "Role - Project Managers"
        Description = "Project managers and coordinators"
        MailNickname = "role-project-managers"
        Labels = @("role", "management", "projects")
    }
)

foreach ($group in $roleGroups) {
    New-EntraGroup @group | Out-Null
}

# Create compliance and policy groups
Write-Log "=== Creating Compliance and Policy Groups ===" -Level "INFO"

$complianceGroups = @(
    @{
        DisplayName = "POL - Conditional Access Pilot"
        Description = "Pilot users for new conditional access policies"
        MailNickname = "pol-ca-pilot"
        Labels = @("policy", "security", "pilot")
    },
    @{
        DisplayName = "POL - Device Compliance Exempt"
        Description = "Users exempt from device compliance"
        MailNickname = "pol-compliance-exempt"
        Labels = @("policy", "compliance", "exempt")
    },
    @{
        DisplayName = "POL - App Protection Required"
        Description = "Users requiring app protection policies"
        MailNickname = "pol-app-protection"
        Labels = @("policy", "security", "apps")
    },
    @{
        DisplayName = "POL - Retention Policy Standard"
        Description = "Standard retention policy users"
        MailNickname = "pol-retention-std"
        Labels = @("policy", "retention", "standard")
    },
    @{
        DisplayName = "POL - Retention Policy Extended"
        Description = "Extended retention policy users"
        MailNickname = "pol-retention-ext"
        Labels = @("policy", "retention", "extended")
    }
)

foreach ($group in $complianceGroups) {
    New-EntraGroup @group | Out-Null
}

# 5. Create department groups
Write-Log "=== Creating Department Groups ===" -Level "INFO"

$deptGroups = @(
    # IT Department
    @{
        DisplayName = "Dept - IT"
        Description = "IT Department members"
        MailNickname = "dept-it"
        Labels = @("department", "it")
        MembershipRule = 'user.department -eq "IT"'
    },
    @{
        DisplayName = "Dept - IT Infrastructure"
        Description = "IT Infrastructure team"
        MailNickname = "dept-it-infra"
        Labels = @("department", "it", "infrastructure")
        MembershipRule = 'user.department -eq "IT" and user.jobTitle -contains "Infrastructure"'
    },
    @{
        DisplayName = "Dept - IT Security"
        Description = "IT Security team"
        MailNickname = "dept-it-security"
        Labels = @("department", "it", "security")
        MembershipRule = 'user.department -eq "IT" and user.jobTitle -contains "Security"'
    },
    @{
        DisplayName = "Dept - IT Development"
        Description = "IT Development team"
        MailNickname = "dept-it-dev"
        Labels = @("department", "it", "development")
        MembershipRule = 'user.department -eq "IT" and (user.jobTitle -contains "Developer" or user.jobTitle -contains "Development")'
    },
    
    # Human Resources
    @{
        DisplayName = "Dept - HR"
        Description = "Human Resources Department"
        MailNickname = "dept-hr"
        Labels = @("department", "hr")
        MembershipRule = 'user.department -eq "Human Resources"'
    },
    @{
        DisplayName = "Dept - HR Recruiting"
        Description = "HR Recruiting team"
        MailNickname = "dept-hr-recruiting"
        Labels = @("department", "hr", "recruiting")
        MembershipRule = 'user.department -eq "Human Resources" and user.jobTitle -contains "Recruiting"'
    },
    @{
        DisplayName = "Dept - HR Benefits"
        Description = "HR Benefits team"
        MailNickname = "dept-hr-benefits"
        Labels = @("department", "hr", "benefits")
        MembershipRule = 'user.department -eq "Human Resources" and user.jobTitle -contains "Benefits"'
    },
    
    # Finance
    @{
        DisplayName = "Dept - Finance"
        Description = "Finance Department"
        MailNickname = "dept-finance"
        Labels = @("department", "finance")
        MembershipRule = 'user.department -eq "Finance"'
    },
    @{
        DisplayName = "Dept - Finance Accounting"
        Description = "Finance Accounting team"
        MailNickname = "dept-finance-accounting"
        Labels = @("department", "finance", "accounting")
        MembershipRule = 'user.department -eq "Finance" and user.jobTitle -contains "Accounting"'
    },
    @{
        DisplayName = "Dept - Finance Payroll"
        Description = "Finance Payroll team"
        MailNickname = "dept-finance-payroll"
        Labels = @("department", "finance", "payroll")
        MembershipRule = 'user.department -eq "Finance" and user.jobTitle -contains "Payroll"'
    },
    
    # Sales and Marketing
    @{
        DisplayName = "Dept - Sales"
        Description = "Sales Department"
        MailNickname = "dept-sales"
        Labels = @("department", "sales")
        MembershipRule = 'user.department -eq "Sales"'
    },
    @{
        DisplayName = "Dept - Sales NA"
        Description = "Sales North America team"
        MailNickname = "dept-sales-na"
        Labels = @("department", "sales", "na")
        MembershipRule = 'user.department -eq "Sales" and (user.usageLocation -eq "US" or user.usageLocation -eq "CA")'
    },
    @{
        DisplayName = "Dept - Sales EMEA"
        Description = "Sales EMEA team"
        MailNickname = "dept-sales-emea"
        Labels = @("department", "sales", "emea")
        MembershipRule = 'user.department -eq "Sales" and (user.country -eq "United Kingdom" or user.country -eq "Germany" or user.country -eq "France")'
    },
    @{
        DisplayName = "Dept - Marketing"
        Description = "Marketing Department"
        MailNickname = "dept-marketing"
        Labels = @("department", "marketing")
        MembershipRule = 'user.department -eq "Marketing"'
    },
    @{
        DisplayName = "Dept - Marketing Digital"
        Description = "Digital Marketing team"
        MailNickname = "dept-marketing-digital"
        Labels = @("department", "marketing", "digital")
        MembershipRule = 'user.department -eq "Marketing" and user.jobTitle -contains "Digital"'
    },
    @{
        DisplayName = "Dept - Marketing Events"
        Description = "Events Marketing team"
        MailNickname = "dept-marketing-events"
        Labels = @("department", "marketing", "events")
        MembershipRule = 'user.department -eq "Marketing" and user.jobTitle -contains "Events"'
    },
    
    # Operations
    @{
        DisplayName = "Dept - Operations"
        Description = "Operations Department"
        MailNickname = "dept-operations"
        Labels = @("department", "operations")
        MembershipRule = 'user.department -eq "Operations"'
    },
    @{
        DisplayName = "Dept - Operations Logistics"
        Description = "Operations Logistics team"
        MailNickname = "dept-operations-logistics"
        Labels = @("department", "operations", "logistics")
        MembershipRule = 'user.department -eq "Operations" and user.jobTitle -contains "Logistics"'
    },
    @{
        DisplayName = "Dept - Operations Facilities"
        Description = "Operations Facilities team"
        MailNickname = "dept-operations-facilities"
        Labels = @("department", "operations", "facilities")
        MembershipRule = 'user.department -eq "Operations" and user.jobTitle -contains "Facilities"'
    }
)

foreach ($group in $deptGroups) {
    New-EntraGroup @group | Out-Null
}

# Create Entra ID license and admin groups with CORRECTED membership rules
Write-Log "=== Creating Entra ID License and Admin Groups ===" -Level "INFO"

$entraGroups = @(
    @{
        DisplayName = "LIC - Entra ID P1"
        Description = "Users with Entra ID P1 licenses"
        MailNickname = "lic-entra-p1"
        Labels = @("license", "entra", "p1")
        # Note: Service plan IDs should be verified and updated as needed
        MembershipRule = 'user.assignedPlans -any (assignedPlan.servicePlanId -eq "41781fb2-bc02-4b7c-bd55-b576c07bb09d" and assignedPlan.capabilityStatus -eq "Enabled")'
    },
    @{
        DisplayName = "LIC - Entra ID P2"
        Description = "Users with Entra ID P2 licenses"
        MailNickname = "lic-entra-p2"
        Labels = @("license", "entra", "p2")
        # Note: Service plan IDs should be verified and updated as needed
        MembershipRule = 'user.assignedPlans -any (assignedPlan.servicePlanId -eq "eec0eb4f-6444-4f95-aba0-50c24d67f998" and assignedPlan.capabilityStatus -eq "Enabled")'
    },
    
    # Conditional Access & Zero Trust Groups
    @{
        DisplayName = "SEC - Break Glass Accounts"
        Description = "Emergency access accounts excluded from Conditional Access"
        MailNickname = "sec-break-glass"
        Labels = @("security", "emergency", "conditional-access")
    },
    @{
        DisplayName = "POL - CA Baseline Policy"
        Description = "Users subject to baseline Conditional Access policies"
        MailNickname = "pol-ca-baseline"
        Labels = @("policy", "security", "conditional-access")
    },
    @{
        DisplayName = "POL - Device Identity Required"
        Description = "Users requiring device identity for Conditional Access"
        MailNickname = "pol-device-identity"
        Labels = @("policy", "security", "device")
        MembershipRule = 'user.userType -eq "Member"'
    },
    @{
        DisplayName = "POL - MFA Required"
        Description = "Users requiring multi-factor authentication"
        MailNickname = "pol-mfa-required"
        Labels = @("policy", "security", "mfa")
        MembershipRule = 'user.userType -eq "Member"'
    },
    @{
        DisplayName = "POL - Risk-Based Auth Required"
        Description = "Users subject to risk-based authentication"
        MailNickname = "pol-risk-auth"
        Labels = @("policy", "security", "risk")
    },
    @{
        DisplayName = "POL - Privileged Auth Required"
        Description = "Users requiring enhanced authentication for privileged access"
        MailNickname = "pol-priv-auth"
        Labels = @("policy", "security", "privileged")
    },
    @{
        DisplayName = "POL - Location-Based Access"
        Description = "Users subject to location-based access controls"
        MailNickname = "pol-location-access"
        Labels = @("policy", "security", "location")
    },
    @{
        DisplayName = "POL - Device Compliance Required"
        Description = "Users requiring compliant devices"
        MailNickname = "pol-device-compliance"
        Labels = @("policy", "security", "compliance")
        MembershipRule = 'user.userType -eq "Member"'
    },
    @{
        DisplayName = "POL - Microsoft Authenticator Required"
        Description = "Users requiring Microsoft Authenticator app"
        MailNickname = "pol-ms-auth-required"
        Labels = @("policy", "security", "authenticator")
    },
    @{
        DisplayName = "POL - B2B Access Controls"
        Description = "External users subject to B2B access controls"
        MailNickname = "pol-b2b-access"
        Labels = @("policy", "security", "b2b")
        MembershipRule = 'user.userType -eq "Guest"'
    },
    @{
        DisplayName = "POL - Workstation Controls"
        Description = "Users subject to workstation access controls"
        MailNickname = "pol-workstation"
        Labels = @("policy", "security", "workstation")
    },
    @{
        DisplayName = "POL - Cloud App Controls"
        Description = "Users subject to cloud app access controls"
        MailNickname = "pol-cloud-app"
        Labels = @("policy", "security", "cloud")
    },
    @{
        DisplayName = "SEC - Zero Trust VIP"
        Description = "VIP users requiring enhanced Zero Trust controls"
        MailNickname = "sec-zerotrust-vip"
        Labels = @("security", "zerotrust", "vip")
    },
    @{
        DisplayName = "SEC - Zero Trust Level 1"
        Description = "Users with basic Zero Trust requirements"
        MailNickname = "sec-zerotrust-l1"
        Labels = @("security", "zerotrust", "basic")
    },
    @{
        DisplayName = "SEC - Zero Trust Level 2"
        Description = "Users with enhanced Zero Trust requirements"
        MailNickname = "sec-zerotrust-l2"
        Labels = @("security", "zerotrust", "enhanced")
    },
    @{
        DisplayName = "SEC - Zero Trust Level 3"
        Description = "Users with strict Zero Trust requirements"
        MailNickname = "sec-zerotrust-l3"
        Labels = @("security", "zerotrust", "strict")
    }
)

foreach ($group in $entraGroups) {
    New-EntraGroup @group | Out-Null
}

# Create break glass accounts with SECURE password generation
Write-Log "=== Creating Break Glass Accounts ===" -Level "INFO"

$breakGlassAccounts = @(
    @{
        UserPrincipalName = "emg.svc.access.controller1@$TenantDomain"
        DisplayName = "EMG Access Controller - Achilles"  # Greek mythology theme
        MailNickname = "emg.svc.access.c1"
    },
    @{
        UserPrincipalName = "emg.svc.access.controller2@$TenantDomain"
        DisplayName = "EMG Access Controller - Hermes"   # Greek mythology theme
        MailNickname = "emg.svc.access.c2"
    }
)

foreach ($account in $breakGlassAccounts) {
    try {
        $existingUser = Get-MgUser -Filter "userPrincipalName eq '$($account.UserPrincipalName)'" -ErrorAction SilentlyContinue
        if ($existingUser) {
            Write-Log "Break glass account $($account.DisplayName) already exists with ID: $($existingUser.Id)" -Level "WARN"
            continue
        }
        
        if ($WhatIf) {
            Write-Log "WHATIF: Would create break glass account $($account.DisplayName)" -Level "INFO"
            continue
        }

        $password = New-SecureRandomPassword
        $params = @{
            DisplayName = $account.DisplayName
            UserPrincipalName = $account.UserPrincipalName
            MailNickname = $account.MailNickname
            AccountEnabled = $true
            PasswordProfile = @{
                Password = $password
                ForceChangePasswordNextSignIn = $false
                PasswordPolicies = "DisablePasswordExpiration"
            }
            UsageLocation = $LocationId
        }

        $newUser = New-MgUser @params
        Write-Log "Created break glass account $($account.DisplayName)" -Level "SUCCESS"
        Write-Log "IMPORTANT: Password for $($account.DisplayName): $password" -Level "WARN"
        Write-Log "CRITICAL: Save this password securely in your password manager!" -Level "ERROR"
        
        # Add to break glass group
        $breakGlassGroup = Get-MgGroup -Filter "displayName eq 'SEC - Break Glass Accounts'" -ErrorAction SilentlyContinue
        if ($breakGlassGroup) {
            New-MgGroupMember -GroupId $breakGlassGroup.Id -DirectoryObjectId $newUser.Id -ErrorAction SilentlyContinue
            Write-Log "Added $($account.DisplayName) to break glass group" -Level "SUCCESS"
        }
        
        # Add a delay to prevent throttling
        Start-Sleep -Seconds 2
    }
    catch {
        Write-Log "Failed to create break glass account $($account.DisplayName): $($_.Exception.Message)" -Level "ERROR"
    }
}

# Completion summary
Write-Log "=== Tenant Provisioning Completed ===" -Level "SUCCESS"
Write-Log "Summary of actions:" -Level "INFO"
Write-Log "- Created base organizational structure groups" -Level "INFO"
Write-Log "- Created Intune device groups with corrected OS types" -Level "INFO"
Write-Log "- Created Autopilot device groups" -Level "INFO"
Write-Log "- Created device management groups" -Level "INFO"
Write-Log "- Created software deployment groups" -Level "INFO"
Write-Log "- Created user role groups" -Level "INFO"
Write-Log "- Created compliance and policy groups" -Level "INFO"
Write-Log "- Created department groups with dynamic membership" -Level "INFO"
Write-Log "- Created Entra ID license and admin groups" -Level "INFO"
Write-Log "- Created break glass accounts with secure passwords" -Level "INFO"

Write-Log "Next steps:" -Level "INFO"
Write-Log "1. Review created groups in the Entra admin center" -Level "INFO"
Write-Log "2. Validate dynamic membership rules are working correctly" -Level "INFO"
Write-Log "3. Assign licenses to software groups" -Level "INFO"
Write-Log "4. Configure Conditional Access policies" -Level "INFO"
Write-Log "5. Set up Intune policies for device groups" -Level "INFO"
Write-Log "6. Configure Autopilot deployment profiles" -Level "INFO"
Write-Log "7. Set up group-based license assignment" -Level "INFO"
Write-Log "8. Configure admin roles for IT staff groups" -Level "INFO"
Write-Log "9. Test break glass account access" -Level "INFO"
Write-Log "10. Review and update service plan IDs for license groups" -Level "INFO"

Write-Log "Log file saved to: $LogPath" -Level "INFO"

# Disconnect from Microsoft Graph
try {
    Disconnect-MgGraph
    Write-Log "Disconnected from Microsoft Graph" -Level "SUCCESS"
}
catch {
    Write-Log "Warning: Could not disconnect from Microsoft Graph: $($_.Exception.Message)" -Level "WARN"
}

Write-Host "`n✅ Tenant provisioning completed successfully!" -ForegroundColor Green
Write-Host "📋 Review the log file for detailed information: $LogPath" -ForegroundColor Cyan
Write-Host "🔐 IMPORTANT: Secure the break glass account passwords immediately!" -ForegroundColor Red