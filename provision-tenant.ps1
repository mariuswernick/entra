# Entra ID (Azure AD) Tenant Provisioning Script
# Prerequisites:
# Install-Module Microsoft.Graph -Scope CurrentUser

# Variables - Customize these as needed
$tenantDomain = "yourdomain.com"  # Replace with your actual domain
$locationId = "USA"  # Replace with your location

# Connect to Microsoft Graph with required scopes
Connect-MgGraph -Scopes @(
    "Group.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "DeviceManagementManagedDevices.ReadWrite.All",
    "DeviceManagementServiceConfig.ReadWrite.All"
)

# Function to generate a cryptographically secure random password
function New-SecureRandomPassword {
    $length = 32
    $symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    $numbers = '0123456789'
    $lowerCase = 'abcdefghijklmnopqrstuvwxyz'
    $upperCase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $allChars = $symbols + $numbers + $lowerCase + $upperCase
    
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $bytes = [byte[]]::new($length)
    $rng.GetBytes($bytes)
    
    # Ensure at least one of each required character type
    $password = @(
        $symbols[(Get-Random -Count 1 -Maximum $symbols.Length)]
        $numbers[(Get-Random -Count 1 -Maximum $numbers.Length)]
        $lowerCase[(Get-Random -Count 1 -Maximum $lowerCase.Length)]
        $upperCase[(Get-Random -Count 1 -Maximum $upperCase.Length)]
    )
    
    # Fill the rest randomly
    $remainingLength = $length - $password.Length
    for ($i = 0; $i -lt $remainingLength; $i++) {
        $password += $allChars[$bytes[$i] % $allChars.Length]
    }
    
    # Shuffle the password
    $password = $password | Get-Random -Count $password.Length
    
    return -join $password
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
        $existingGroup = Get-MgGroup -Filter "displayName eq '$DisplayName'"
        if ($existingGroup) {
            Write-Host "Group '$DisplayName' already exists with id: $($existingGroup.Id)" -ForegroundColor Yellow
            return $existingGroup
        }

        $params = @{
            DisplayName = $DisplayName
            Description = $Description
            MailNickname = $MailNickname
            SecurityEnabled = $SecurityEnabled
            MailEnabled = $MailEnabled
            GroupTypes = @()  # Empty array for security groups
        }        if ($Labels.Count -gt 0) {
            $params.Labels = $Labels
        }

        if ($MembershipRule) {
            $params.GroupTypes = @("DynamicMembership")
            $params.MembershipRule = $MembershipRule
            $params.MembershipRuleProcessingState = if ($MembershipRuleProcessingState) { "On" } else { "Off" }
        }

        $newGroup = New-MgGroup @params
        Write-Host "Created group '$DisplayName' with id: $($newGroup.Id)" -ForegroundColor Green
        return $newGroup
    }
    catch {
        Write-Error "Failed to create group '$DisplayName': $_"
        return $null
    }
}

# 1. Create base organizational structure
Write-Host "`n=== Creating Base Organizational Structure ===" -ForegroundColor Cyan

# Root groups for different purposes
$groups = @(
    @{
        DisplayName = "All Users"
        Description = "Contains all users in the organization"
        MailNickname = "all-users"
        Labels = @("core", "users")
    },
    @{
        DisplayName = "All Devices"
        Description = "Contains all managed devices"
        MailNickname = "all-devices"
        Labels = @("core", "devices")
    }
)

$baseGroups = @{}
foreach ($group in $groups) {
    $newGroup = New-EntraGroup @group
    $baseGroups[$group.DisplayName] = $newGroup
}

# 2. Create Intune device groups
Write-Host "`n=== Creating Intune Device Groups ===" -ForegroundColor Cyan

$intuneGroups = @(
    @{
        DisplayName = "Intune - Windows Devices"
        Description = "Windows devices managed by Intune"
        MailNickname = "intune-windows"
        Labels = @("intune", "windows")
        MembershipRule = '(device.deviceOSType -eq "Windows") and (device.managementType -eq "MDM")'
    },
    @{
        DisplayName = "Intune - iOS Devices"
        Description = "iOS devices managed by Intune"
        MailNickname = "intune-ios"
        Labels = @("intune", "ios")
        MembershipRule = '(device.deviceOSType -eq "iOS") and (device.managementType -eq "MDM")'
    },
    @{
        DisplayName = "Intune - Android Devices"
        Description = "Android devices managed by Intune"
        MailNickname = "intune-android"
        Labels = @("intune", "android")
        MembershipRule = '(device.deviceOSType -eq "Android") and (device.managementType -eq "MDM")'
    },
    @{
        DisplayName = "Intune - MacOS Devices"
        Description = "MacOS devices managed by Intune"
        MailNickname = "intune-macos"
        Labels = @("intune", "macos")
        MembershipRule = '(device.deviceOSType -eq "MacOS") and (device.managementType -eq "MDM")'
    }
)

# Create standard Intune device groups
foreach ($group in $intuneGroups) {
    New-EntraGroup @group
}

# Create Autopilot groups
Write-Host "`n=== Creating Autopilot Groups ===" -ForegroundColor Cyan

$autopilotGroups = @(
    @{
        DisplayName = "Autopilot - New Devices"
        Description = "New devices pending Autopilot enrollment"
        MailNickname = "autopilot-new"
        Labels = @("autopilot", "enrollment")
        MembershipRule = '(device.devicePhysicalIDs -any _ -contains "[ZTDId]") and (device.deviceOSType -eq "Windows") and (device.enrollmentProfileName -eq "")'
    },
    @{
        DisplayName = "Autopilot - Enrolled Devices"
        Description = "Devices enrolled through Autopilot"
        MailNickname = "autopilot-enrolled"
        Labels = @("autopilot", "enrolled")
        MembershipRule = '(device.devicePhysicalIDs -any _ -contains "[ZTDId]") and (device.deviceOSType -eq "Windows") and (device.enrollmentProfileName -ne "")'
    },
    @{
        DisplayName = "Autopilot - Executive Devices"
        Description = "Executive devices with special configuration"
        MailNickname = "autopilot-executive"
        Labels = @("autopilot", "executive")
        MembershipRule = '(device.devicePhysicalIDs -any _ -contains "[ZTDId]") and (device.deviceOSType -eq "Windows") and (device.enrollmentProfileName -eq "Executive")'
    },
    @{
        DisplayName = "Autopilot - Standard Devices"
        Description = "Standard devices with default configuration"
        MailNickname = "autopilot-standard"
        Labels = @("autopilot", "standard")
        MembershipRule = '(device.devicePhysicalIDs -any _ -contains "[ZTDId]") and (device.deviceOSType -eq "Windows") and (device.enrollmentProfileName -eq "Standard")'
    }
)

foreach ($group in $autopilotGroups) {
    New-EntraGroup @group
}

# Create additional device management groups
Write-Host "`n=== Creating Device Management Groups ===" -ForegroundColor Cyan

$deviceManagementGroups = @(
    @{
        DisplayName = "Devices - Co-Managed"
        Description = "Devices co-managed by SCCM and Intune"
        MailNickname = "devices-co-managed"
        Labels = @("devices", "co-managed")
        MembershipRule = '(device.deviceOSType -eq "Windows") and (device.managementType -eq "MDM") and (device.deviceManagementAppId -eq "17ab22b0-3237-4238-9124-f3090fb71611")'
    },
    @{
        DisplayName = "Devices - Primary Users"
        Description = "Devices with assigned primary users"
        MailNickname = "devices-primary-users"
        Labels = @("devices", "primary-users")
        MembershipRule = '(device.deviceOSType -eq "Windows") and (device.managementType -eq "MDM") and (device.primaryUser -ne null)'
    },
    @{
        DisplayName = "Devices - Shared"
        Description = "Shared devices without primary users"
        MailNickname = "devices-shared"
        Labels = @("devices", "shared")
        MembershipRule = '(device.deviceOSType -eq "Windows") and (device.managementType -eq "MDM") and (device.primaryUser -eq null)'
    },
    @{
        DisplayName = "Devices - Compliance Failed"
        Description = "Devices that failed compliance checks"
        MailNickname = "devices-compliance-failed"
        Labels = @("devices", "compliance")
        MembershipRule = '(device.deviceOSType -eq "Windows") and (device.managementType -eq "MDM") and (device.complianceState -eq "noncompliant")'
    },
    @{
        DisplayName = "Devices - Updates Required"
        Description = "Devices requiring Windows updates"
        MailNickname = "devices-updates-required"
        Labels = @("devices", "updates")
        MembershipRule = '(device.deviceOSType -eq "Windows") and (device.managementType -eq "MDM") and (device.securityPatchLevel -lt device.manufacturer)'
    }
)

foreach ($group in $deviceManagementGroups) {
    New-EntraGroup @group
}

# 3. Create software deployment groups
Write-Host "`n=== Creating Software Deployment Groups ===" -ForegroundColor Cyan

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
    New-EntraGroup @group
}

# 4. Create user role groups
Write-Host "`n=== Creating User Role Groups ===" -ForegroundColor Cyan

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
    New-EntraGroup @group
}

# Create compliance and policy groups
Write-Host "`n=== Creating Compliance and Policy Groups ===" -ForegroundColor Cyan

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
    New-EntraGroup @group
}

# 5. Create department groups
Write-Host "`n=== Creating Department Groups ===" -ForegroundColor Cyan

$deptGroups = @(
    # IT Department
    @{
        DisplayName = "Dept - IT"
        Description = "IT Department members"
        MailNickname = "dept-it"
        Labels = @("department", "it")
    },
    @{
        DisplayName = "Dept - IT Infrastructure"
        Description = "IT Infrastructure team"
        MailNickname = "dept-it-infra"
        Labels = @("department", "it", "infrastructure")
    },
    @{
        DisplayName = "Dept - IT Security"
        Description = "IT Security team"
        MailNickname = "dept-it-security"
        Labels = @("department", "it", "security")
    },
    @{
        DisplayName = "Dept - IT Development"
        Description = "IT Development team"
        MailNickname = "dept-it-dev"
        Labels = @("department", "it", "development")
    },
    
    # Human Resources
    @{
        DisplayName = "Dept - HR"
        Description = "Human Resources Department"
        MailNickname = "dept-hr"
        Labels = @("department", "hr")
    },
    @{
        DisplayName = "Dept - HR Recruiting"
        Description = "HR Recruiting team"
        MailNickname = "dept-hr-recruiting"
        Labels = @("department", "hr", "recruiting")
    },
    @{
        DisplayName = "Dept - HR Benefits"
        Description = "HR Benefits team"
        MailNickname = "dept-hr-benefits"
        Labels = @("department", "hr", "benefits")
    },
    
    # Finance
    @{
        DisplayName = "Dept - Finance"
        Description = "Finance Department"
        MailNickname = "dept-finance"
        Labels = @("department", "finance")
    },
    @{
        DisplayName = "Dept - Finance Accounting"
        Description = "Finance Accounting team"
        MailNickname = "dept-finance-accounting"
        Labels = @("department", "finance", "accounting")
    },
    @{
        DisplayName = "Dept - Finance Payroll"
        Description = "Finance Payroll team"
        MailNickname = "dept-finance-payroll"
        Labels = @("department", "finance", "payroll")
    },
    
    # Sales and Marketing
    @{
        DisplayName = "Dept - Sales"
        Description = "Sales Department"
        MailNickname = "dept-sales"
        Labels = @("department", "sales")
    },
    @{
        DisplayName = "Dept - Sales NA"
        Description = "Sales North America team"
        MailNickname = "dept-sales-na"
        Labels = @("department", "sales", "na")
    },
    @{
        DisplayName = "Dept - Sales EMEA"
        Description = "Sales EMEA team"
        MailNickname = "dept-sales-emea"
        Labels = @("department", "sales", "emea")
    },
    @{
        DisplayName = "Dept - Marketing"
        Description = "Marketing Department"
        MailNickname = "dept-marketing"
        Labels = @("department", "marketing")
    },
    @{
        DisplayName = "Dept - Marketing Digital"
        Description = "Digital Marketing team"
        MailNickname = "dept-marketing-digital"
        Labels = @("department", "marketing", "digital")
    },
    @{
        DisplayName = "Dept - Marketing Events"
        Description = "Events Marketing team"
        MailNickname = "dept-marketing-events"
        Labels = @("department", "marketing", "events")
    },
    
    # Operations
    @{
        DisplayName = "Dept - Operations"
        Description = "Operations Department"
        MailNickname = "dept-operations"
        Labels = @("department", "operations")
    },
    @{
        DisplayName = "Dept - Operations Logistics"
        Description = "Operations Logistics team"
        MailNickname = "dept-operations-logistics"
        Labels = @("department", "operations", "logistics")
    },
    @{
        DisplayName = "Dept - Operations Facilities"
        Description = "Operations Facilities team"
        MailNickname = "dept-operations-facilities"
        Labels = @("department", "operations", "facilities")
    }
)

foreach ($group in $deptGroups) {
    New-EntraGroup @group
}

# Create Entra ID license and admin groups
Write-Host "`n=== Creating Entra ID License and Admin Groups ===" -ForegroundColor Cyan

$entraGroups = @(
    @{
        DisplayName = "LIC - Entra ID P1"
        Description = "Users with Entra ID P1 licenses"
        MailNickname = "lic-entra-p1"
        Labels = @("license", "entra", "p1")
        MembershipRule = 'user.assignedPlans -any (assignedPlan.servicePlanId -eq "41781fb2-bc02-4b7c-bd55-b576c07bb09d" -and assignedPlan.capabilityStatus -eq "Enabled")'
    },
    @{
        DisplayName = "LIC - Entra ID P2"
        Description = "Users with Entra ID P2 licenses"
        MailNickname = "lic-entra-p2"
        Labels = @("license", "entra", "p2")
        MembershipRule = 'user.assignedPlans -any (assignedPlan.servicePlanId -eq "eec0eb4f-6444-4f95-aba0-50c24d67f998" -and assignedPlan.capabilityStatus -eq "Enabled")'
    },
    @{
        DisplayName = "Role - Entra Admins"
        Description = "Users with Entra ID administrator roles"
        MailNickname = "role-entra-admins"
        Labels = @("role", "entra", "admin")
        MembershipRule = 'user.memberOf -any (group.displayName -match "Role - Global Administrators") or user.memberOf -any (group.displayName -match "Role - Identity Administrators") or user.memberOf -any (group.displayName -match "Role - Security Administrators")'
    },
    @{
        DisplayName = "Role - Entra Global Admins"
        Description = "Users with Global Administrator role"
        MailNickname = "role-entra-global-admins"
        Labels = @("role", "entra", "global-admin")
        MembershipRule = 'user.directoryroles -any (role.roleTemplateId -eq "62e90394-69f5-4237-9190-012177145e10")'
    },
    @{
        DisplayName = "Role - Entra Privileged Role Admins"
        Description = "Users with Privileged Role Administrator role"
        MailNickname = "role-entra-pra"
        Labels = @("role", "entra", "privileged")
        MembershipRule = 'user.directoryroles -any (role.roleTemplateId -eq "e8611ab8-c189-46e8-94e1-60213ab1f814")'
    },
    @{
        DisplayName = "Role - Entra License Admins"
        Description = "Users with License Administrator role"
        MailNickname = "role-entra-license-admins"
        Labels = @("role", "entra", "license")
        MembershipRule = 'user.directoryroles -any (role.roleTemplateId -eq "4d6ac14f-3453-41d0-bef9-a3e0c569773a")'
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
    New-EntraGroup @group
}

# Create break glass accounts with randomized but recognizable names
Write-Host "`n=== Creating Break Glass Accounts ===" -ForegroundColor Cyan

$breakGlassAccounts = @(
    @{
        UserPrincipalName = "emg.svc.access.controller1@$tenantDomain"
        DisplayName = "EMG Access Controller - Achilles"  # Greek mythology theme
        MailNickname = "emg.svc.access.c1"
    },
    @{
        UserPrincipalName = "emg.svc.access.controller2@$tenantDomain"
        DisplayName = "EMG Access Controller - Hermes"   # Greek mythology theme
        MailNickname = "emg.svc.access.c2"
    }
)

foreach ($account in $breakGlassAccounts) {
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
    }

    try {
        $existingUser = Get-MgUser -Filter "userPrincipalName eq '$($account.UserPrincipalName)'"
        if ($existingUser) {
            Write-Host "Break glass account $($account.DisplayName) already exists with id: $($existingUser.Id)" -ForegroundColor Yellow
        } else {
            $newUser = New-MgUser @params
            Write-Host "Created break glass account $($account.DisplayName) with password: $password" -ForegroundColor Green
            Write-Host "IMPORTANT: Save this password securely!" -ForegroundColor Red
        }
    }
    catch {
        Write-Error "Failed to create break glass account $($account.DisplayName): $_"
    }
}

Write-Host "`n✅ Tenant provisioning completed successfully!" -ForegroundColor Green
Write-Host "Next steps:"
Write-Host "1. Review created groups in the Entra admin center"
Write-Host "2. Configure dynamic membership rules for device groups"
Write-Host "3. Assign licenses to software groups"
Write-Host "4. Configure Conditional Access policies"
Write-Host "5. Set up Intune policies for device groups"
Write-Host "6. Review and configure Autopilot deployment profiles"
Write-Host "7. Set up group-based license assignment"
Write-Host "8. Configure admin roles for IT staff groups"
