#Requires -Version 5.1
<#
.VERSION HISTORY
    v2.0  — Initial release.
    v2.1  — Extended $adminRoleIds with corrected role GUID labels and the following added roles:
              Attribute Provisioning Administrator, Attribute Provisioning Reader,
              Authentication Extensibility Administrator, Authentication Policy Administrator,
              B2C IEF Keyset Administrator, Directory Writers, Domain Name Administrator,
              External Identity Provider Administrator, Lifecycle Workflows Administrator,
              Security Reader.
    v2.2  — Aligned $adminRoleIds with $roles in Import-PIMSettings.ps1. Added 13 roles with
              GUIDs confirmed from Microsoft Entra documentation: Agent ID Administrator,
              AI Administrator, AI Reader, Authentication Extensibility Password Administrator,
              Compliance Administrator, Compliance Data Administrator, Exchange Recipient
              Administrator, External ID User Flow Administrator, External ID User Flow
              Attribute Administrator, Identity Governance Administrator, Knowledge
              Administrator, SharePoint Administrator, Teams Administrator.
              Corrected mislabelled entry: 29232cdf is Exchange Administrator (was labelled
              Exchange Recipient Administrator). $adminRoleIds now covers all 42 roles from
              Import-PIMSettings.ps1.
#>

<#
DISCLAIMER The sample scripts are not supported under any Microsoft standard support program or service.
The sample codes are provided AS IS without warranty of any kind. Microsoft further disclaims all implied
warranties including, without limitation, any implied warranties of merchantability or of fitness for a
particular purpose. The entire risk arising out of the use or performance of the sample codes and documentation
remains with you. In no event shall Microsoft, its authors, owners of this repository or anyone else involved
in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without
limitation, damages for loss of business profits, business interruption, loss of business information, or other
pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if
Microsoft has been advised of the possibility of such damages.
#>

#region Helper Functions

function Install-RequiredModule {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Host "Installing module '$Name'..." -ForegroundColor Yellow
        Install-Module -Name $Name -Force -AllowClobber
    } else {
        Write-Host "Module '$Name' is already installed." -ForegroundColor Green
    }
}

# Cache of existing CA policies populated once before the policy loop to avoid N API calls
$script:existingPolicies = $null

function Select-ExistingAppIds {
    # Filters a list of app IDs to those that have a service principal in this tenant.
    # CA policy creation fails with ServicePrincipalNotFound if an excluded app is not provisioned.
    param([string[]] $AppIds)
    $AppIds | Where-Object {
        $appId = $_
        try {
            Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$appId')?`$select=id" `
                -ErrorAction Stop | Out-Null
            $true
        } catch {
            Write-Host "    App '$appId' has no service principal in this tenant — excluded from policy." -ForegroundColor DarkGray
            $false
        }
    }
}

function New-CAPolicyIfNotExists {
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][hashtable]$BodyParameter
    )
    if ($script:existingPolicies.DisplayName -contains $DisplayName) {
        Write-Host "CA policy '$DisplayName' already exists." -ForegroundColor Green
        return
    }
    Write-Host "Creating CA policy '$DisplayName'..." -ForegroundColor Yellow
    try {
        New-MgIdentityConditionalAccessPolicy -BodyParameter $BodyParameter -ErrorAction Stop | Out-Null
    } catch {
        $errDetail = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        Write-Warning "Failed to create CA policy '${DisplayName}': $errDetail"
    }
}

#endregion

#region Module Installation

# NuGet is required by PowerShellGet to install modules from the Gallery
if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Write-Host "Installing package provider 'NuGet'..." -ForegroundColor Yellow
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
} else {
    Write-Host "Package provider 'NuGet' is already installed." -ForegroundColor Green
}

@(
    'Microsoft.Graph.Authentication'
    'Microsoft.Graph.Users'
    'Microsoft.Graph.Groups'
    'Microsoft.Graph.Identity.SignIns'
    'Microsoft.Graph.Identity.Governance'
    'Microsoft.Graph.Identity.DirectoryManagement'
    'Microsoft.Graph.Applications'
) | ForEach-Object { Install-RequiredModule -Name $_ }

#endregion

#region Graph Connection

$permissions = @(
    'Policy.Read.All'
    'Policy.ReadWrite.ConditionalAccess'
    'Application.Read.All'
    'CustomSecAttributeDefinition.Read.All'
    'CustomSecAttributeDefinition.ReadWrite.All'
    'User.Read.All'
    'User.ReadWrite.All'
    'Group.Read.All'
    'Group.ReadWrite.All'
    'RoleManagement.ReadWrite.Directory'
)
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
Connect-MgGraph -Scopes $permissions -NoWelcome

#endregion

#region Attribute Definition Administrator Role Assignment

$currentUser   = (Get-MgContext).Account
# -UserId accepts a UPN directly and returns a single typed object; .Id works under strict mode
$currentUserId = (Get-MgUser -UserId $currentUser).Id

# Role GUID: Attribute Definition Administrator — needed to create custom security attributes below
$attrAdminRoleId = '8424c6f0-a189-499e-bbd0-26c1753c96d4'

$existingAttrRole = Get-MgRoleManagementDirectoryRoleAssignment |
    Where-Object { $_.PrincipalId -eq $currentUserId -and $_.RoleDefinitionId -eq $attrAdminRoleId }

if (-not $existingAttrRole) {
    Write-Host "Assigning 'Attribute Definition Administrator' to $currentUser..." -ForegroundColor Yellow
    try {
        New-MgRoleManagementDirectoryRoleAssignment -BodyParameter @{
            '@odata.type'    = '#microsoft.graph.unifiedRoleAssignment'
            RoleDefinitionId = $attrAdminRoleId
            PrincipalId      = $currentUserId
            DirectoryScopeId = '/'
        } | Out-Null
    } catch {
        Write-Warning "Failed to assign role: $_"
    }
} else {
    Write-Host "'Attribute Definition Administrator' already assigned to $currentUser." -ForegroundColor Green
}

#endregion

#region Custom Security Attributes

# Attribute set that groups all data classification attributes used in DLP CA policies
if (-not (Get-MgDirectoryAttributeSet | Where-Object { $_.Id -eq 'DataSensitivity' })) {
    Write-Host "Creating attribute set 'DataSensitivity'..." -ForegroundColor Yellow
    try {
        New-MgDirectoryAttributeSet -BodyParameter @{
            Id                  = 'DataSensitivity'
            Description         = 'Data sensitivity attribute set'
            MaxAttributesPerSet = 25
        } | Out-Null
    } catch {
        Write-Warning "Failed to create attribute set 'DataSensitivity': $_"
    }
} else {
    Write-Host "Attribute set 'DataSensitivity' already exists." -ForegroundColor Green
}

# Classification attribute enables labeling apps as Confidential/HC so CA policies can target them
if (-not (Get-MgDirectoryCustomSecurityAttributeDefinition | Where-Object { $_.Name -eq 'Classification' })) {
    Write-Host "Creating attribute definition 'Classification'..." -ForegroundColor Yellow
    try {
        New-MgDirectoryCustomSecurityAttributeDefinition -BodyParameter @{
            attributeSet            = 'DataSensitivity'
            description             = 'Data sensitivity classifications'
            isCollection            = $true
            isSearchable            = $true
            name                    = 'Classification'
            status                  = 'Available'
            type                    = 'String'
            usePreDefinedValuesOnly = $true
            allowedValues           = @(
                @{ id = 'Highly Confidential'; isActive = $true }
                @{ id = 'Confidential';        isActive = $true }
                @{ id = 'General';             isActive = $true }
                @{ id = 'Public';              isActive = $true }
                @{ id = 'Non-Business';        isActive = $true }
            )
        } | Out-Null
    } catch {
        Write-Warning "Failed to create attribute definition 'Classification': $_"
    }
} else {
    Write-Host "Attribute definition 'Classification' already exists." -ForegroundColor Green
}

#endregion

#region Break Glass Accounts

# Break glass accounts must pre-exist — run Import-BreakGlassAccounts.ps1 to create them.
# This region only resolves their object IDs for use as CA policy exclusions.
$breakGlassDomain = (Get-MgDomain | Where-Object { $_.IsDefault }).Id
$bgUPN1 = "BreakGlass1@$breakGlassDomain"
$bgUPN2 = "BreakGlass2@$breakGlassDomain"

function Get-MgUserIdByUpn {
    param([string]$Upn)
    try {
        $r = Invoke-MgGraphRequest -Method GET `
                 -Uri "v1.0/users/$([System.Uri]::EscapeDataString($Upn))?`$select=id" `
                 -OutputType PSObject -ErrorAction Stop
        return $r.id
    } catch {
        if ($_.Exception.Message -notmatch 'Request_ResourceNotFound') {
            Write-Warning "Unexpected error looking up user '$Upn': $_"
        }
        return $null
    }
}

$breakGlass1Id = Get-MgUserIdByUpn -Upn $bgUPN1
$breakGlass2Id = Get-MgUserIdByUpn -Upn $bgUPN2

$missing = @()
if ([string]::IsNullOrEmpty($breakGlass1Id)) { $missing += $bgUPN1 }
if ([string]::IsNullOrEmpty($breakGlass2Id)) { $missing += $bgUPN2 }
if ($missing) {
    Write-Error ("Break glass account(s) not found: $($missing -join ', '). " +
        "Run Import-BreakGlassAccounts.ps1 first, then re-run this script.")
    exit 1
}

Write-Host "Break Glass User 1: $bgUPN1 ($breakGlass1Id)" -ForegroundColor Green
Write-Host "Break Glass User 2: $bgUPN2 ($breakGlass2Id)" -ForegroundColor Green

#endregion

#region Named Locations

# IDs must be captured in both branches — they are referenced later in DLP004 and PER003 CA policies

$existingAdminLoc = Get-MgIdentityConditionalAccessNamedLocation |
    Where-Object { $_.DisplayName -eq 'Countries allowed for admin access' }
if (-not $existingAdminLoc) {
    Write-Host "Creating named location 'Countries allowed for admin access'..." -ForegroundColor Yellow
    try {
        $adminAllowedCountriesId = (New-MgIdentityConditionalAccessNamedLocation -BodyParameter @{
            '@odata.type'                     = '#microsoft.graph.countryNamedLocation'
            DisplayName                       = 'Countries allowed for admin access'
            CountriesAndRegions               = @('US', 'CH')
            IncludeUnknownCountriesAndRegions = $false
        }).Id
    } catch {
        Write-Error "Failed to create admin allowed countries location: $_"
    }
} else {
    $adminAllowedCountriesId = $existingAdminLoc.Id
    Write-Host "Named location 'Countries allowed for admin access' already exists." -ForegroundColor Green
}

$existingChcLoc = Get-MgIdentityConditionalAccessNamedLocation |
    Where-Object { $_.DisplayName -eq 'Countries allowed for CHC data access' }
if (-not $existingChcLoc) {
    Write-Host "Creating named location 'Countries allowed for CHC data access'..." -ForegroundColor Yellow
    try {
        $chcAllowedCountriesId = (New-MgIdentityConditionalAccessNamedLocation -BodyParameter @{
            '@odata.type'                     = '#microsoft.graph.countryNamedLocation'
            DisplayName                       = 'Countries allowed for CHC data access'
            CountriesAndRegions               = @('US', 'CH')
            IncludeUnknownCountriesAndRegions = $false
        }).Id
    } catch {
        Write-Error "Failed to create CHC allowed countries location: $_"
    }
} else {
    $chcAllowedCountriesId = $existingChcLoc.Id
    Write-Host "Named location 'Countries allowed for CHC data access' already exists." -ForegroundColor Green
}

#endregion

#region Secure Workstation Users Group

# In a PAW CSM tenant, PAW-Global-Users already exists and serves as the target group.
# Use it directly; only fall back to creating Secure Workstation Users when it is absent.
$pawGlobalUsers = Get-MgGroup -Filter "displayName eq 'PAW-Global-Users'" -ErrorAction SilentlyContinue |
    Select-Object -First 1

if ($pawGlobalUsers) {
    $secureGroupId = $pawGlobalUsers.Id
    Write-Host "Using existing group 'PAW-Global-Users' (ID: $secureGroupId) for CA policy assignments." -ForegroundColor Green
} else {
    $secureGroupName = 'Secure Workstation Users'
    $existingSecureGroup = Get-MgGroup -Filter "displayName eq '$secureGroupName'" -ErrorAction SilentlyContinue
    if (-not $existingSecureGroup) {
        Write-Host "Creating dynamic group '$secureGroupName'..." -ForegroundColor Yellow
        try {
            $secureGroupId = (New-MgGroup -BodyParameter @{
                Description                   = $secureGroupName
                DisplayName                   = $secureGroupName
                MailEnabled                   = $false
                SecurityEnabled               = $true
                MailNickName                  = 'SecureWorkstationsUsers'
                GroupTypes                    = @('DynamicMembership')
                MembershipRule                = '(user.userPrincipalName -startsWith "AZADM-")'
                MembershipRuleProcessingState = 'On'
            }).Id
        } catch {
            Write-Error "Failed to create secure workstation group: $_"
        }
    } else {
        $secureGroupId = $existingSecureGroup.Id
        Write-Host "Group '$secureGroupName' already exists." -ForegroundColor Green
    }
}

#endregion

#region Conditional Access Policies

# Privileged role GUIDs shared across BAS007, BAS011, PER001, PER003, PER004, PER005.
# GUIDs verified against Microsoft Entra built-in roles documentation (learn.microsoft.com).
$adminRoleIds = @(
    # --- Tier 1 ---
    '62e90394-69f5-4237-9190-012177145e10'  # Global Administrator
    '3a2c62db-5318-420d-8d74-23affee5d9d5'  # Intune Administrator
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'  # Conditional Access Administrator
    'c4e39bd9-1100-46d3-8c65-fb160da0071f'  # Authentication Administrator
    '0526716b-113d-4c15-b2c8-68e3c22b9f80'  # Authentication Policy Administrator
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'  # Hybrid Identity Administrator
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'  # Privileged Authentication Administrator
    'e8611ab8-c189-46e8-94e1-60213ab1f814'  # Privileged Role Administrator
    '194ae4cb-b126-40b2-bd5b-6091b380977d'  # Security Administrator
    # --- Tier 2 ---
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'  # Application Administrator
    'cf1c38e5-3621-4004-a7cb-879624dced7c'  # Application Developer
    'ecb2c6bf-0ab6-418e-bd87-7986f8d63bbe'  # Attribute Provisioning Administrator
    '422218e4-db15-4ef9-bbe0-8afb41546d79'  # Attribute Provisioning Reader
    '25a516ed-2fa0-40ea-a2d0-12923a21473a'  # Authentication Extensibility Administrator
    'aaf43236-0c0d-4d5f-883a-6955382ac081'  # B2C IEF Keyset Administrator
    '158c047a-c907-4556-b7ef-446551a6b5f7'  # Cloud Application Administrator
    '7698a772-787b-4ac8-901f-60d6b08affd2'  # Cloud Device Administrator
    '9360feb5-f418-4baa-8175-e2a00bac4301'  # Directory Writers
    '8329153b-31d0-4727-b945-745eb3bc5f31'  # Domain Name Administrator
    '29232cdf-9323-42fd-ade2-1d097af3e4de'  # Exchange Administrator
    'be2f45a1-457d-42af-a067-6ec1fa63bc45'  # External Identity Provider Administrator
    'f2ef992c-3afb-46b9-b7cf-a126ee74c451'  # Global Reader
    'fdd7a751-b60b-444a-984c-02652fe8fa1c'  # Groups Administrator
    '729827e3-9c14-49f7-bb1b-9608f156bbb8'  # Helpdesk Administrator
    '59d46f88-662b-457b-bceb-5c3809e5908f'  # Lifecycle Workflows Administrator
    '966707d0-3269-4727-9be2-8c3a10f19b9d'  # Password Administrator
    '5d6b6bb7-de71-4623-b4af-96380a352509'  # Security Reader
    '5f2222b1-57c3-48ba-8ad5-d4759f1fde6f'  # Security Operator
    'fe930be7-5e62-47db-91af-98c3a49a38b1'  # User Administrator
    # --- v2.2 additions ---
    'db506228-d27e-4b7d-95e5-295956d6615f'  # Agent ID Administrator
    'd2562ede-74db-457e-a7b6-544e236ebb61'  # AI Administrator
    '1fe13547-53f6-408d-ac04-7f8eed167b38'  # AI Reader
    '0b00bede-4072-4d22-b441-e7df02a1ef63'  # Authentication Extensibility Password Administrator
    '17315797-102d-40b4-93e0-432062caca18'  # Compliance Administrator
    'e6d1a23a-da11-4be4-9570-befc86d067a7'  # Compliance Data Administrator
    '31392ffb-586c-42d1-9346-e59415a2cc4e'  # Exchange Recipient Administrator
    '6e591065-9bad-43ed-90f3-e9424366d2f0'  # External ID User Flow Administrator
    '0f971eea-41eb-4569-a71e-57bb8a3eff1e'  # External ID User Flow Attribute Administrator
    '45d8d3c5-c802-45c6-b32a-1d70b5e1e86e'  # Identity Governance Administrator
    'b5a8dcf3-09d5-43a9-a639-8e29ef291470'  # Knowledge Administrator
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'  # SharePoint Administrator
    '69091246-20e8-4a56-aa4d-066075b2a7a8'  # Teams Administrator
)

# Retrieve all existing CA policies once to avoid a separate API call per policy
$script:existingPolicies = Get-MgIdentityConditionalAccessPolicy -All

Write-Host "`nDeploying Conditional Access policies..." -ForegroundColor Cyan

# BAS001 — Block legacy auth protocols (EAS, basic auth) which cannot satisfy MFA
New-CAPolicyIfNotExists -DisplayName 'BAS-001-2606-Block-AllResources-AllUsers-LegacyAuth' -BodyParameter @{
    DisplayName   = 'BAS-001-2606-Block-AllResources-AllUsers-LegacyAuth'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications   = @{ includeApplications = 'All' }
        Users          = @{ includeUsers = 'All'; excludeUsers = @($breakGlass1Id, $breakGlass2Id) }
        clientAppTypes = @('exchangeActiveSync', 'other')
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# BAS002 — Require MFA for all users; excludes Directory Sync accounts (d29b2b05-...) which cannot do MFA
New-CAPolicyIfNotExists -DisplayName 'BAS-002-2606-Allow-AllResources-AllUsers-RequireMFA' -BodyParameter @{
    DisplayName   = 'BAS-002-2606-Allow-AllResources-AllUsers-RequireMFA'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = @{ includeApplications = 'All' }
        Users        = @{
            includeUsers = 'All'
            excludeUsers = @($breakGlass1Id, $breakGlass2Id)
            excludeRoles = 'd29b2b05-8046-44ba-8758-1e26182fcf32'  # Directory Synchronization Accounts
        }
    }
    GrantControls = @{ BuiltInControls = @('mfa'); Operator = 'OR' }
}

# BAS003 — Block any platform not in the explicit allowlist (e.g., ChromeOS, unknown OS)
New-CAPolicyIfNotExists -DisplayName 'BAS-003-2606-Block-AllResources-AllUsers-UnsupportedPlatform' -BodyParameter @{
    DisplayName   = 'BAS-003-2606-Block-AllResources-AllUsers-UnsupportedPlatform'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = @{ includeApplications = 'All' }
        Users        = @{ includeUsers = 'All'; excludeUsers = @($breakGlass1Id, $breakGlass2Id) }
        Platforms    = @{
            includePlatforms = @('all')
            excludePlatforms = @('android', 'iOS', 'windowsPhone', 'windows', 'macOS', 'linux')
        }
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# BAS004 — Enforce short session lifetime and no persistent browser for unmanaged/non-compliant devices
New-CAPolicyIfNotExists -DisplayName 'BAS-004-2606-Allow-AllResources-AllUsers-NoPersistentBrowser' -BodyParameter @{
    DisplayName     = 'BAS-004-2606-Allow-AllResources-AllUsers-NoPersistentBrowser'
    State           = 'EnabledForReportingButNotEnforced'
    Conditions      = @{
        Applications = @{ includeApplications = 'All' }
        Users        = @{ includeUsers = 'All'; excludeUsers = @($breakGlass1Id, $breakGlass2Id) }
        Devices      = @{
            deviceFilter = @{
                mode = 'include'
                rule = 'device.trustType -ne "ServerAD" -or device.isCompliant -ne True'
            }
        }
    }
    GrantControls   = @{ Operator = 'OR' }
    SessionControls = @{
        persistentBrowser = @{ mode = 'never'; isEnabled = $true }
        signInFrequency   = @{ value = 1; type = 'hours'; isEnabled = $true }
    }
}

# BAS005 — Step-up MFA every sign-in when Identity Protection detects a high-risk sign-in
New-CAPolicyIfNotExists -DisplayName 'BAS-005-2606-Allow-AllResources-AllUsers-MFAforRiskySignIns' -BodyParameter @{
    DisplayName     = 'BAS-005-2606-Allow-AllResources-AllUsers-MFAforRiskySignIns'
    State           = 'EnabledForReportingButNotEnforced'
    Conditions      = @{
        Applications     = @{ includeApplications = 'All' }
        Users            = @{ includeUsers = 'All'; excludeUsers = @($breakGlass1Id, $breakGlass2Id) }
        signInRiskLevels = @('high')
    }
    GrantControls   = @{ BuiltInControls = @('mfa'); Operator = 'OR' }
    SessionControls = @{
        signInFrequency = @{
            authenticationType = 'primaryAndSecondaryAuthentication'
            frequencyInterval  = 'everyTime'
            isEnabled          = $true
        }
    }
}

# BAS006 — Force MFA + password change for users flagged as high user risk
# passwordChange remediates the risk itself; signInFrequency=everyTime is not valid with userRiskLevels
New-CAPolicyIfNotExists -DisplayName 'BAS-006-2606-Allow-AllResources-AllUsers-PasswordChangeForHighRiskUsers' -BodyParameter @{
    DisplayName   = 'BAS-006-2606-Allow-AllResources-AllUsers-PasswordChangeForHighRiskUsers'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications   = @{ includeApplications = 'All' }
        Users          = @{ includeUsers = 'All'; excludeUsers = @($breakGlass1Id, $breakGlass2Id) }
        userRiskLevels = @('high')
    }
    GrantControls = @{ BuiltInControls = @('mfa', 'passwordChange'); Operator = 'AND' }
}

# BAS007 — Block all standard users (not guests, handled by PER policies) on non-compliant devices
New-CAPolicyIfNotExists -DisplayName 'BAS-007-2606-Block-AllResources-AllUsers-RequireCompliantDevice' -BodyParameter @{
    DisplayName   = 'BAS-007-2606-Block-AllResources-AllUsers-RequireCompliantDevice'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = @{ includeApplications = 'All' }
        Users        = @{
            includeUsers = 'All'
            excludeUsers = @($breakGlass1Id, $breakGlass2Id, 'GuestsOrExternalUsers')
        }
        Devices      = @{ deviceFilter = @{ mode = 'exclude'; rule = 'device.isCompliant -eq True' } }
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# BAS008 — Block device code flow and authentication transfer to prevent token hijacking via these flows
New-CAPolicyIfNotExists -DisplayName 'BAS-008-2606-Block-AllResources-AllUsers-DeviceFlowAuthenticationTransfer' -BodyParameter @{
    DisplayName   = 'BAS-008-2606-Block-AllResources-AllUsers-DeviceFlowAuthenticationTransfer'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications        = @{ includeApplications = 'All' }
        Users               = @{ includeUsers = 'All'; excludeUsers = @($breakGlass1Id, $breakGlass2Id) }
        AuthenticationFlows = @{ transferMethods = 'deviceCodeFlow,authenticationTransfer' }
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# BAS009 — Block O365 for users with an elevated Insider Risk score (Purview integration)
New-CAPolicyIfNotExists -DisplayName 'BAS-009-2606-Block-O365Apps-AllUsers-ElevatedInsiderRisk' -BodyParameter @{
    DisplayName   = 'BAS-009-2606-Block-O365Apps-AllUsers-ElevatedInsiderRisk'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications      = @{ includeApplications = 'Office365' }
        Users             = @{ includeUsers = 'All'; excludeUsers = @($breakGlass1Id, $breakGlass2Id) }
        InsiderRiskLevels = 'elevated'
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# BAS010 — Application Enforced Restrictions for Office 365 so SharePoint/Exchange honour CA app control
New-CAPolicyIfNotExists -DisplayName 'BAS-010-2606-Allow-O365-AllUsers-ApplicationEnforcedRestrictions' -BodyParameter @{
    DisplayName     = 'BAS-010-2606-Allow-O365-AllUsers-ApplicationEnforcedRestrictions'
    State           = 'EnabledForReportingButNotEnforced'
    Conditions      = @{
        Applications   = @{ includeApplications = @('Office365') }
        Users          = @{ includeUsers = @('All'); excludeUsers = @($breakGlass1Id, $breakGlass2Id) }
        clientAppTypes = @('all')
    }
    SessionControls = @{
        applicationEnforcedRestrictions = @{ isEnabled = $true }
    }
}

# BAS011 — Require MFA to register security info from untrusted networks (prevents attacker-controlled registration)
New-CAPolicyIfNotExists -DisplayName 'BAS-011-2606-Allow-AllResources-AllUsers-SecureSecurityInfoRegistration' -BodyParameter @{
    DisplayName   = 'BAS-011-2606-Allow-AllResources-AllUsers-SecureSecurityInfoRegistration'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = @{ includeUserActions = 'urn:user:registersecurityinfo' }
        Users        = @{
            includeUsers = 'All'
            excludeUsers = @($breakGlass1Id, $breakGlass2Id, 'GuestsOrExternalUsers')
            excludeRoles = '62e90394-69f5-4237-9190-012177145e10'  # Global Admins manage this policy; exclude to avoid lockout
        }
        Locations    = @{ includeLocations = 'All'; excludeLocations = 'AllTrusted' }
    }
    GrantControls = @{ BuiltInControls = @('mfa'); Operator = 'OR' }
}

# BAS012 — Enable SharePoint/OneDrive app-enforced restrictions for O365; limits download on unmanaged devices
New-CAPolicyIfNotExists -DisplayName 'BAS-012-2606-Allow-O365Apps-AllUsers-ApplicationEnforcedRestrictions' -BodyParameter @{
    DisplayName     = 'BAS-012-2606-Allow-O365Apps-AllUsers-ApplicationEnforcedRestrictions'
    State           = 'EnabledForReportingButNotEnforced'
    Conditions      = @{
        Applications = @{ includeApplications = 'Office365' }
        Users        = @{ includeUsers = 'All'; excludeUsers = @($breakGlass1Id, $breakGlass2Id) }
    }
    GrantControls   = @{ BuiltInControls = @('mfa'); Operator = 'OR' }
    SessionControls = @{ applicationEnforcedRestrictions = @{ isEnabled = $true } }
}


# Reusable app filter for apps tagged Highly Confidential or Confidential via custom security attribute
$chcAppFilter = @{
    applicationFilter = @{
        mode = 'include'
        rule = 'CustomSecurityAttribute.DataSensitivity_Classification -contains "Highly Confidential" -or CustomSecurityAttribute.DataSensitivity_Classification -contains "Confidential"'
    }
}

# DLP001 — Require phishing-resistant MFA to access CHC-classified apps (stronger than BAS002)
New-CAPolicyIfNotExists -DisplayName 'DLP-001-2606-Allow-AllApps-AllUsers-PhishingResistantMFAforCHCData' -BodyParameter @{
    DisplayName   = 'DLP-001-2606-Allow-AllApps-AllUsers-PhishingResistantMFAforCHCData'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = $chcAppFilter
        Users        = @{ includeUsers = 'All'; excludeUsers = @($breakGlass1Id, $breakGlass2Id) }
    }
    GrantControls = @{
        Operator               = 'OR'
        authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000004' }
    }
}

# DLP002 — Require device with extensionAttribute1=CSC and compliance for CHC-classified apps
New-CAPolicyIfNotExists -DisplayName 'DLP-002-2606-Block-AllApps-AllUsers-RequireCompliantSecureDeviceforCHCData' -BodyParameter @{
    DisplayName   = 'DLP-002-2606-Block-AllApps-AllUsers-RequireCompliantSecureDeviceforCHCData'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = $chcAppFilter
        Users        = @{ includeUsers = 'All'; excludeUsers = @($breakGlass1Id, $breakGlass2Id) }
        Devices      = @{
            deviceFilter = @{
                mode = 'exclude'
                rule = 'device.extensionAttribute1 -eq "CSC" -and device.isCompliant -eq True'
            }
        }
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# DLP003 — Restrict CHC-classified app access to allowed countries only (data sovereignty enforcement)
New-CAPolicyIfNotExists -DisplayName 'DLP-003-2606-Block-AllApps-AllUsers-AllowSpecificCountriesOnlyForCHCData' -BodyParameter @{
    DisplayName   = 'DLP-003-2606-Block-AllApps-AllUsers-AllowSpecificCountriesOnlyForCHCData'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = $chcAppFilter
        Users        = @{ includeUsers = 'All'; excludeUsers = @($breakGlass1Id, $breakGlass2Id) }
        Locations    = @{ includeLocations = 'All'; excludeLocations = $chcAllowedCountriesId }
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# DLP004 — Guests have no legitimate need to access Confidential/HC-classified applications
New-CAPolicyIfNotExists -DisplayName 'DLP-004-2606-Block-AllApps-Guests-AccessToCHCData' -BodyParameter @{
    DisplayName   = 'DLP-004-2606-Block-AllApps-Guests-BlockAccessToCHCData'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = $chcAppFilter
        Users        = @{ includeUsers = 'GuestsOrExternalUsers'; excludeUsers = @($breakGlass1Id, $breakGlass2Id) }
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# PER001 — Require phishing-resistant MFA (FIDO2/WHfB) for all admin roles and secure workstation users
New-CAPolicyIfNotExists -DisplayName 'PER-001-2606-Allow-AllApps-Admins-PhishingResistantMFA' -BodyParameter @{
    DisplayName   = 'PER-001-2606-Allow-AllApps-Admins-PhishingResistantMFA'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = @{ includeApplications = 'All' }
        Users        = @{
            excludeUsers  = @($breakGlass1Id, $breakGlass2Id)
            includeGroups = @($secureGroupId)
            includeRoles  = $adminRoleIds
        }
    }
    GrantControls = @{
        Operator               = 'OR'
        authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000004' }  # Built-in phishing-resistant strength
    }
}

# PER002 — Admin sign-ins are only allowed from approved countries; excludes device/enrollment flows that must work globally
$per002ExcludeApps = Select-ExistingAppIds -AppIds @(
    '0af06dc6-e4b5-4f28-818e-e78e62d137a5'  # Azure Virtual Desktop
    '9cdead84-a844-4324-93f2-b2e6bb768d07'  # Device Registration Service
    'a4a365df-50f1-4397-bc59-1a1564b8bb9c'  # Microsoft Intune Enrollment
    '270efc09-cd0d-444b-a71f-39af4910ec45'  # Windows Hello for Business Provisioning
)
New-CAPolicyIfNotExists -DisplayName 'PER-002-2606-Block-AllApps-Admins-AllowSpecificCountriesOnly' -BodyParameter @{
    DisplayName   = 'PER-002-2606-Block-AllApps-Admins-AllowSpecificCountriesOnly'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = @{
            includeApplications = 'All'
            excludeApplications = $per002ExcludeApps
        }
        Users        = @{ excludeUsers = @($breakGlass1Id, $breakGlass2Id); includeRoles = $adminRoleIds }
        Locations    = @{ includeLocations = 'All'; excludeLocations = $adminAllowedCountriesId }
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# PER003 — Block admin sign-in when Identity Protection signals a high sign-in risk score
New-CAPolicyIfNotExists -DisplayName 'PER-003-2606-Block-AllApps-Admins-HighSignInRisk' -BodyParameter @{
    DisplayName   = 'PER-003-2606-Block-AllApps-Admins-HighSignInRisk'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications     = @{ includeApplications = 'All' }
        Users            = @{ excludeUsers = @($breakGlass1Id, $breakGlass2Id); includeRoles = $adminRoleIds }
        signInRiskLevels = @('high')
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# PER004 — Block admin sign-in when the user account itself is flagged as high risk (compromised credentials)
New-CAPolicyIfNotExists -DisplayName 'PER-004-2606-Block-AllApps-Admins-HighUserRisk' -BodyParameter @{
    DisplayName   = 'PER-004-2606-Block-AllApps-Admins-HighUserRisk'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications   = @{ includeApplications = 'All' }
        Users          = @{ excludeUsers = @($breakGlass1Id, $breakGlass2Id); includeRoles = $adminRoleIds }
        userRiskLevels = @('high')
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# PER005 — Block admin roles from signing in on any non-compliant device
New-CAPolicyIfNotExists -DisplayName 'PER-005-2606-Block-AllApps-Admins-RequireCompliantDevice' -BodyParameter @{
    DisplayName   = 'PER-005-2606-Block-AllApps-Admins-RequireCompliantDevice'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = @{ includeApplications = 'All' }
        Users        = @{ excludeUsers = @($breakGlass1Id, $breakGlass2Id); includeRoles = $adminRoleIds }
        Devices      = @{ deviceFilter = @{ mode = 'exclude'; rule = 'device.isCompliant -eq True' } }
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# PER006 — Admins and secure workstation users must use a PAW (extensionAttribute1=PAW) that is compliant
New-CAPolicyIfNotExists -DisplayName 'PER-006-2606-Block-AllApps-Admins-RequireSecureCompliantDevice' -BodyParameter @{
    DisplayName   = 'PER-006-2606-Block-AllApps-Admins-RequireSecureCompliantDevice'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = @{ includeApplications = 'All' }
        Users        = @{
            excludeUsers  = @($breakGlass1Id, $breakGlass2Id)
            includeGroups = @($secureGroupId)
            includeRoles  = $adminRoleIds
        }
        Devices      = @{
            deviceFilter = @{
                mode = 'exclude'
                rule = 'device.extensionAttribute1 -eq "PAW" -and device.isCompliant -eq True'
            }
        }
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# PER007 — Block service principals with high Identity Protection risk (workload identity policy).
# includeAgentIdServicePrincipals was retired when CAforAgentID went GA (May/Jun 2026).
# The GA workload identity structure uses clientApplications.includeServicePrincipals.
# No Users condition — its presence makes a policy "user-based" and disallows servicePrincipalRiskLevels.
$per007Name = 'PER-007-2606-Block-AllApps-Agents-HighRisk'
if ($script:existingPolicies.DisplayName -contains $per007Name) {
    Write-Host "  Skipping (already exists): $per007Name" -ForegroundColor DarkGray
} else {
    try {
        Invoke-MgGraphRequest -Method POST -Uri 'beta/identity/conditionalAccess/policies' `
            -OutputType PSObject -ErrorAction Stop -Body @{
                displayName   = $per007Name
                state         = 'EnabledForReportingButNotEnforced'
                conditions    = @{
                    applications               = @{ includeApplications = @('All') }
                    servicePrincipalRiskLevels = @('high')
                    clientApplications         = @{
                        includeServicePrincipals = @('ServicePrincipalsInMyTenant')
                        excludeServicePrincipals = @()
                    }
                }
                grantControls = @{ builtInControls = @('block'); operator = 'OR' }
            } | Out-Null
        Write-Host "  Created: $per007Name" -ForegroundColor Green
    } catch {
        if ($_ -match '1149') {
            Write-Host "  [SKIP] $per007Name requires Microsoft Entra Workload Identities Premium license." -ForegroundColor Yellow
            Write-Host "         Assign the license (Entra Workload ID Premium) to the tenant and re-run to create this policy." -ForegroundColor Yellow
        } else {
            Write-Warning "Failed to create ${per007Name}: $_"
        }
    }
}

# PER008 — Block users with high sign-in risk when acting through AI agent delegation.
# agents.includeAgentUsers is PrivatePreview:CAAgentContext (available until Aug 2026 deprecation).
# If the tenant is not enrolled in that preview the API returns 400; the catch block creates
# the policy without the agents scope so deployment is not blocked.
$per008Name = 'PER-008-2606-BlockAllApps-AgentUsers-HighRisk'
if ($script:existingPolicies.DisplayName -contains $per008Name) {
    Write-Host "  Skipping (already exists): $per008Name" -ForegroundColor DarkGray
} else {
    $per008Body = @{
        displayName   = $per008Name
        state         = 'EnabledForReportingButNotEnforced'
        conditions    = @{
            applications     = @{ includeApplications = @('All') }
            users            = @{
                includeUsers = @('All')
                excludeUsers = @($breakGlass1Id, $breakGlass2Id)
            }
            clientAppTypes   = @('all')
            signInRiskLevels = @('high')
            agents           = @{
                includeAgentUsers = @('All')
                excludeAgentUsers = @()
            }
        }
        grantControls = @{ builtInControls = @('block'); operator = 'OR' }
    }
    try {
        Invoke-MgGraphRequest -Method POST -Uri 'beta/identity/conditionalAccess/policies' `
            -OutputType PSObject -ErrorAction Stop -Body $per008Body | Out-Null
        Write-Host "  Created: $per008Name (with agents scope)" -ForegroundColor Green
    } catch {
        # 1263 = Users condition not allowed in agent user policy type (PrivatePreview:CAAgentContext not enrolled)
        # 1149 = Workload Identities Premium license required
        if ($_ -match '1263') {
            Write-Host "  [WARN] ${per008Name}: 'agents' condition requires PrivatePreview:CAAgentContext enrollment (not active in this tenant)." -ForegroundColor Yellow
            Write-Host "         Falling back to sign-in risk policy without agents scope." -ForegroundColor Yellow
        } elseif ($_ -match '1149') {
            Write-Host "  [SKIP] $per008Name requires Microsoft Entra Workload Identities Premium license." -ForegroundColor Yellow
            Write-Host "         Assign the license and re-run to create this policy." -ForegroundColor Yellow
            return
        } else {
            Write-Host "  [WARN] ${per008Name}: unexpected error creating with agents scope - falling back. Error: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        $per008Body.conditions.Remove('agents')
        try {
            Invoke-MgGraphRequest -Method POST -Uri 'beta/identity/conditionalAccess/policies' `
                -OutputType PSObject -ErrorAction Stop -Body $per008Body | Out-Null
            Write-Host "  Created: $per008Name (sign-in risk only, no agents scope)" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to create ${per008Name}: $($_.Exception.Message)"
        }
    }
}

# PER009 — External users may only use the approved VDI app (0af06dc6-...); all other apps are blocked
New-CAPolicyIfNotExists -DisplayName 'PER-009-2606-Block-AllApps-Externals-RequireCompliantSecureVDI' -BodyParameter @{
    DisplayName   = 'PER-009-2606-Block-AllApps-Externals-RequireCompliantSecureVDI'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = @{
            includeApplications = 'All'
            excludeApplications = @('0af06dc6-e4b5-4f28-818e-e78e62d137a5')  # Approved VDI/AVD application
        }
        Users        = @{ includeUsers = 'GuestsOrExternalUsers'; excludeUsers = @($breakGlass1Id, $breakGlass2Id) }
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# PER010 — Prevent guests from reaching any Microsoft Admin Portal (Azure, M365, Intune, etc.)
New-CAPolicyIfNotExists -DisplayName 'PER-010-2606-Block-AdminPortals-Guests-AdminPortals' -BodyParameter @{
    DisplayName   = 'PER-010-2606-Block-AdminPortals-Guests-AdminPortals'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = @{ includeApplications = 'MicrosoftAdminPortals' }
        Users        = @{ includeUsers = 'GuestsOrExternalUsers'; excludeUsers = @($breakGlass1Id, $breakGlass2Id) }
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

#endregion

Write-Host "CA Policy Framework deployment complete." -ForegroundColor Cyan
