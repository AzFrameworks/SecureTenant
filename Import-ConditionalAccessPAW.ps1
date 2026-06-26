#Requires -Version 5.1
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

$script:existingPolicies = $null

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

#region Module Import
# Modules are installed by CAPolicyFrameworkV2.ps1 — only imported here

@(
    'Microsoft.Graph.Authentication'
    'Microsoft.Graph.Groups'
    'Microsoft.Graph.Identity.SignIns'
    'Microsoft.Graph.Identity.DirectoryManagement'
) | ForEach-Object { Import-Module $_ -ErrorAction Stop }

#endregion

#region Graph Connection

Connect-MgGraph -Scopes @(
    'Policy.Read.All'
    'Policy.ReadWrite.ConditionalAccess'
    'Group.ReadWrite.All'
    'User.Read.All'
    'Domain.Read.All'
) -NoWelcome -ErrorAction Stop

$context = Get-MgContext
Write-Host "Connected as: $($context.Account) | Tenant: $($context.TenantId)" -ForegroundColor Green

#endregion

#region Break Glass Accounts
# Break glass accounts must already exist (created by CAPolicyFrameworkV2.ps1)

$breakGlassDomain = (Get-MgDomain | Where-Object { $_.IsDefault }).Id
$bgUPN1 = "BreakGlass1@$breakGlassDomain"
$bgUPN2 = "BreakGlass2@$breakGlassDomain"

function Get-UserIdByUpn {
    param([string]$Upn)
    try {
        $r = Invoke-MgGraphRequest -Method GET `
                 -Uri "v1.0/users/$([System.Uri]::EscapeDataString($Upn))?`$select=id" `
                 -OutputType PSObject -ErrorAction Stop
        return $r.id
    } catch {
        return $null
    }
}

$breakGlass1Id = Get-UserIdByUpn -Upn $bgUPN1
$breakGlass2Id = Get-UserIdByUpn -Upn $bgUPN2

if ([string]::IsNullOrEmpty($breakGlass1Id) -or [string]::IsNullOrEmpty($breakGlass2Id)) {
    Write-Error "Break glass accounts not found (BG1='$breakGlass1Id' BG2='$breakGlass2Id'). Run CAPolicyFrameworkV2.ps1 first to create them."
    exit 1
}

Write-Host "Break Glass 1: $bgUPN1 ($breakGlass1Id)" -ForegroundColor Green
Write-Host "Break Glass 2: $bgUPN2 ($breakGlass2Id)" -ForegroundColor Green

#endregion

#region PAW Groups

function New-SecGroupIfNotExists {
    param(
        [string]$DisplayName,
        [string]$MailNickname,
        [string]$Description
    )
    $existing = Get-MgGroup -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "Group '$DisplayName' already exists." -ForegroundColor Green
        return $existing.Id
    }
    Write-Host "Creating group '$DisplayName'..." -ForegroundColor Yellow
    try {
        return (New-MgGroup -BodyParameter @{
            DisplayName     = $DisplayName
            Description     = $Description
            MailEnabled     = $false
            SecurityEnabled = $true
            MailNickName    = $MailNickname
        }).Id
    } catch {
        Write-Error "Failed to create group '${DisplayName}': $_"
        return $null
    }
}

$pawUsersGroupId = New-SecGroupIfNotExists -DisplayName 'PAW-Global-Users' `
                       -MailNickname 'PAWGlobalUsers' `
                       -Description 'Members who use Privileged Access Workstations'

if ([string]::IsNullOrEmpty($pawUsersGroupId)) {
    Write-Error "PAW-Global-Users group ID could not be resolved. Cannot continue."
    exit 1
}

#endregion

#region Named Location

# ACTION REQUIRED: replace 'AQ' (Antarctica) with the actual country codes to block after deployment
$existingPawLoc = Get-MgIdentityConditionalAccessNamedLocation |
    Where-Object { $_.DisplayName -eq 'PAW-Global-Blocked-SignIn-Locations' }
if (-not $existingPawLoc) {
    Write-Host "Creating named location 'PAW-Global-Blocked-SignIn-Locations'..." -ForegroundColor Yellow
    try {
        $pawBlockedLocationsId = (New-MgIdentityConditionalAccessNamedLocation -BodyParameter @{
            '@odata.type'                     = '#microsoft.graph.countryNamedLocation'
            DisplayName                       = 'PAW-Global-Blocked-SignIn-Locations'
            CountriesAndRegions               = @('AQ')
            IncludeUnknownCountriesAndRegions = $false
        }).Id
        # Named locations take a few seconds to replicate before CA policies can reference them
        Write-Host "Waiting for named location to propagate..." -ForegroundColor Yellow
        Start-Sleep -Seconds 15
    } catch {
        Write-Error "Failed to create PAW named location: $_"
        exit 1
    }
} else {
    $pawBlockedLocationsId = $existingPawLoc.Id
    Write-Host "Named location 'PAW-Global-Blocked-SignIn-Locations' already exists." -ForegroundColor Green
}

#endregion

#region Authentication Strength

$existingAuthStrength = Get-MgPolicyAuthenticationStrengthPolicy |
    Where-Object { $_.DisplayName -eq 'PAW-Global-Auth-Strength' }
if (-not $existingAuthStrength) {
    Write-Host "Creating authentication strength 'PAW-Global-Auth-Strength'..." -ForegroundColor Yellow
    try {
        $pawAuthStrengthId = (New-MgPolicyAuthenticationStrengthPolicy -BodyParameter @{
            DisplayName         = 'PAW-Global-Auth-Strength'
            Description         = 'Requires Windows Hello for Business or FIDO2 for PAW users'
            AllowedCombinations = @('windowsHelloForBusiness', 'fido2')
        }).Id
    } catch {
        Write-Error "Failed to create PAW authentication strength: $_"
        exit 1
    }
} else {
    $pawAuthStrengthId = $existingAuthStrength.Id
    Write-Host "Authentication strength 'PAW-Global-Auth-Strength' already exists." -ForegroundColor Green
}

if ([string]::IsNullOrEmpty($pawAuthStrengthId)) {
    Write-Error "PAW authentication strength ID could not be resolved. Cannot continue."
    exit 1
}

#endregion

#region Conditional Access Policies

$script:existingPolicies = Get-MgIdentityConditionalAccessPolicy -All

$pawInclude   = @($pawUsersGroupId)
$bgExclude    = @($breakGlass1Id, $breakGlass2Id)

$pawAdminRoleIds = @(
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'  # Application Administrator
    'c4e39bd9-1100-46d3-8c65-fb160da0071f'  # Authentication Administrator
    '0526716b-113d-4c15-b2c8-68e3c22b9f80'  # Authentication Policy Administrator
    '158c047a-c907-4556-b7ef-446551a6b5f7'  # Cloud Application Administrator
    '7698a772-787b-4ac8-901f-60d6b08affd2'  # Cloud Device Administrator
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'  # Conditional Access Administrator
    'cf1c38e5-3621-4004-a7cb-879624dced7c'  # Compliance Administrator
    'ecb2c6bf-0ab6-418e-bd87-7986f8d63bbe'  # Compliance Data Administrator
    '9360feb5-f418-4baa-8175-e2a00bac4301'  # Exchange Administrator
    '29232cdf-9323-42fd-ade2-1d097af3e4de'  # Exchange Recipient Administrator
    'be2f45a1-457d-42af-a067-6ec1fa63bc45'  # External ID User Flow Administrator
    '59d46f88-662b-457b-bceb-5c3809e5908f'  # External ID Attribute Administrator
    '62e90394-69f5-4237-9190-012177145e10'  # Global Administrator
    'f2ef992c-3afb-46b9-b7cf-a126ee74c451'  # Global Reader
    'fdd7a751-b60b-444a-984c-02652fe8fa1c'  # Groups Administrator
    '729827e3-9c14-49f7-bb1b-9608f156bbb8'  # Helpdesk Administrator
    '8329153b-31d0-4727-b945-745eb3bc5f31'  # Hybrid Identity Administrator
    '194ae4cb-b126-40b2-bd5b-6091b380977d'  # Identity Governance Administrator
    '3a2c62db-5318-420d-8d74-23affee5d9d5'  # Intune Administrator
    'aaf43236-0c0d-4d5f-883a-6955382ac081'  # Knowledge Administrator
    '966707d0-3269-4727-9be2-8c3a10f19b9d'  # Password Administrator
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'  # Privileged Authentication Administrator
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'  # Privileged Role Administrator
    '5d6b6bb7-de71-4623-b4af-96380a352509'  # Security Administrator
    '5f2222b1-57c3-48ba-8ad5-d4759f1fde6f'  # Security Operator
    'fe930be7-5e62-47db-91af-98c3a49a38b1'  # SharePoint Administrator
    '422218e4-db15-4ef9-bbe0-8afb41546d79'  # Teams Administrator
    'e8611ab8-c189-46e8-94e1-60213ab1f814'  # User Administrator
    '25a516ed-2fa0-40ea-a2d0-12923a21473a'  # Application Developer
)

Write-Host "`nDeploying PAW Conditional Access policies..." -ForegroundColor Cyan

# PAW01 — Block legacy auth (EAS, basic auth) for PAW users; these protocols cannot satisfy MFA
New-CAPolicyIfNotExists -DisplayName 'PAW-Global-2606-Block-Legacy-Auth' -BodyParameter @{
    DisplayName   = 'PAW-Global-2606-Block-Legacy-Auth'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications   = @{ includeApplications = 'All' }
        Users          = @{ includeGroups = $pawInclude; excludeUsers = $bgExclude }
        clientAppTypes = @('exchangeActiveSync', 'other')
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# PAW02 — PAW devices must be Windows; block sign-in from any other OS platform
New-CAPolicyIfNotExists -DisplayName 'PAW-Global-2606-Block-Unsupported-OS' -BodyParameter @{
    DisplayName   = 'PAW-Global-2606-Block-Unsupported-OS'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = @{ includeApplications = 'All' }
        Users        = @{ includeGroups = $pawInclude; excludeUsers = $bgExclude }
        Platforms    = @{
            includePlatforms = @('all')
            excludePlatforms = @('windows')
        }
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# PAW03 — Block sign-ins from geographies listed in PAW-Global-Blocked-SignIn-Locations
# ACTION REQUIRED: populate PAW-Global-Blocked-SignIn-Locations with the actual blocked countries
New-CAPolicyIfNotExists -DisplayName 'PAW-Global-2606-Block-Unsupported-SignIn-Locations' -BodyParameter @{
    DisplayName   = 'PAW-Global-2606-Block-Unsupported-SignIn-Locations'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = @{ includeApplications = 'All' }
        Users        = @{ includeGroups = $pawInclude; excludeUsers = $bgExclude }
        Locations    = @{ includeLocations = @($pawBlockedLocationsId) }
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# PAW04 — Block PAW users when Identity Protection detects a high or medium sign-in risk
New-CAPolicyIfNotExists -DisplayName 'PAW-Global-2606-Block-Unsupported-SignIn-Risk' -BodyParameter @{
    DisplayName   = 'PAW-Global-2606-Block-Unsupported-SignIn-Risk'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications     = @{ includeApplications = 'All' }
        Users            = @{ includeGroups = $pawInclude; excludeUsers = $bgExclude }
        signInRiskLevels = @('high', 'medium')
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# PAW05 — Require MFA + password change when Identity Protection flags a PAW user as high user risk
New-CAPolicyIfNotExists -DisplayName 'PAW-Global-2606-Block-Unsupported-User-Risk' -BodyParameter @{
    DisplayName   = 'PAW-Global-2606-Block-Unsupported-User-Risk'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications   = @{ includeApplications = 'All' }
        Users          = @{ includeGroups = $pawInclude; excludeUsers = $bgExclude }
        userRiskLevels = @('high')
    }
    GrantControls = @{ BuiltInControls = @('mfa', 'passwordChange'); Operator = 'AND' }
}

# PAW06 — Require MFA to register or join devices; prevents rogue device enrollment from PAW users
New-CAPolicyIfNotExists -DisplayName 'PAW-Global-2606-Allow-Require-MFA-to-Azure-AD-Join' -BodyParameter @{
    DisplayName   = 'PAW-Global-2606-Allow-Require-MFA-to-Azure-AD-Join'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = @{ includeUserActions = 'urn:user:registerdevice' }
        Users        = @{ includeGroups = $pawInclude; excludeUsers = $bgExclude }
    }
    GrantControls = @{ BuiltInControls = @('mfa'); Operator = 'OR' }
}

# PAW07 — Enforce 8-hour session limit and no persistent browser for admin roles on PAW
# No GrantControls — session management only, access is controlled by other PAW policies
New-CAPolicyIfNotExists -DisplayName 'PAW-Global-2606-Allow-Session-Management' -BodyParameter @{
    DisplayName     = 'PAW-Global-2606-Allow-Session-Management'
    State           = 'EnabledForReportingButNotEnforced'
    Conditions      = @{
        Applications = @{ includeApplications = 'All' }
        Users        = @{
            includeGroups = $pawInclude
            excludeUsers = $bgExclude
            includeRoles  = $pawAdminRoleIds
        }
    }
    SessionControls = @{
        signInFrequency   = @{
            value              = 8
            type               = 'hours'
            frequencyInterval  = 'timeBased'
            authenticationType = 'primaryAndSecondaryAuthentication'
            isEnabled          = $true
        }
        persistentBrowser = @{ mode = 'never'; isEnabled = $true }
    }
}

# PAW08 — Block device code flow and authentication transfer for PAW users (prevent token hijacking)
New-CAPolicyIfNotExists -DisplayName 'PAW-Global-2606-Block-Authentication-Flows' -BodyParameter @{
    DisplayName   = 'PAW-Global-2606-Block-Authentication-Flows'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications        = @{ includeApplications = 'All' }
        Users               = @{ includeGroups = $pawInclude; excludeUsers = $bgExclude }
        AuthenticationFlows = @{ transferMethods = 'deviceCodeFlow,authenticationTransfer' }
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# PAW09 — Block all users (except PAW-Global-Users and break glass) from signing in on a PAW device
# Enforces the rule that only designated PAW users may use extensionAttribute1="PAW" devices
New-CAPolicyIfNotExists -DisplayName 'PAW-Global-2606-Block-CloudApp-All-Non-PAW-Users' -BodyParameter @{
    DisplayName   = 'PAW-Global-2606-Block-CloudApp-All-Non-PAW-Users'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = @{ includeApplications = 'All' }
        Users        = @{
            includeUsers  = 'All'
            excludeGroups = @($pawUsersGroupId)
            excludeUsers  = $bgExclude
        }
        Devices      = @{
            deviceFilter = @{
                mode = 'include'
                rule = 'device.extensionAttribute1 -eq "PAW"'
            }
        }
        Platforms    = @{ includePlatforms = @('all') }
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# PAW10 — Require phishing-resistant auth (WHfB or FIDO2) for PAW admin roles on Microsoft Admin Portals
New-CAPolicyIfNotExists -DisplayName 'PAW-Global-2606-Allow-Require-Phishing-Resistant-Auth-Microsoft-Admin-Portals' -BodyParameter @{
    DisplayName   = 'PAW-Global-2606-Allow-Require-Phishing-Resistant-Auth-Microsoft-Admin-Portals'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = @{ includeApplications = 'MicrosoftAdminPortals' }
        Users        = @{
            includeGroups = $pawInclude
            excludeUsers = $bgExclude
            includeRoles  = $pawAdminRoleIds
        }
    }
    GrantControls = @{
        Operator               = 'OR'
        authenticationStrength = @{ id = $pawAuthStrengthId }
    }
}

#endregion

Write-Host "`nPAW Conditional Access policy deployment complete." -ForegroundColor Cyan

Disconnect-MgGraph | Out-Null
Write-Host "Disconnected." -ForegroundColor Gray
