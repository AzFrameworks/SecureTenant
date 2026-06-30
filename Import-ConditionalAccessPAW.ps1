#Requires -Version 5.1
<#
.SYNOPSIS
    Deploys PAW Conditional Access policies for the PAWCSM framework.
.PARAMETER PawAuthContextId
    Optional. ID of an existing authentication context slot (e.g. 'c3') to adopt as
    'PAW-Role-Activation'. Required when all c1-c25 slots are already in use and none
    is named 'PAW-Role-Activation'. Run the script once without this parameter to see
    a list of all existing contexts if an error occurs.
.PARAMETER TenantId
    Optional tenant ID for explicit tenant targeting.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)][string] $PawAuthContextId,
    [Parameter(Mandatory = $false)][string] $TenantId
)

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

$connectParams = @{
    Scopes      = @(
        'Policy.Read.All'
        'Policy.ReadWrite.ConditionalAccess'
        'Group.ReadWrite.All'
        'User.Read.All'
        'Domain.Read.All'
    )
    NoWelcome   = $true
    ErrorAction = 'Stop'
}
if ($TenantId) { $connectParams['TenantId'] = $TenantId }
Connect-MgGraph @connectParams

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

#region Authentication Context

$rawAuthContexts  = Invoke-MgGraphRequest -Method GET `
    -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences'
# Normalize: the API may return null, a single object, or an array
$existingAuthContexts = @(if ($rawAuthContexts.value) { $rawAuthContexts.value } else { @() })

$existingPawContext = $existingAuthContexts | Where-Object { $_.displayName -eq 'PAW-Role-Activation' }

if ($existingPawContext) {
    $pawAuthContextId = $existingPawContext.id
    Write-Host "Authentication context 'PAW-Role-Activation' already exists (id: $pawAuthContextId)." -ForegroundColor Green
} else {
    # Resolve which slot to adopt: explicit parameter > first unclaimed > c1 (when none returned)
    if ($PawAuthContextId) {
        $targetId = $PawAuthContextId
    } elseif ($existingAuthContexts.Count -eq 0) {
        # Tenant returned no contexts — slots are uninitialized; start with c1
        $targetId = 'c1'
    } else {
        $unclaimed = $existingAuthContexts |
            Where-Object { -not $_.isAvailable -or [string]::IsNullOrEmpty($_.displayName) } |
            Select-Object -First 1
        if ($unclaimed) {
            $targetId = $unclaimed.id
        } else {
            $contextList = ($existingAuthContexts |
                ForEach-Object { "  $($_.id): $($_.displayName)" }) -join "`n"
            Write-Error ("All authentication context slots (c1-c25) are already in use.`n" +
                "Re-run with -PawAuthContextId <id> to adopt one of the existing slots:`n$contextList")
            exit 1
        }
    }

    $pawAuthContextId = $targetId
    Write-Host "Configuring authentication context slot '$pawAuthContextId' as 'PAW-Role-Activation'..." -ForegroundColor Yellow
    try {
        Invoke-MgGraphRequest -Method PATCH `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences/$pawAuthContextId" `
            -ContentType 'application/json' `
            -Body (@{
                displayName = 'PAW-Role-Activation'
                description = 'Requires PAW device for PIM role activation'
                isAvailable = $true
            } | ConvertTo-Json) | Out-Null
    } catch {
        Write-Error "Failed to configure PAW authentication context: $_"
        exit 1
    }
}

if ([string]::IsNullOrEmpty($pawAuthContextId)) {
    Write-Error 'PAW authentication context ID could not be resolved. Cannot continue.'
    exit 1
}

#endregion

#region Conditional Access Policies

$script:existingPolicies = Get-MgIdentityConditionalAccessPolicy -All

$pawInclude   = @($pawUsersGroupId)
$bgExclude    = @($breakGlass1Id, $breakGlass2Id)

$pawAdminRoleIds = @(
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

# PAW11 — Block PAW users and admin roles from accessing any app unless the sign-in originates
#          from a PAW device (extensionAttribute1 = "PAW"). MDM enrollment apps are excluded so
#          a device can be enrolled and provisioned before the PAW attribute is stamped.
$paw11ExcludeApps = @(
    'd4ebce55-015a-49b5-a083-c84d1797ae8c'  # Microsoft Intune
    '0000000a-0000-0000-c000-000000000000'  # Microsoft Intune Enrollment
    '45a330b1-b1ec-4cc1-9161-9f03992aa49f'  # Windows Hello for Business Provisioning
) | Where-Object {
    $appId = $_
    try {
        Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$appId')" `
            -ErrorAction Stop | Out-Null
        $true
    } catch { $false }
}
New-CAPolicyIfNotExists -DisplayName 'PAW-Global-2606-Block-Device-Filter' -BodyParameter @{
    DisplayName   = 'PAW-Global-2606-Block-Device-Filter'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = @{
            includeApplications = 'All'
            excludeApplications = $paw11ExcludeApps
        }
        Users        = @{
            includeGroups = $pawInclude
            excludeUsers  = $bgExclude
            includeRoles  = $pawAdminRoleIds
        }
        Devices      = @{
            deviceFilter = @{
                mode = 'exclude'
                rule = 'device.extensionAttribute1 -eq "PAW"'
            }
        }
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

# PAW12 — Require MFA and a compliant device for all PAW users and admin roles.
#          WHfB Provisioning is excluded so users can complete provisioning before the
#          device is marked compliant.
$paw12ExcludeApps = @(
    '45a330b1-b1ec-4cc1-9161-9f03992aa49f'  # Windows Hello for Business Provisioning
) | Where-Object {
    $appId = $_
    try {
        Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$appId')" `
            -ErrorAction Stop | Out-Null
        $true
    } catch { $false }
}
New-CAPolicyIfNotExists -DisplayName 'PAW-Global-2606-Allow-Require-MFA-and-Compliant-Device' -BodyParameter @{
    DisplayName   = 'PAW-Global-2606-Allow-Require-MFA-and-Compliant-Device'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = @{
            includeApplications = 'All'
            excludeApplications = $paw12ExcludeApps
        }
        Users        = @{
            includeGroups = $pawInclude
            excludeUsers  = $bgExclude
            includeRoles  = $pawAdminRoleIds
        }
    }
    GrantControls = @{ BuiltInControls = @('mfa', 'compliantDevice'); Operator = 'AND' }
}

# PAW13 — Block PAW users from completing PIM role activation (targeted via authentication context
#          PAW-Role-Activation) unless the request originates from a PAW device.
#          This ties PIM's "require auth context on activation" setting to the PAW device filter.
New-CAPolicyIfNotExists -DisplayName 'PAW-Global-2606-Block-Device-Filter-Role-Activation-via-AuthContext' -BodyParameter @{
    DisplayName   = 'PAW-Global-2606-Block-Device-Filter-Role-Activation-via-AuthContext'
    State         = 'EnabledForReportingButNotEnforced'
    Conditions    = @{
        Applications = @{
            includeAuthenticationContextClassReferences = @($pawAuthContextId)
        }
        Users        = @{
            includeGroups = $pawInclude
            excludeUsers  = $bgExclude
        }
        Devices      = @{
            deviceFilter = @{
                mode = 'exclude'
                rule = 'device.extensionAttribute1 -eq "PAW"'
            }
        }
    }
    GrantControls = @{ BuiltInControls = @('block'); Operator = 'OR' }
}

#endregion

Write-Host "`nPAW Conditional Access policy deployment complete." -ForegroundColor Cyan

Disconnect-MgGraph | Out-Null
Write-Host "Disconnected." -ForegroundColor Gray
