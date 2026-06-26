<#
    .SYNOPSIS
    Imports the Microsoft Edge Hardening ADMX-based group policy configuration
    into Intune for PAW, assigns the PAW scope tag, and assigns it to
    PAW-Global-Devices — no external files needed.

    .PARAMETER PAWCSMVersion
    Version string substituted for {PAWCSMVersion} in the policy display name.
    Defaults to "2606".

    .PARAMETER ScopeTagName
    Intune scope tag display name. Defaults to "PAW".

    .PARAMETER GroupDisplayName
    Entra group to assign the policy to. Defaults to "PAW-Global-Devices".

    .NOTES
    Required Graph scopes:
        DeviceManagementConfiguration.ReadWrite.All
        Group.Read.All
        DeviceManagementRBAC.Read.All

    .EXAMPLE
    .\Import-ConfigurationPoliciesAdmxPAW.ps1
    .\Import-ConfigurationPoliciesAdmxPAW.ps1 -PAWCSMVersion "2606"
#>
[CmdletBinding()]
param(
    [string] $PAWCSMVersion    = '2606',
    [string] $ScopeTagName     = 'PAW',
    [string] $GroupDisplayName = 'PAW-Global-Devices'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -- Prerequisites -------------------------------------------------------------
Write-Host "Checking prerequisites..." -ForegroundColor White

if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue |
        Where-Object { $_.Version -ge '2.8.5.208' })) {
    Write-Host "  Installing NuGet provider..." -ForegroundColor Yellow
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force -Scope CurrentUser | Out-Null
}

foreach ($module in @('Microsoft.Graph.Authentication')) {
    if (-not (Get-Module -Name $module -ListAvailable)) {
        Write-Host "  Installing module '$module'..." -ForegroundColor Yellow
        Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module -Name $module -ErrorAction Stop
}
Write-Host "  Prerequisites OK." -ForegroundColor Green

# -- Graph connection ----------------------------------------------------------
Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All', 'Group.Read.All', 'DeviceManagementRBAC.Read.All' -NoWelcome

# -- One-time lookups ----------------------------------------------------------
Write-Host "`nResolving scope tag and group..." -ForegroundColor White

$escapedTag = $ScopeTagName -replace "'", "''"
$tagResp    = Invoke-MgGraphRequest -Method GET `
    -Uri ('https://graph.microsoft.com/beta/deviceManagement/roleScopeTags?$filter=displayName eq ''' + $escapedTag + '''')
$scopeTag = $tagResp.value | Select-Object -First 1
if (-not $scopeTag) { throw "Scope tag '$ScopeTagName' not found in Intune." }
Write-Host "  Scope tag '$ScopeTagName' -> $($scopeTag.id)" -ForegroundColor DarkGray

$escapedGroup = $GroupDisplayName -replace "'", "''"
$groupResp    = Invoke-MgGraphRequest -Method GET `
    -Uri ('https://graph.microsoft.com/v1.0/groups?$filter=displayName eq ''' + $escapedGroup + '''&$select=id,displayName')
$entraGroup = $groupResp.value | Select-Object -First 1
if (-not $entraGroup) { throw "Entra group '$GroupDisplayName' not found." }
Write-Host "  Group '$GroupDisplayName' -> $($entraGroup.id)" -ForegroundColor DarkGray

# -- Helper: check if policy already exists ------------------------------------
function Get-ADMXPolicyId {
    param([string] $DisplayName)
    $escaped  = $DisplayName -replace "'", "''" -replace '&', '%26'
    $response = Invoke-MgGraphRequest -Method GET `
        -Uri ('https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations?$filter=displayName eq ''' + $escaped + '''')
    ($response.value | Select-Object -First 1)?.id
}

# -- Policy definitions --------------------------------------------------------
$displayName = "PAW-Global-$PAWCSMVersion-Microsoft-Edge-Hardening-UI"

$definitions = @(
    @{
        'definition@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('06b9c400-f1ed-4046-b8cb-02af3ae8e38d')"
        enabled                 = $true
    },
    @{
        'definition@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('75c20a0b-f76e-4131-892a-1f47dd6534e4')"
        enabled                 = $true
        presentationValues      = @(
            @{
                '@odata.type'             = '#microsoft.graph.groupPolicyPresentationValueText'
                value                     = '2'
                'presentation@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('75c20a0b-f76e-4131-892a-1f47dd6534e4')/presentations('6f605b7e-ca35-4f6a-b616-0cf85f5e9580')"
            }
        )
    },
    @{
        'definition@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('59922037-5107-4eaf-a72f-249a73c08d16')"
        enabled                 = $true
    },
    @{
        'definition@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('6189eace-13bd-435e-b438-2f38495bf9cc')"
        enabled                 = $false
    },
    @{
        'definition@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('1a52c714-6ece-45d2-a8a9-505f97bdec1b')"
        enabled                 = $true
        presentationValues      = @(
            @{
                '@odata.type'             = '#microsoft.graph.groupPolicyPresentationValueList'
                values                    = @(
                    @{ name = '*'; value = $null }
                )
                'presentation@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('1a52c714-6ece-45d2-a8a9-505f97bdec1b')/presentations('75f2a4b4-fa3d-4acc-bbba-6a120e2ef96e')"
            }
        )
    },
    @{
        'definition@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('270e643f-a1dd-49eb-8365-8292e9d6c7f7')"
        enabled                 = $true
    },
    @{
        'definition@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('fdfedea9-c9d1-4109-9b59-883cfe2d861a')"
        enabled                 = $true
        presentationValues      = @(
            @{
                '@odata.type'             = '#microsoft.graph.groupPolicyPresentationValueText'
                value                     = 'ntlm,negotiate'
                'presentation@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('fdfedea9-c9d1-4109-9b59-883cfe2d861a')/presentations('e6b8ffac-8e06-4a30-95c6-cec2dfc1a08f')"
            }
        )
    },
    @{
        'definition@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('bc6a79f3-77d4-462c-9924-8ea74dc34386')"
        enabled                 = $false
    },
    @{
        'definition@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('ccfd2123-ff05-4680-a4eb-ab2790b6d6ed')"
        enabled                 = $false
    },
    @{
        'definition@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('6f317cd9-3683-476b-adea-b93eb74e07c1')"
        enabled                 = $true
    },
    @{
        'definition@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('7f7e757c-1137-4e59-8cd1-cb51ca6896c0')"
        enabled                 = $true
        presentationValues      = @(
            @{
                '@odata.type'             = '#microsoft.graph.groupPolicyPresentationValueText'
                value                     = 'tls1.2'
                'presentation@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('7f7e757c-1137-4e59-8cd1-cb51ca6896c0')/presentations('10ecdc74-5985-4f1e-9308-ceadffe422ff')"
            }
        )
    },
    @{
        'definition@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('f9de5937-2ff5-4c34-a5ec-d0d997787b68')"
        enabled                 = $true
    }
)

# -- Main ----------------------------------------------------------------------
Write-Host "`n--- $displayName ---" -ForegroundColor Cyan

$policyId = Get-ADMXPolicyId -DisplayName $displayName
if ($policyId) {
    Write-Host "  Already exists (ID: $policyId)" -ForegroundColor Yellow
} else {
    # 1. Create the policy shell
    $created  = Invoke-MgGraphRequest -Method POST -ContentType 'application/json' `
        -Uri 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations' `
        -Body (@{
            displayName     = $displayName
            description     = ''
            roleScopeTagIds = @($scopeTag.id)
        } | ConvertTo-Json -Depth 3)
    $policyId = $created.id
    Write-Host "  Created policy (ID: $policyId)" -ForegroundColor Green

    # 2. Add each definition value
    $defUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$policyId/definitionValues"
    $i = 0
    foreach ($def in $definitions) {
        $i++
        Invoke-MgGraphRequest -Method POST -ContentType 'application/json' `
            -Uri $defUri -Body ($def | ConvertTo-Json -Depth 5) | Out-Null
        Write-Host "  Added definition $i/$($definitions.Count)" -ForegroundColor DarkGray
    }
    Write-Host "  All $($definitions.Count) definitions added." -ForegroundColor Green
}

# 3. Assign
Invoke-MgGraphRequest -Method POST -ContentType 'application/json' `
    -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$policyId/assign" `
    -Body (@{
        assignments = @(@{
            target = @{
                '@odata.type'                              = '#microsoft.graph.groupAssignmentTarget'
                groupId                                    = $entraGroup.id
                deviceAndAppManagementAssignmentFilterType = 'none'
                deviceAndAppManagementAssignmentFilterId   = $null
            }
        })
    } | ConvertTo-Json -Depth 5) | Out-Null
Write-Host "  Assigned to '$GroupDisplayName'." -ForegroundColor Green

Write-Host "`nDone." -ForegroundColor Cyan
