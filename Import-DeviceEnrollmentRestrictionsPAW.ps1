<#
    .SYNOPSIS
    Imports Device Enrollment Restrictions into Intune for PAW, assigns the PAW
    scope tag, and assigns them to PAW-Global-Users — no external files needed.

    .PARAMETER PAWCSMVersion
    Version string substituted for {PAWCSMVersion} in restriction display names.
    Defaults to "2606".

    .PARAMETER ScopeTagName
    Intune scope tag display name. Defaults to "PAW".

    .PARAMETER GroupDisplayName
    Entra group to assign every restriction to. Defaults to "PAW-Global-Users".

    .NOTES
    Required Graph scopes:
        DeviceManagementServiceConfig.ReadWrite.All
        Group.Read.All
        DeviceManagementRBAC.Read.All

    .EXAMPLE
    .\Import-DeviceEnrollmentRestrictionsPAW.ps1
    .\Import-DeviceEnrollmentRestrictionsPAW.ps1 -PAWCSMVersion "2606"
#>
[CmdletBinding()]
param(
    [string] $PAWCSMVersion    = '2606',
    [string] $ScopeTagName     = 'PAW',
    [string] $GroupDisplayName = 'PAW-Global-Users'
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
Connect-MgGraph -Scopes 'DeviceManagementServiceConfig.ReadWrite.All', 'Group.Read.All', 'DeviceManagementRBAC.Read.All' -NoWelcome

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

# -- Helper --------------------------------------------------------------------
# PlatformType is used to distinguish the two Android restrictions that share
# the same display name. Pass '' for types that have no platformType (Limit).
function Get-EnrollmentConfigId {
    param([string] $DisplayName, [string] $PlatformType = '')
    $uri = 'https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations?$top=999'
    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        $match    = $response.value | Where-Object {
            $_.displayName -eq $DisplayName -and
            (-not $PlatformType -or $_.platformType -eq $PlatformType)
        } | Select-Object -First 1
        if ($match) { return $match.id }
        $uri = $response['@odata.nextLink']
    } while ($uri)
    return $null
}

# -- Restriction definitions ---------------------------------------------------
$restrictionDefs = @(
    @{
        PlatformType = 'androidForWork'
        Json         = @'
{
  "@odata.type": "#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration",
  "displayName": "PAW-Global-{PAWCSMVersion}-Device-Android-Restrictions",
  "description": "",
  "deviceEnrollmentConfigurationType": "singlePlatformRestriction",
  "platformType": "androidForWork",
  "platformRestriction": {
    "platformBlocked": true,
    "personalDeviceEnrollmentBlocked": false,
    "osMinimumVersion": null,
    "osMaximumVersion": null,
    "blockedManufacturers": [],
    "blockedSkus": []
  }
}
'@
    },
    @{
        PlatformType = 'android'
        Json         = @'
{
  "@odata.type": "#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration",
  "displayName": "PAW-Global-{PAWCSMVersion}-Device-Android-Restrictions",
  "description": "",
  "deviceEnrollmentConfigurationType": "singlePlatformRestriction",
  "platformType": "android",
  "platformRestriction": {
    "platformBlocked": true,
    "personalDeviceEnrollmentBlocked": false,
    "osMinimumVersion": null,
    "osMaximumVersion": null,
    "blockedManufacturers": [],
    "blockedSkus": []
  }
}
'@
    },
    @{
        PlatformType = 'ios'
        Json         = @'
{
  "@odata.type": "#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration",
  "displayName": "PAW-Global-{PAWCSMVersion}-Device-iOS-Restrictions",
  "description": "",
  "platformType": "ios",
  "platformRestriction": {
    "platformBlocked": true,
    "personalDeviceEnrollmentBlocked": false,
    "osMinimumVersion": "",
    "osMaximumVersion": "",
    "blockedManufacturers": []
  }
}
'@
    },
    @{
        PlatformType = ''
        Json         = @'
{
  "@odata.type": "#microsoft.graph.deviceEnrollmentLimitConfiguration",
  "displayName": "PAW-Global-{PAWCSMVersion}-Device-Limit-Restrictions",
  "description": "",
  "limit": 5
}
'@
    },
    @{
        PlatformType = 'mac'
        Json         = @'
{
  "@odata.type": "#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration",
  "displayName": "PAW-Global-{PAWCSMVersion}-Device-MacOS-Restrictions",
  "description": "",
  "platformType": "mac",
  "platformRestriction": {
    "platformBlocked": true,
    "personalDeviceEnrollmentBlocked": false,
    "osMinimumVersion": "",
    "osMaximumVersion": "",
    "blockedManufacturers": []
  }
}
'@
    },
    @{
        PlatformType = 'windows'
        Json         = @'
{
  "@odata.type": "#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration",
  "displayName": "PAW-Global-{PAWCSMVersion}-Device-Windows-Restrictions",
  "description": "",
  "platformType": "windows",
  "platformRestriction": {
    "platformBlocked": false,
    "personalDeviceEnrollmentBlocked": true,
    "osMinimumVersion": "10.0.26200.8655",
    "osMaximumVersion": "",
    "blockedManufacturers": []
  }
}
'@
    }
)

# -- Main loop -----------------------------------------------------------------
foreach ($def in $restrictionDefs) {
    $parsed      = $def.Json | ConvertFrom-Json
    $displayName = $parsed.displayName -replace '\{PAWCSMVersion\}', $PAWCSMVersion
    $label       = if ($def.PlatformType) { "$displayName [$($def.PlatformType)]" } else { $displayName }
    Write-Host "`n--- $label ---" -ForegroundColor Cyan

    $existingId = Get-EnrollmentConfigId -DisplayName $displayName -PlatformType $def.PlatformType
    if ($existingId) {
        Write-Host "  Already exists (ID: $existingId) — skipping." -ForegroundColor Yellow
        continue
    }

    # Build create body: copy all fields from the embedded JSON, then override
    # displayName (with resolved version) and inject the runtime scope tag ID.
    $createBody = [ordered]@{}
    $parsed.PSObject.Properties | ForEach-Object { $createBody[$_.Name] = $_.Value }
    $createBody['displayName']     = $displayName
    $createBody['roleScopeTagIds'] = @($scopeTag.id)

    $created = Invoke-MgGraphRequest -Method POST -ContentType 'application/json' `
        -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations' `
        -Body ($createBody | ConvertTo-Json -Depth 5)
    Write-Host "  Created (ID: $($created.id))" -ForegroundColor Green

    # Assign to group
    Invoke-MgGraphRequest -Method POST -ContentType 'application/json' `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations/$($created.id)/assign" `
        -Body (@{
            enrollmentConfigurationAssignments = @(@{
                target = @{
                    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                    groupId       = $entraGroup.id
                }
            })
        } | ConvertTo-Json -Depth 5) | Out-Null
    Write-Host "  Assigned to '$GroupDisplayName'." -ForegroundColor Green
}

Write-Host "`nDone." -ForegroundColor Cyan
