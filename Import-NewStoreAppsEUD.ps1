<#
    .SYNOPSIS
    Imports WinGet/Store apps into Intune, assigns the EUD scope tag, and creates
    group assignments (required / available / uninstall) -- no external files needed.

    .PARAMETER ScopeTagName
    Display name of the Intune scope tag to assign to every app. Defaults to "EUD".

    .PARAMETER GroupDisplayName
    Display name of the Entra group to assign every app to. Defaults to "EUD-Global-Devices".

.NOTES
    Required Graph scopes:
        DeviceManagementApps.ReadWrite.All
        Group.Read.All
        DeviceManagementRBAC.Read.All

    .EXAMPLE
    .\Import-NewStoreAppsEUD.ps1
    .\Import-NewStoreAppsEUD.ps1 -ScopeTagName "EUD" -GroupDisplayName "EUD-Global-Devices"
#>
[CmdletBinding()]
param(
    [string] $ScopeTagName     = 'EUD',
    [string] $GroupDisplayName = 'EUD-Global-Devices'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor White

# NuGet provider
if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue | Where-Object { $_.Version -ge '2.8.5.208' })) {
    Write-Host "  Installing NuGet provider..." -ForegroundColor Yellow
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force -Scope CurrentUser | Out-Null
}

# Required modules
foreach ($module in @('Microsoft.Graph.Authentication')) {
    if (-not (Get-Module -Name $module -ListAvailable)) {
        Write-Host "  Installing module '$module'..." -ForegroundColor Yellow
        Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module -Name $module -ErrorAction Stop
}
Write-Host "  Prerequisites OK." -ForegroundColor Green

# Graph connection
Connect-MgGraph -Scopes 'DeviceManagementApps.ReadWrite.All', 'Group.Read.All', 'DeviceManagementRBAC.Read.All' -NoWelcome

# App list
$appDefinitions = @'
[
  { "appDisplayName": "Microsoft - EUD-Global - Company Portal", "packageName": "Company Portal", "AppId": "9WZDNCRFJ3PZ", "assignmentType": "required", "importToIntune": "yes" }
]
'@

# One-time lookups
$escapedTag = $ScopeTagName -replace "'", "''"
$tagResponse = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags?`$filter=displayName eq '$escapedTag'"
$scopeTag = $tagResponse.value | Select-Object -First 1
if (-not $scopeTag) { throw "Scope tag '$ScopeTagName' not found in Intune." }
Write-Host "Scope tag  '$ScopeTagName' -> $($scopeTag.id)" -ForegroundColor DarkGray

$escapedGroup = $GroupDisplayName -replace "'", "''"
$groupResponse = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$escapedGroup'&`$select=id,displayName"
$entraGroup = $groupResponse.value | Select-Object -First 1
if (-not $entraGroup) { throw "Entra group '$GroupDisplayName' not found." }
Write-Host "Group      '$GroupDisplayName' -> $($entraGroup.id)" -ForegroundColor DarkGray

# Helpers
function Get-IntuneWinGetAppId {
    param([string] $DisplayName, [string] $PackageId)
    $escaped  = $DisplayName -replace "'", "''" -replace '&', '%26'
    $response = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=displayName eq '$escaped'"
    $match = $response.value | Where-Object { $_.packageIdentifier -eq $PackageId } | Select-Object -First 1
    if ($match) { $match.id } else { $null }
}

# Main loop
$appsToImport = ($appDefinitions | ConvertFrom-Json) | Where-Object { $_.importToIntune -eq 'yes' }
Write-Host "`nApps to import : $($appsToImport.Count)`n" -ForegroundColor Cyan

foreach ($app in $appsToImport) {
    Write-Host "--- $($app.appDisplayName) ---" -ForegroundColor Cyan

    # 1. Create app if it does not yet exist
    $intuneAppId = Get-IntuneWinGetAppId -DisplayName $app.appDisplayName -PackageId $app.AppId

    if ($intuneAppId) {
        Write-Host "  Already exists (ID: $intuneAppId)" -ForegroundColor Yellow
    }
    else {
        Write-Host "  Querying Microsoft Store for metadata..." -ForegroundColor White

        $searchBody = @{
            Query = @{ KeyWord = $app.AppId; MatchType = 'Substring' }
        } | ConvertTo-Json

        $searchResult = Invoke-MgGraphRequest -Method POST -ContentType 'application/json' `
            -Uri 'https://storeedgefd.dsx.mp.microsoft.com/v9.0/manifestSearch' -Body $searchBody

        $storeApp = $searchResult.Data |
            Where-Object { $_.PackageName -eq $app.packageName } |
            Select-Object -First 1

        if (-not $storeApp) {
            Write-Warning "  '$($app.packageName)' not found in Microsoft Store - skipping."
            continue
        }

        $pkgManifest = Invoke-MgGraphRequest -Method GET `
            -Uri ("https://storeedgefd.dsx.mp.microsoft.com/v9.0/packageManifests/{0}" -f $storeApp.PackageIdentifier)
        $pkgInfo = $pkgManifest.Data.Versions[-1].DefaultLocale

        $appBody = [ordered]@{
            '@odata.type'         = '#microsoft.graph.winGetApp'
            displayName           = $app.appDisplayName
            description           = $pkgInfo.ShortDescription
            publisher             = $pkgInfo.Publisher
            developer             = $pkgInfo.Publisher
            informationUrl        = ''
            privacyInformationUrl = $pkgInfo.PrivacyUrl
            isFeatured            = $false
            packageIdentifier     = $storeApp.PackageIdentifier
            repositoryType        = 'microsoftStore'
            installExperience     = [ordered]@{
                '@odata.type' = 'microsoft.graph.winGetAppInstallExperience'
                runAsAccount  = 'system'
            }
            roleScopeTagIds       = @($scopeTag.id)
        } | ConvertTo-Json -Depth 5

        $created     = Invoke-MgGraphRequest -Method POST -ContentType 'application/json' `
            -Uri 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps' -Body $appBody
        $intuneAppId = $created.id
        Write-Host "  Created (ID: $intuneAppId)" -ForegroundColor Green

        Write-Host "  Waiting 5 s before assignment..." -ForegroundColor DarkGray
        Start-Sleep -Seconds 5
    }

    # 2. Skip if assignment already exists
    $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$intuneAppId/assignments"
    $existing       = Invoke-MgGraphRequest -Method GET -Uri $assignmentsUri
    $intent         = $app.assignmentType

    $alreadyAssigned = $existing.value | Where-Object {
        $_.intent -eq $intent -and $_.target.groupId -eq $entraGroup.id
    }
    if ($alreadyAssigned) {
        Write-Host "  Assignment '$intent' already exists." -ForegroundColor Yellow
        continue
    }

    # 3. Create assignment
    $assignmentBody = [ordered]@{
        '@odata.type' = '#microsoft.graph.mobileAppAssignment'
        intent        = $intent
        source        = 'direct'
        target        = [ordered]@{
            '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
            groupId       = $entraGroup.id
        }
        settings      = [ordered]@{
            '@odata.type'       = '#microsoft.graph.winGetAppAssignmentSettings'
            notifications       = 'showAll'
            installTimeSettings = $null
            restartSettings     = $null
        }
    } | ConvertTo-Json -Depth 5

    Invoke-MgGraphRequest -Method POST -ContentType 'application/json' `
        -Uri $assignmentsUri -Body $assignmentBody | Out-Null

    Write-Host "  Assigned as '$intent' to '$GroupDisplayName'." -ForegroundColor Green
}

Write-Host "`nDone." -ForegroundColor Cyan
