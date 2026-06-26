<#
    .SYNOPSIS
    Imports WinGet/Store apps into Intune, assigns the PAW scope tag, and creates
    group assignments (required / available / uninstall) — no external files needed.

    .PARAMETER ScopeTagName
    Display name of the Intune scope tag to assign to every app. Defaults to "PAW".

    .PARAMETER GroupDisplayName
    Display name of the Entra group to assign every app to. Defaults to "PAW-Global-Devices".

.NOTES
    Required Graph scopes:
        DeviceManagementApps.ReadWrite.All
        Group.Read.All
        DeviceManagementRBAC.Read.All

    .EXAMPLE
    .\Import-NewStoreAppsPAW.ps1
    .\Import-NewStoreAppsPAW.ps1 -ScopeTagName "PAW" -GroupDisplayName "PAW-Global-Devices"
#>
[CmdletBinding()]
param(
    [string] $ScopeTagName    = 'PAW',
    [string] $GroupDisplayName = 'PAW-Global-Devices'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Prerequisites ─────────────────────────────────────────────────────────────
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

# ── Graph connection ──────────────────────────────────────────────────────────
Connect-MgGraph -Scopes 'DeviceManagementApps.ReadWrite.All', 'Group.Read.All', 'DeviceManagementRBAC.Read.All' -NoWelcome

# ── App list ──────────────────────────────────────────────────────────────────
# Fields: appDisplayName, packageName, AppId, assignmentType, importToIntune
# assignmentType: required | available | uninstall
$appDefinitions = @'
[
  { "appDisplayName": "Microsoft - PAW-Global - Company Portal",                        "packageName": "Company Portal",                         "AppId": "9WZDNCRFJ3PZ",  "assignmentType": "required",  "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - PowerShell",                            "packageName": "PowerShell",                             "AppId": "9MZ1SNWT0N5D",  "assignmentType": "required",  "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Windows Notepad",                       "packageName": "Windows Notepad",                        "AppId": "9MSMLRH6LZF3",  "assignmentType": "required",  "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Microsoft Clipchamp",                   "packageName": "Microsoft Clipchamp",                    "AppId": "9P1J8S7CCWWT",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - 3D Viewer",                             "packageName": "3D Viewer",                              "AppId": "9NBLGGH42THS",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Windows Media Player",                  "packageName": "Windows Media Player",                   "AppId": "9WZDNCRFJ3PT",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Mail and Calendar",                     "packageName": "Mail and Calendar",                      "AppId": "9WZDNCRFHVQM",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Microsoft Messaging",                   "packageName": "Microsoft Messaging",                    "AppId": "9WZDNCRFJBQ6",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Microsoft News",                        "packageName": "Microsoft News",                         "AppId": "9WZDNCRFHVFW",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Microsoft Photos",                      "packageName": "Microsoft Photos",                       "AppId": "9WZDNCRFJBH4",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Microsoft Sticky Notes",                "packageName": "Microsoft Sticky Notes",                 "AppId": "9NBLGGH4QGHW",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Mixed Reality Portal",                  "packageName": "Mixed Reality Portal",                   "AppId": "9NG1H8B3ZC7M",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - MSN Weather",                           "packageName": "MSN Weather",                            "AppId": "9WZDNCRFJ3Q2",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Paint",                                 "packageName": "Paint",                                  "AppId": "9PCFS5B6T72H",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Phone Link",                            "packageName": "Phone Link",                             "AppId": "9NMPJ99VJBWV",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Snipping Tool",                         "packageName": "Snipping Tool",                          "AppId": "9MZ95KL8MR0L",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Surface",                               "packageName": "Surface",                                "AppId": "9WZDNCRFJB8P",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Windows Clock",                         "packageName": "Windows Clock",                          "AppId": "9WZDNCRFJ3PR",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Windows Calculator",                    "packageName": "Windows Calculator",                     "AppId": "9WZDNCRFHVN5",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Windows Camera",                        "packageName": "Windows Camera",                         "AppId": "9WZDNCRFJBBG",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Windows Sound Recorder",                "packageName": "Windows Sound Recorder",                 "AppId": "9WZDNCRFHWKN",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Microsoft Wireless Display Adapter",    "packageName": "Microsoft Wireless Display Adapter",     "AppId": "9WZDNCRFJBB1",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Game Bar",                              "packageName": "Game Bar",                               "AppId": "9NZKPSTSNW4P",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Feedback Hub",                          "packageName": "Feedback Hub",                           "AppId": "9NBLGGH4R32N",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Xbox",                                  "packageName": "Xbox",                                   "AppId": "9MV0B5HZVK9Z",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Microsoft To Do: Lists, Tasks & Reminders", "packageName": "Microsoft To Do: Lists, Tasks & Reminders", "AppId": "9NBLGGH5R558", "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Movies & TV",                           "packageName": "Movies & TV",                            "AppId": "9WZDNCRFJ3P2",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Microsoft Whiteboard",                  "packageName": "Microsoft Whiteboard",                   "AppId": "9MSPC6MP8FM4",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Get Help",                              "packageName": "Get Help",                               "AppId": "9PKDZBMV1H3T",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Quick Assist",                          "packageName": "Quick Assist",                           "AppId": "9P7BP5VNWKX5",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Power Automate",                        "packageName": "Power Automate",                         "AppId": "9NFTCH6J7FHV",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Dev Center",                            "packageName": "Dev Center",                             "AppId": "9NBLGGH4R5WS", "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Outlook for Windows",                   "packageName": "Outlook for Windows",                    "AppId": "9NRX63209R7B",  "assignmentType": "uninstall", "importToIntune": "yes" },
  { "appDisplayName": "Microsoft - PAW-Global - Microsoft Family Safety",               "packageName": "Microsoft Family Safety",                "AppId": "9PDJDJS743XF",  "assignmentType": "uninstall", "importToIntune": "yes" }
]
'@


# ── One-time lookups ──────────────────────────────────────────────────────────
$escapedTag = $ScopeTagName -replace "'", "''"
$tagResponse = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags?`$filter=displayName eq '$escapedTag'"
$scopeTag = $tagResponse.value | Select-Object -First 1
if (-not $scopeTag) { throw "Scope tag '$ScopeTagName' not found in Intune." }
Write-Host "Scope tag  '$ScopeTagName' → $($scopeTag.id)" -ForegroundColor DarkGray

$escapedGroup = $GroupDisplayName -replace "'", "''"
$groupResponse = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$escapedGroup'&`$select=id,displayName"
$entraGroup = $groupResponse.value | Select-Object -First 1
if (-not $entraGroup) { throw "Entra group '$GroupDisplayName' not found." }
Write-Host "Group      '$GroupDisplayName' → $($entraGroup.id)" -ForegroundColor DarkGray

# ── Helpers ───────────────────────────────────────────────────────────────────
function Get-IntuneWinGetAppId {
    param([string] $DisplayName, [string] $PackageId)
    $escaped  = $DisplayName -replace "'", "''" -replace '&', '%26'
    $response = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=displayName eq '$escaped'"
    ($response.value | Where-Object { $_.packageIdentifier -eq $PackageId } | Select-Object -First 1)?.id
}

# ── Main loop ─────────────────────────────────────────────────────────────────
$appsToImport = ($appDefinitions | ConvertFrom-Json) | Where-Object { $_.importToIntune -eq 'yes' }
Write-Host "`nApps to import : $($appsToImport.Count)`n" -ForegroundColor Cyan

foreach ($app in $appsToImport) {
    Write-Host "─── $($app.appDisplayName) ───" -ForegroundColor Cyan

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
            Write-Warning "  '$($app.packageName)' not found in Microsoft Store — skipping."
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
    $intent         = $app.assignmentType   # required / available / uninstall

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
