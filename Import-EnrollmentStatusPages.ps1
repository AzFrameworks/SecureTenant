<#
.SYNOPSIS
    Creates the PAW-CSM 2606 Enrollment Status Pages in Intune and assigns
    each one to its respective device group.

.DESCRIPTION
    Self-contained script that creates two Enrollment Status Page policies:

      PAW-2606-Autopilot-ESP-Profile  → scope tag PAW, group PAW-Global-Devices
      EUD-2606-Autopilot-ESP-Profile  → scope tag EUD, group EUD-Global-Devices

    All symbolic names (scope tags, groups, app display names) are resolved to
    live tenant IDs via Microsoft Graph at runtime.

    Duplicate detection is included: each policy is skipped if it already exists.

.EXAMPLE
    .\Import-EnrollmentStatusPages.ps1

.EXAMPLE
    .\Import-EnrollmentStatusPages.ps1 -WhatIf

.NOTES
    Version  : 1.1
    Author   : ForgeSafe AG
    Created  : 2026-06-26

    Requires : PowerShell 7.0 or later (Microsoft.Graph v2+ is incompatible with Windows PowerShell 5.1)
               Microsoft.Graph module v2+
               Install-Module Microsoft.Graph -Scope CurrentUser

    Required Graph permissions:
        DeviceManagementServiceConfig.ReadWrite.All
        DeviceManagementConfiguration.ReadWrite.All
        DeviceManagementApps.Read.All
        Group.Read.All
        DeviceManagementRBAC.Read.All

DISCLAIMER
    This script is provided "as is" without warranty of any kind, express or
    implied.  ForgeSafe AG shall not be liable for any damages arising from the
    use of this script.  Test in a non-production environment before deploying
    to production.  The operator is responsible for reviewing and validating
    all changes made to the tenant.

COPYRIGHT
    Copyright (c) 2026 ForgeSafe AG. All rights reserved.
#>

#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Microsoft.Graph.Authentication v2+ requires PowerShell 7+.
# Import explicitly here so a missing or broken module gives a clear message.
try {
    Import-Module Microsoft.Graph.Authentication -MinimumVersion '2.0.0' -ErrorAction Stop
}
catch {
    Write-Error ("Microsoft.Graph.Authentication v2+ is required. " +
                 "Install it with: Install-Module Microsoft.Graph -Scope CurrentUser`n$_")
    exit 1
}

#region ── ESP configurations ────────────────────────────────────────────────

# Shared settings applied to every ESP in this script.
$ESPDefaults = @{
    ShowInstallationProgress           = $true
    BlockDeviceSetupRetryByUser        = $false
    AllowDeviceResetOnInstallFailure   = $true
    AllowLogCollectionOnInstallFailure = $true
    CustomErrorMessage                 = ''
    InstallProgressTimeoutInMinutes    = 90
    AllowDeviceUseOnInstallFailure     = $false
    TrackInstallProgressForAutopilot   = $true
    DisableUserStatusAfterFirstUser    = $true
    TrackedAppNames                    = @('Microsoft - PAW-Global - Company Portal')
}

# Per-policy definitions. Add or remove entries here to control what gets created.
$ESPConfigs = @(
    @{
        DisplayName         = 'PAW-2606-Autopilot-ESP-Profile'
        Description         = ''
        Priority            = 1
        ScopeTagName        = 'PAW'
        AssignmentGroupName = 'PAW-Global-Devices'
    },
    @{
        DisplayName         = 'EUD-2606-Autopilot-ESP-Profile'
        Description         = ''
        Priority            = 2
        ScopeTagName        = 'EUD'
        AssignmentGroupName = 'EUD-Global-Devices'
    }
)

#endregion

#region ── Required Graph scopes ─────────────────────────────────────────────

$RequiredScopes = @(
    'DeviceManagementServiceConfig.ReadWrite.All',
    'DeviceManagementConfiguration.ReadWrite.All',
    'DeviceManagementApps.Read.All',
    'Group.Read.All',
    'DeviceManagementRBAC.Read.All'
)

#endregion

#region ── Helper functions ───────────────────────────────────────────────────

function Write-Step {
    param([string]$Message)
    Write-Host ''
    Write-Host "── $Message" -ForegroundColor Cyan
}

function Write-Info  { param([string]$m) Write-Host "   $m" -ForegroundColor Gray }
function Write-Ok    { param([string]$m) Write-Host "   $m" -ForegroundColor Green }
function Write-Warn  { param([string]$m) Write-Host "   $m" -ForegroundColor Yellow }

function Invoke-GraphGet {
    param([string]$Uri)
    Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
}

function Get-ScopeTagId {
    param([string]$DisplayName)
    $uri    = "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags" +
              "?`$filter=displayName eq '$([Uri]::EscapeDataString($DisplayName))'&`$select=id,displayName"
    $result = (Invoke-GraphGet -Uri $uri).value
    if (-not $result) { throw "Scope tag '$DisplayName' not found in tenant." }
    return $result[0].id
}

function Get-GroupId {
    param([string]$DisplayName)
    $uri    = "https://graph.microsoft.com/v1.0/groups" +
              "?`$filter=displayName eq '$([Uri]::EscapeDataString($DisplayName))'&`$select=id,displayName"
    $result = (Invoke-GraphGet -Uri $uri).value
    if (-not $result) { throw "Entra ID group '$DisplayName' not found in tenant." }
    return $result[0].id
}

function Get-IntuneAppId {
    param([string]$DisplayName)
    $uri    = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps" +
              "?`$filter=displayName eq '$([Uri]::EscapeDataString($DisplayName))'&`$select=id,displayName"
    $result = (Invoke-GraphGet -Uri $uri).value
    if (-not $result) { throw "Intune app '$DisplayName' not found in tenant." }
    return $result[0].id
}

function Get-ExistingESP {
    param([string]$DisplayName)
    $uri    = "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations" +
              "?`$filter=displayName eq '$([Uri]::EscapeDataString($DisplayName))'&`$select=id,displayName"
    $result = (Invoke-GraphGet -Uri $uri).value
    if (-not $result) { return $null }
    return $result | Where-Object {
        $_.'@odata.type' -eq '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'
    }
}

function New-ESPWithAssignment {
    [CmdletBinding(SupportsShouldProcess)]
    param([hashtable]$Config, [hashtable]$Defaults)

    $displayName = $Config.DisplayName

    Write-Step "ESP : $displayName"

    # Duplicate check
    $existing = Get-ExistingESP -DisplayName $displayName
    if ($existing) {
        Write-Warn "Already exists (ID: $($existing[0].id)) – skipping."
        return
    }

    # Resolve IDs
    Write-Info "Scope tag : $($Config.ScopeTagName)"
    $scopeTagId = Get-ScopeTagId -DisplayName $Config.ScopeTagName
    Write-Ok "  → $scopeTagId"

    Write-Info "Group     : $($Config.AssignmentGroupName)"
    $groupId = Get-GroupId -DisplayName $Config.AssignmentGroupName
    Write-Ok "  → $groupId"

    $appIds = @()
    foreach ($appName in $Defaults.TrackedAppNames) {
        Write-Info "App       : $appName"
        $appId   = Get-IntuneAppId -DisplayName $appName
        $appIds += $appId
        Write-Ok "  → $appId"
    }

    # Create
    $espBody = [ordered]@{
        '@odata.type'                           = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'
        displayName                             = $displayName
        description                             = $Config.Description
        priority                                = $Config.Priority
        roleScopeTagIds                         = @($scopeTagId)
        showInstallationProgress                = $Defaults.ShowInstallationProgress
        blockDeviceSetupRetryByUser             = $Defaults.BlockDeviceSetupRetryByUser
        allowDeviceResetOnInstallFailure        = $Defaults.AllowDeviceResetOnInstallFailure
        allowLogCollectionOnInstallFailure      = $Defaults.AllowLogCollectionOnInstallFailure
        customErrorMessage                      = $Defaults.CustomErrorMessage
        installProgressTimeoutInMinutes         = $Defaults.InstallProgressTimeoutInMinutes
        allowDeviceUseOnInstallFailure          = $Defaults.AllowDeviceUseOnInstallFailure
        selectedMobileAppIds                    = $appIds
        trackInstallProgressForAutopilotOnly    = $Defaults.TrackInstallProgressForAutopilot
        disableUserStatusTrackingAfterFirstUser = $Defaults.DisableUserStatusAfterFirstUser
    } | ConvertTo-Json -Depth 5

    if ($PSCmdlet.ShouldProcess($displayName, 'Create Enrollment Status Page')) {
        $espUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations'
        $newESP = Invoke-MgGraphRequest -Method POST -Uri $espUri -Body $espBody -ContentType 'application/json' -OutputType PSObject
        Write-Ok "Created (ID: $($newESP.id))"

        # Assign
        $assignUri  = "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations/$($newESP.id)/assign"
        $assignBody = @{
            enrollmentConfigurationAssignments = @(
                @{
                    target = @{
                        '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                        groupId       = $groupId
                    }
                }
            )
        } | ConvertTo-Json -Depth 4

        Invoke-MgGraphRequest -Method POST -Uri $assignUri -Body $assignBody -ContentType 'application/json' | Out-Null
        Write-Ok "Assigned to '$($Config.AssignmentGroupName)'"
    }
}

#endregion

#region ── Banner ─────────────────────────────────────────────────────────────

Write-Host ''
Write-Host '================================================' -ForegroundColor Magenta
Write-Host '  PAW-CSM 2606 – Import Enrollment Status Pages' -ForegroundColor Magenta
Write-Host '================================================' -ForegroundColor Magenta

#endregion

#region ── Authentication ─────────────────────────────────────────────────────

Write-Step 'Connecting to Microsoft Graph'

$ctx = Get-MgContext

if ($null -eq $ctx) {
    Write-Info 'No active session – sign in via browser...'
    Connect-MgGraph -Scopes $RequiredScopes -NoWelcome
    $ctx = Get-MgContext
}
else {
    $missing = $RequiredScopes | Where-Object { $ctx.Scopes -notcontains $_ }
    if ($missing) {
        Write-Warn "Missing scopes ($($missing -join ', ')) – reconnecting..."
        Disconnect-MgGraph | Out-Null
        Connect-MgGraph -Scopes $RequiredScopes -NoWelcome
        $ctx = Get-MgContext
    }
    else {
        Write-Info 'Reusing existing session.'
    }
}

Write-Ok "Account : $($ctx.Account)"
Write-Ok "Tenant  : $($ctx.TenantId)"

#endregion

#region ── Create all ESPs ────────────────────────────────────────────────────

foreach ($config in $ESPConfigs) {
    New-ESPWithAssignment -Config $config -Defaults $ESPDefaults
}

#endregion

Write-Host ''
Write-Host '================================================' -ForegroundColor Magenta
Write-Host '  Completed.' -ForegroundColor Green
Write-Host '================================================' -ForegroundColor Magenta
Write-Host ''
