<#
.SYNOPSIS
    Creates the PAW 2606 Autopilot Deployment Profile in Microsoft Intune.
.DESCRIPTION
    Installs required modules, authenticates to Microsoft Graph, checks for an
    existing profile with the same name, then creates the profile and assigns it
    to the PAW-Global-Devices group. The script is self-sufficient and requires
    no external files or specific execution path.
.EXAMPLE
    .\Import-AutopilotProfilePAW.ps1
.EXAMPLE
    .\Import-AutopilotProfilePAW.ps1 -WhatIf
#>

<#
DISCLAIMER
----------
This script is provided "AS IS" without warranty of any kind, express or implied,
including but not limited to warranties of merchantability, fitness for a particular
purpose, or non-infringement. Use at your own risk.

The author(s) and contributors accept no liability for any damage, data loss, or
unintended configuration changes resulting from the use of this script.

Always review and test this script in a non-production / staging environment before
running it against any production tenant or device fleet.
#>

#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# TLS 1.2 is required for PowerShell Gallery and Microsoft endpoints
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Install NuGet package provider if missing
if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Write-Host "Installing NuGet package provider..." -ForegroundColor Yellow
    Install-PackageProvider -Name NuGet -Scope CurrentUser -Force | Out-Null
}

# Install Microsoft.Graph.Authentication module if missing
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Host "Installing Microsoft.Graph.Authentication module..." -ForegroundColor Yellow
    Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# --- Configuration (all settings embedded, no external file needed) ---
$profileName  = "PAW 2606 Autopilot Profile"
$scopeTagName = "PAW"
$groupName    = "PAW-Global-Devices"

# Connect to Microsoft Graph (reuse existing session if already authenticated)
if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes @(
        "DeviceManagementServiceConfig.ReadWrite.All",
        "DeviceManagementRBAC.Read.All",
        "Group.Read.All"
    ) -NoWelcome
}

# Check if the profile already exists — exit early if so
Write-Host "Checking if profile '$profileName' already exists..." -ForegroundColor Cyan
$filterEncoded = [uri]::EscapeDataString("displayName eq '$profileName'")
$existing = (Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles?`$filter=$filterEncoded"
).value

if ($existing) {
    Write-Host "Profile '$profileName' already exists. Nothing to do." -ForegroundColor Yellow
    return
}

# Resolve scope tag to its ID
Write-Host "Resolving scope tag '$scopeTagName'..." -ForegroundColor Cyan
$filterEncoded = [uri]::EscapeDataString("displayName eq '$scopeTagName'")
$scopeTag = (Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags?`$filter=$filterEncoded"
).value | Select-Object -First 1

if (-not $scopeTag) { throw "Scope tag '$scopeTagName' not found in Intune." }

# Resolve assignment group to its ID
Write-Host "Resolving group '$groupName'..." -ForegroundColor Cyan
$filterEncoded = [uri]::EscapeDataString("displayName eq '$groupName'")
$group = (Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=$filterEncoded"
).value | Select-Object -First 1

if (-not $group) { throw "Group '$groupName' not found in Entra ID." }

# Build the Autopilot profile payload
$profileBody = @{
    "@odata.type"       = "#microsoft.graph.azureADWindowsAutopilotDeploymentProfile"
    displayName         = $profileName
    description         = ""
    language            = "os-default"
    extractHardwareHash = $true
    deviceNameTemplate  = "PAW-%SERIAL%"
    deviceType          = "windowsPc"
    enableWhiteGlove    = $false
    roleScopeTagIds     = @($scopeTag.id)
    outOfBoxExperienceSettings = @{
        hidePrivacySettings       = $true
        hideEULA                  = $true
        userType                  = "standard"
        deviceUsageType           = "singleUser"
        skipKeyboardSelectionPage = $false    # keyboard layout selected by user
        hideEscapeLink            = $true
    }
}

# Create the profile
if ($PSCmdlet.ShouldProcess($profileName, "Create Autopilot Deployment Profile")) {
    Write-Host "Creating Autopilot profile '$profileName'..." -ForegroundColor Cyan
    $newProfile = Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles" `
        -Body ($profileBody | ConvertTo-Json -Depth 10) `
        -ContentType "application/json"

    # Assign the profile to the group
    Write-Host "Assigning profile to group '$groupName'..." -ForegroundColor Cyan
    $assignmentBody = @{
        target = @{
            "@odata.type"                                   = "#microsoft.graph.groupAssignmentTarget"
            deviceAndAppManagementAssignmentFilterId        = $null
            deviceAndAppManagementAssignmentFilterType      = "none"
            groupId                                         = $group.id
        }
    }
    Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles/$($newProfile.id)/assignments" `
        -Body ($assignmentBody | ConvertTo-Json -Depth 5) `
        -ContentType "application/json" | Out-Null

    Write-Host "Done. Profile '$profileName' created and assigned to '$groupName'." -ForegroundColor Green
}
