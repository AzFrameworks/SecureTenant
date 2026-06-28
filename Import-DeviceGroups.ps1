<#
.SYNOPSIS
    Creates dynamic device security groups in Microsoft Entra ID for Autopilot
    Group Tag based membership (PAW-Global-Devices, EUD-Global-Devices).
.DESCRIPTION
    Installs required modules, authenticates to Microsoft Graph, checks for
    existing groups with the same name, then creates the dynamic security groups
    with membership rules based on the Autopilot Group Tag (OrderID) property.
    The script is self-sufficient and requires no external files or specific
    execution path.
.EXAMPLE
    .\Import-DeviceGroups.ps1
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

[CmdletBinding()]
param()

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
Write-Host 'Checking prerequisites...' -ForegroundColor White

if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue |
          Where-Object { $_.Version -ge '2.8.5.208' })) {
    Write-Host '  Installing NuGet provider...' -ForegroundColor Yellow
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force -Scope CurrentUser | Out-Null
    Write-Host '  NuGet provider installed.' -ForegroundColor Green
}
else {
    Write-Host '  NuGet provider OK.' -ForegroundColor Green
}

foreach ($module in @('Microsoft.Graph.Authentication')) {
    if (-not (Get-Module -Name $module -ListAvailable)) {
        Write-Host "  Installing module '$module'..." -ForegroundColor Yellow
        Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
        Write-Host "  Module '$module' installed." -ForegroundColor Green
    }
    else {
        Write-Host "  Module '$module' OK." -ForegroundColor Green
    }
    Import-Module -Name $module -ErrorAction Stop
}

Write-Host '  Prerequisites OK.' -ForegroundColor Green
Write-Host ''

# ---------------------------------------------------------------------------
# Interactive Graph authentication - only if no active session with required scope
# ---------------------------------------------------------------------------
$requiredScope = 'Group.ReadWrite.All'
$ctx = Get-MgContext

if (-not $ctx -or ($ctx.Scopes -notcontains $requiredScope)) {
    Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor White
    Write-Host '  A browser window will open for interactive sign-in.' -ForegroundColor DarkGray
    Connect-MgGraph -Scopes $requiredScope -NoWelcome -ErrorAction Stop
    $ctx = Get-MgContext
}
else {
    Write-Host 'Using existing Microsoft Graph session.' -ForegroundColor DarkGray
}

Write-Host ''
Write-Host '  Signed in as : ' -NoNewline -ForegroundColor Green
Write-Host $ctx.Account
Write-Host '  Tenant ID    : ' -NoNewline -ForegroundColor Green
Write-Host $ctx.TenantId
Write-Host ''

# ---------------------------------------------------------------------------
# Group definitions
# Autopilot Group Tags map to the [OrderID] physical device property in Entra ID
# ---------------------------------------------------------------------------
$groups = @(
    [PSCustomObject]@{
        DisplayName     = 'PAW-Global-Devices'
        Description     = 'Dynamic device group - Autopilot devices with Group Tag PAW'
        MailNickname    = 'PAW-Global-Devices'
        MembershipRule  = '(device.devicePhysicalIds -any (_ -eq "[OrderID]:PAW"))'
    }
    [PSCustomObject]@{
        DisplayName     = 'EUD-Global-Devices'
        Description     = 'Dynamic device group - Autopilot devices with Group Tag EUD'
        MailNickname    = 'EUD-Global-Devices'
        MembershipRule  = '(device.devicePhysicalIds -any (_ -eq "[OrderID]:EUD"))'
    }
)

# ---------------------------------------------------------------------------
# Create groups
# ---------------------------------------------------------------------------
foreach ($group in $groups) {

    Write-Host "Checking for existing group '$($group.DisplayName)'..." -ForegroundColor White

    $escapedName = $group.DisplayName -replace "'", "''"
    $existing = (Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$escapedName'").value |
        Select-Object -First 1

    if ($existing) {
        Write-Host "  Group '$($group.DisplayName)' already exists (ID: $($existing.id)) - skipping." -ForegroundColor Yellow
    }
    else {
        Write-Host "  Creating group '$($group.DisplayName)'..." -ForegroundColor White

        $body = [ordered]@{
            displayName                   = $group.DisplayName
            description                   = $group.Description
            mailNickname                  = $group.MailNickname
            mailEnabled                   = $false
            securityEnabled               = $true
            groupTypes                    = @('DynamicMembership')
            membershipRule                = $group.MembershipRule
            membershipRuleProcessingState = 'On'
        } | ConvertTo-Json

        $created = Invoke-MgGraphRequest -Method POST -ContentType 'application/json' `
            -Uri 'https://graph.microsoft.com/v1.0/groups' -Body $body

        Write-Host "  Group '$($group.DisplayName)' created (ID: $($created.id))" -ForegroundColor Green
        Write-Host "  Membership rule : $($group.MembershipRule)" -ForegroundColor DarkGray
    }
    Write-Host ''
}

Write-Host 'Done.' -ForegroundColor Cyan
