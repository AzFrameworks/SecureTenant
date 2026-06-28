<#
.SYNOPSIS
    Disables Entra ID Security Defaults if they are currently enabled.
.DESCRIPTION
    Installs required modules, authenticates to Microsoft Graph, reads the current
    Security Defaults enforcement policy, and disables it if it is enabled.
    If Security Defaults are already disabled the script exits without making any
    changes. The script is self-sufficient and requires no external files or
    specific execution path.
.EXAMPLE
    .\Disable-SecurityDefaults.ps1
#>

<#
DISCLAIMER
----------
This script is provided "AS IS" without warranty of any kind, express or implied,
including but not limited to warranties of merchantability, fitness for a particular
purpose, or non-infringement. Use at your own risk.

The author(s) and contributors accept no liability for any damage, data loss, or
unintended configuration changes resulting from the use of this script.

Disabling Security Defaults removes baseline protections from your tenant. Ensure
that equivalent or stronger controls (e.g. Conditional Access policies) are in
place before disabling Security Defaults.

Always review and test this script in a non-production / staging environment before
running it against any production tenant.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
$requiredScope = 'Policy.ReadWrite.ConditionalAccess'
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
# Read current Security Defaults state
# ---------------------------------------------------------------------------
$policyUri = 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'

Write-Host 'Reading Security Defaults policy...' -ForegroundColor White
$policy = Invoke-MgGraphRequest -Method GET -Uri $policyUri

if ($policy.isEnabled -eq $false) {
    Write-Host '  Security Defaults are already disabled - no changes made.' -ForegroundColor Green
    Write-Host ''
    Write-Host 'Done.' -ForegroundColor Cyan
    exit 0
}

Write-Host '  Security Defaults are currently ENABLED.' -ForegroundColor Yellow
Write-Host ''

# ---------------------------------------------------------------------------
# Disable Security Defaults
# ---------------------------------------------------------------------------
Write-Host 'Disabling Security Defaults...' -ForegroundColor White

$body = '{"isEnabled": false}'
Invoke-MgGraphRequest -Method PATCH -ContentType 'application/json' -Uri $policyUri -Body $body

Write-Host '  Security Defaults have been disabled.' -ForegroundColor Green
Write-Host ''
Write-Host 'Done.' -ForegroundColor Cyan
