#Requires -Version 5.1
<#
.SYNOPSIS
    Creates Restricted Management Administrative Units (RMAUs) for the PAWCSM framework.
.DESCRIPTION
    Creates four RMAUs used by the PAW control plane:
      CP.BreakGlass         — assigned membership, no direct role assignments
      CP.PAW-Users          — assigned membership, PAW user objects and selected groups
      CP.PAW-SolutionAssets — assigned membership, PAW solution objects and groups
      CP.PAW-Devices        — dynamic membership, all PAW devices via OrderID or extensionAttribute1

    Existing AUs with a matching displayName are reported and skipped.
    Use -WhatIf to preview without making any changes.
.PARAMETER WhatIf
    Lists which AUs would be created without making any changes.
.PARAMETER TenantId
    Optional tenant ID for explicit tenant targeting.
.EXAMPLE
    .\Import-AdministrativeUnits.ps1 -WhatIf
.EXAMPLE
    .\Import-AdministrativeUnits.ps1
#>

<#
DISCLAIMER
----------
This script is provided "AS IS" without warranty of any kind, express or implied,
including but not limited to warranties of merchantability, fitness for a particular
purpose, or non-infringement. Use at your own risk.

The author and contributors shall not be held liable for any direct, indirect,
incidental, special, exemplary, or consequential damages arising from the use or
inability to use this script.

Restricted Management Administrative Units prevent even Global Administrators from
managing members without an explicit scoped role assignment. Ensure you have
appropriate authorisation and that your organisation's change management processes
have been followed before running this script.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string] $TenantId
)

#region Prerequisites

if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue |
        Where-Object { $_.Version -ge '2.8.5.201' })) {
    Write-Host 'Installing NuGet package provider...' -ForegroundColor Cyan
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
}

if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
    Write-Host 'Installing module Microsoft.Graph.Authentication...' -ForegroundColor Cyan
    Install-Module -Name 'Microsoft.Graph.Authentication' -Scope CurrentUser -Force -AllowClobber
}
Import-Module -Name 'Microsoft.Graph.Authentication' -ErrorAction Stop

#endregion Prerequisites

#region Authentication

$requiredScopes = @('AdministrativeUnit.ReadWrite.All')

$ctx = Get-MgContext
$missingScopes = if ($ctx) {
    $requiredScopes | Where-Object { $ctx.Scopes -notcontains $_ }
} else {
    $requiredScopes
}

if (-not $ctx -or $missingScopes) {
    $connectParams = @{
        Scopes      = $requiredScopes
        NoWelcome   = $true
        ErrorAction = 'Stop'
    }
    if ($TenantId) { $connectParams['TenantId'] = $TenantId }
    Connect-MgGraph @connectParams
    $ctx = Get-MgContext
} else {
    Write-Host 'Using existing Microsoft Graph session.' -ForegroundColor DarkGray
}

Write-Host "Connected as: $($ctx.Account)   Tenant: $($ctx.TenantId)" -ForegroundColor DarkGray

#endregion Authentication

#region Definitions

$administrativeUnits = @(
    [ordered]@{
        displayName                  = 'CP.BreakGlass'
        description                  = 'RMAU contains Control Plane related breakglass users and groups. No direct role assignments will be configured for this RMAU.'
        isMemberManagementRestricted = $true
        membershipType               = 'Assigned'
    }
    [ordered]@{
        displayName                  = 'CP.PAW-Users'
        description                  = 'RMAU contains Control Plane related PAW user objects and selected groups.'
        isMemberManagementRestricted = $true
        membershipType               = 'Assigned'
    }
    [ordered]@{
        displayName                  = 'CP.PAW-SolutionAssets'
        description                  = 'RMAU contains Control Plane related PAW solution objects, which are mainly all PAW related groups.'
        isMemberManagementRestricted = $true
        membershipType               = 'Assigned'
    }
    [ordered]@{
        displayName                   = 'CP.PAW-Devices'
        description                   = 'Dynamic RMAU contains Control Plane related PAW device objects, which are all PAW devices.'
        isMemberManagementRestricted  = $true
        membershipType                = 'Dynamic'
        membershipRule                = '(device.devicePhysicalIds -any _ -eq "[OrderID]:PAW") or (device.extensionAttribute1 -eq "PAW")'
        membershipRuleProcessingState = 'On'
    }
)

#endregion Definitions

#region Retrieve existing AUs

Write-Host ''
Write-Host 'Retrieving existing Administrative Units...' -ForegroundColor Cyan

$uri       = 'https://graph.microsoft.com/v1.0/directory/administrativeUnits?$select=id,displayName'
$existingAUs = [System.Collections.Generic.List[object]]::new()
do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    foreach ($au in $response.value) { $existingAUs.Add($au) }
    $uri = $response.'@odata.nextLink'
} while ($uri)

#endregion

#region Preview

Write-Host ''
Write-Host 'Administrative Units to process:' -ForegroundColor White
Write-Host ('-' * 72)
foreach ($au in $administrativeUnits) {
    $exists = $existingAUs | Where-Object { $_.displayName -eq $au.displayName }
    $status = if ($exists) { '[exists — will skip]' } else { '[will create]' }
    $type   = if ($au.membershipType -eq 'Dynamic') { 'Dynamic RMAU' } else { 'Assigned RMAU' }
    Write-Host ("  {0,-30} {1,-15} {2}" -f $au.displayName, $type, $status)
}
Write-Host ('-' * 72)

$toCreate = @($administrativeUnits | Where-Object {
    $name = $_.displayName
    -not ($existingAUs | Where-Object { $_.displayName -eq $name })
})

if ($PSCmdlet.ShouldProcess("$($toCreate.Count) Administrative Unit(s)", 'Create')) {
    # intentionally empty — ShouldProcess handles -WhatIf output automatically
} else {
    Write-Host ''
    Write-Host 'WhatIf: no changes made.' -ForegroundColor Yellow
    exit 0
}

#endregion Preview

#region Create

Write-Host ''
$succeeded = 0
$skipped   = 0
$failed    = 0

foreach ($au in $administrativeUnits) {
    $existing = $existingAUs | Where-Object { $_.displayName -eq $au.displayName }

    if ($existing) {
        Write-Host "  Exists:  $($au.displayName) (id: $($existing.id))" -ForegroundColor DarkGray
        $skipped++
        continue
    }

    try {
        $created = Invoke-MgGraphRequest -Method POST `
            -Uri 'https://graph.microsoft.com/v1.0/directory/administrativeUnits' `
            -ContentType 'application/json' `
            -Body ($au | ConvertTo-Json -Depth 5)
        Write-Host "  Created: $($au.displayName) (id: $($created.id))" -ForegroundColor Green
        $succeeded++
    } catch {
        Write-Warning "  Failed:  $($au.displayName): $_"
        $failed++
    }
}

Write-Host ''
Write-Host "Done. Created: $succeeded   Skipped: $skipped   Failed: $failed" `
    -ForegroundColor $(if ($failed -gt 0) { 'Yellow' } else { 'Green' })

#endregion Create
