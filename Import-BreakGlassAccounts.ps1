<#
.SYNOPSIS
    Creates and configures break glass accounts in Entra ID.
.DESCRIPTION
    Creates BreakGlass1 and BreakGlass2 user accounts on the tenant's primary verified
    domain and assigns Global Administrator to both.  Displays temporary passwords on
    creation — these must be saved immediately as they are not retrievable afterwards.

    Steps that are already in place (account exists, role already assigned) are skipped
    so the script is safe to re-run.

    Run this script before Import-CAPolicyFrameworkV2.ps1, which expects these accounts
    to pre-exist and uses their object IDs as CA policy exclusions.
.NOTES
    Required Graph scopes:
        User.ReadWrite.All
        RoleManagement.ReadWrite.Directory
        Directory.Read.All
.EXAMPLE
    .\Import-BreakGlassAccounts.ps1
#>

<#
DISCLAIMER
----------
This script is provided "AS IS" without warranty of any kind, express or implied,
including but not limited to warranties of merchantability, fitness for a particular
purpose, or non-infringement.  Use at your own risk.

The author and contributors shall not be held liable for any direct, indirect,
incidental, special, exemplary, or consequential damages arising from the use or
inability to use this script.

Break glass accounts are highly privileged.  Store the generated passwords in a
secure, offline location (e.g. a physical safe) immediately after running this script.
Ensure appropriate authorisation and change management processes have been followed.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Prerequisites

if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue |
        Where-Object { $_.Version -ge '2.8.5.201' })) {
    Write-Host "Installing NuGet package provider..." -ForegroundColor Yellow
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
}

foreach ($mod in @('Microsoft.Graph.Authentication')) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "Installing module '$mod'..." -ForegroundColor Yellow
        Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module -Name $mod -ErrorAction Stop
}

#endregion Prerequisites

#region Authentication

$requiredScopes = @(
    'User.ReadWrite.All'
    'RoleManagement.ReadWrite.Directory'
    'Directory.Read.All'
)

$ctx = Get-MgContext
$missingScopes = if ($ctx) {
    $requiredScopes | Where-Object { $ctx.Scopes -notcontains $_ }
} else {
    $requiredScopes
}

if (-not $ctx -or $missingScopes) {
    Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
    $ctx = Get-MgContext
} else {
    Write-Host "Using existing Microsoft Graph session." -ForegroundColor DarkGray
}

Write-Host "Connected as: $($ctx.Account)   Tenant: $($ctx.TenantId)" -ForegroundColor DarkGray

#endregion Authentication

#region Helpers

function New-RandomPassword {
    # Generates a 20-char password meeting Entra ID complexity requirements
    $charSets = @(
        'ABCDEFGHJKLMNPQRSTUVWXYZ'
        'abcdefghijkmnpqrstuvwxyz'
        '23456789'
        '!@#$%^&*'
    )
    $all    = $charSets -join ''
    $chars  = $charSets | ForEach-Object { $_[(Get-Random -Maximum $_.Length)] }
    $chars += (1..16) | ForEach-Object { $all[(Get-Random -Maximum $all.Length)] }
    -join ($chars | Get-Random -Count $chars.Count)
}

function Get-UserIdByUpn {
    param([string]$Upn)
    try {
        $r = Invoke-MgGraphRequest -Method GET `
                 -Uri "v1.0/users/$([System.Uri]::EscapeDataString($Upn))?`$select=id" `
                 -OutputType PSObject -ErrorAction Stop
        return $r.id
    } catch {
        if ($_.Exception.Message -notmatch 'Request_ResourceNotFound') {
            Write-Warning "Unexpected error looking up user '$Upn': $_"
        }
        return $null
    }
}

function Resolve-SoftDeletedBgUser {
    param([string]$Upn, [string]$Label)
    try {
        $del = Invoke-MgGraphRequest -Method GET `
            -Uri "v1.0/directory/deletedItems/microsoft.graph.user?`$filter=userPrincipalName eq '$Upn'&`$select=id,userPrincipalName,deletedDateTime" `
            -OutputType PSObject -ErrorAction Stop
        if ($null -ne $del.value -and $del.value.Count -gt 0) {
            $delId = $del.value[0].id
            Write-Host "  [ACTION REQUIRED] $Label '$Upn' exists in soft-deleted state (ID: $delId)." -ForegroundColor Red
            Write-Host "  Option A - Restore: Restore-MgDirectoryDeletedItem -DirectoryObjectId '$delId'" -ForegroundColor Yellow
            Write-Host "  Option B - Permanent-delete then re-run: Remove-MgDirectoryDeletedItem -DirectoryObjectId '$delId'" -ForegroundColor Yellow
        } else {
            Write-Host "  [ACTION REQUIRED] $Label '$Upn' could not be created and was not found anywhere." -ForegroundColor Red
            Write-Host "  Verify that the signed-in account has User.ReadWrite.All permission." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [WARN] Could not query soft-deleted items (check Directory.Read.All permission): $_" -ForegroundColor Yellow
    }
}

#endregion Helpers

#region Break Glass Accounts

$domainResp    = Invoke-MgGraphRequest -Method GET -Uri 'v1.0/domains?$select=id,isDefault' -OutputType PSObject
$defaultDomain = ($domainResp.value | Where-Object { $_.isDefault }).id
$bgUPN1        = "BreakGlass1@$defaultDomain"
$bgUPN2        = "BreakGlass2@$defaultDomain"
Write-Host "Primary domain: $defaultDomain" -ForegroundColor DarkGray

$breakGlass1Id = $null
$breakGlass2Id = $null

# ── Break Glass User 1 ────────────────────────────────────────────────────────

$breakGlass1Id = Get-UserIdByUpn -Upn $bgUPN1
if ($null -eq $breakGlass1Id) {
    $bgPassword1 = New-RandomPassword
    Write-Host "Creating Break Glass User 1 ($bgUPN1)..." -ForegroundColor Yellow
    Write-Host "  *** SAVE NOW — Temp password: $bgPassword1 ***" -ForegroundColor Red
    try {
        $r = Invoke-MgGraphRequest -Method POST -Uri 'v1.0/users' -OutputType PSObject `
                 -Body @{
                     displayName       = 'Break Glass User 1'
                     userPrincipalName = $bgUPN1
                     mailNickname      = 'BreakGlass1'
                     accountEnabled    = $true
                     passwordProfile   = @{
                         password                             = $bgPassword1
                         forceChangePasswordNextSignIn        = $true
                         forceChangePasswordNextSignInWithMfa = $true
                     }
                 } -ErrorAction Stop
        $breakGlass1Id = $r.id
    } catch {
        Write-Host "  [ERROR] POST failed for Break Glass User 1: $_" -ForegroundColor Red
        $breakGlass1Id = Get-UserIdByUpn -Upn $bgUPN1
        if ($null -eq $breakGlass1Id) {
            Resolve-SoftDeletedBgUser -Upn $bgUPN1 -Label 'Break Glass User 1'
        } else {
            Write-Host "  Break Glass User 1 resolved after conflict — account already existed." -ForegroundColor Green
        }
    }
} else {
    Write-Host "Break Glass User 1 already exists ($bgUPN1)." -ForegroundColor Green
}

# ── Break Glass User 2 ────────────────────────────────────────────────────────

$breakGlass2Id = Get-UserIdByUpn -Upn $bgUPN2
if ($null -eq $breakGlass2Id) {
    $bgPassword2 = New-RandomPassword
    Write-Host "Creating Break Glass User 2 ($bgUPN2)..." -ForegroundColor Yellow
    Write-Host "  *** SAVE NOW — Temp password: $bgPassword2 ***" -ForegroundColor Red
    try {
        $r = Invoke-MgGraphRequest -Method POST -Uri 'v1.0/users' -OutputType PSObject `
                 -Body @{
                     displayName       = 'Break Glass User 2'
                     userPrincipalName = $bgUPN2
                     mailNickname      = 'BreakGlass2'
                     accountEnabled    = $true
                     passwordProfile   = @{
                         password                             = $bgPassword2
                         forceChangePasswordNextSignIn        = $true
                         forceChangePasswordNextSignInWithMfa = $true
                     }
                 } -ErrorAction Stop
        $breakGlass2Id = $r.id
    } catch {
        Write-Host "  [ERROR] POST failed for Break Glass User 2: $_" -ForegroundColor Red
        $breakGlass2Id = Get-UserIdByUpn -Upn $bgUPN2
        if ($null -eq $breakGlass2Id) {
            Resolve-SoftDeletedBgUser -Upn $bgUPN2 -Label 'Break Glass User 2'
        } else {
            Write-Host "  Break Glass User 2 resolved after conflict — account already existed." -ForegroundColor Green
        }
    }
} else {
    Write-Host "Break Glass User 2 already exists ($bgUPN2)." -ForegroundColor Green
}

#endregion Break Glass Accounts

#region Global Administrator Role Assignment

$globalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'

foreach ($bgEntry in @(
    @{ Id = $breakGlass1Id; Name = 'Break Glass User 1' }
    @{ Id = $breakGlass2Id; Name = 'Break Glass User 2' }
)) {
    if ([string]::IsNullOrEmpty($bgEntry.Id)) {
        Write-Warning "Skipping role assignment for $($bgEntry.Name) — object ID not available."
        continue
    }

    $roleCheck = Invoke-MgGraphRequest -Method GET `
        -Uri "v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($bgEntry.Id)' and roleDefinitionId eq '$globalAdminRoleId'&`$select=id" `
        -OutputType PSObject -ErrorAction Stop

    if ($roleCheck.value -and $roleCheck.value.Count -gt 0) {
        Write-Host "'Global Administrator' already assigned to $($bgEntry.Name)." -ForegroundColor Green
    } else {
        Write-Host "Assigning 'Global Administrator' to $($bgEntry.Name)..." -ForegroundColor Yellow
        try {
            Invoke-MgGraphRequest -Method POST `
                -Uri 'v1.0/roleManagement/directory/roleAssignments' `
                -OutputType PSObject -ErrorAction Stop `
                -Body @{
                    '@odata.type'    = '#microsoft.graph.unifiedRoleAssignment'
                    roleDefinitionId = $globalAdminRoleId
                    principalId      = $bgEntry.Id
                    directoryScopeId = '/'
                } | Out-Null
            Write-Host "  Assigned." -ForegroundColor Green
        } catch {
            Write-Warning "Failed to assign Global Administrator to $($bgEntry.Name): $_"
        }
    }
}

#endregion Global Administrator Role Assignment

Write-Host ''
Write-Host "Break glass account setup complete." -ForegroundColor Cyan
if ($breakGlass1Id) { Write-Host "  BG1: $bgUPN1  ($breakGlass1Id)" -ForegroundColor DarkGray }
if ($breakGlass2Id) { Write-Host "  BG2: $bgUPN2  ($breakGlass2Id)" -ForegroundColor DarkGray }
