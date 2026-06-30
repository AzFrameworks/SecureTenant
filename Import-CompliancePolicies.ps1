<#
    .SYNOPSIS
    Creates three Windows compliance policies (Defender-for-Endpoint, Immediate, Delayed)
    in Intune for both PAW and EUD tenants — no external files needed.

    .DESCRIPTION
    For each tenant (PAW and EUD) the script:
      - Looks up the scope tag and target group from Intune / Entra ID
      - Creates the three compliance policies if they do not already exist
      - Assigns each policy to the matching group

    .PARAMETER PAWCSMVersion
    Version string embedded in policy display names, e.g. "PAW-Global-2503-Immediate".
    Defaults to "2503".

    .NOTES
    Required Graph scopes:
        DeviceManagementConfiguration.ReadWrite.All
        Group.ReadWrite.All
        DeviceManagementRBAC.Read.All

    .EXAMPLE
    .\Import-CompliancePolicies.ps1
    .\Import-CompliancePolicies.ps1 -PAWCSMVersion "2410"
#>
[CmdletBinding()]
param(
    [string] $PAWCSMVersion = '2606'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Prerequisites ─────────────────────────────────────────────────────────────
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

# ── Graph connection ──────────────────────────────────────────────────────────
Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All', 'Group.ReadWrite.All', 'DeviceManagementRBAC.Read.All' -NoWelcome

# ── Policy templates ──────────────────────────────────────────────────────────
# Shared baseline settings — overridden per-template below
$baseline = @{
    '@odata.type'                               = '#microsoft.graph.windows10CompliancePolicy'
    passwordRequired                             = $false
    passwordBlockSimple                          = $false
    passwordRequiredToUnlockFromIdle             = $false
    passwordMinutesOfInactivityBeforeLock        = $null
    passwordExpirationDays                       = $null
    passwordMinimumLength                        = $null
    passwordMinimumCharacterSetCount             = $null
    passwordRequiredType                         = 'deviceDefault'
    passwordPreviousPasswordBlockCount           = $null
    requireHealthyDeviceReport                   = $false
    osMinimumVersion                             = '10.0.26200.8655'
    osMaximumVersion                             = $null
    mobileOsMinimumVersion                       = $null
    mobileOsMaximumVersion                       = $null
    earlyLaunchAntiMalwareDriverEnabled          = $false
    storageRequireEncryption                     = $false
    defenderVersion                              = $null
    configurationManagerComplianceRequired       = $false
    deviceCompliancePolicyScript                 = $null
    validOperatingSystemBuildRanges              = @()
}

$policyTemplates = @(
    @{
        Suffix      = 'Defender-for-Endpoint'
        Description = "Defender for Endpoint specific compliance settings to apply immediately`n"
        Override    = @{
            bitLockerEnabled                             = $false
            secureBootEnabled                            = $false
            codeIntegrityEnabled                         = $false
            activeFirewallRequired                       = $false
            defenderEnabled                              = $false
            signatureOutOfDate                           = $false
            rtpEnabled                                   = $false
            antivirusRequired                            = $false
            antiSpywareRequired                          = $false
            deviceThreatProtectionEnabled                = $true
            deviceThreatProtectionRequiredSecurityLevel  = 'secured'
            tpmRequired                                  = $false
        }
        GracePeriodHours = 0
    },
    @{
        Suffix      = 'Immediate'
        Description = "Compliance settings to apply immediately`n"
        Override    = @{
            bitLockerEnabled                             = $false
            secureBootEnabled                            = $false
            codeIntegrityEnabled                         = $false
            activeFirewallRequired                       = $true
            defenderEnabled                              = $true
            signatureOutOfDate                           = $false
            rtpEnabled                                   = $true
            antivirusRequired                            = $true
            antiSpywareRequired                          = $true
            deviceThreatProtectionEnabled                = $false
            deviceThreatProtectionRequiredSecurityLevel  = 'unavailable'
            tpmRequired                                  = $true
        }
        GracePeriodHours = 0
    },
    @{
        Suffix      = 'Delayed'
        Description = "Compliance settings to apply after 4 hours`n"
        Override    = @{
            bitLockerEnabled                             = $true
            secureBootEnabled                            = $true
            codeIntegrityEnabled                         = $true
            activeFirewallRequired                       = $true
            defenderEnabled                              = $true
            signatureOutOfDate                           = $true
            rtpEnabled                                   = $true
            antivirusRequired                            = $true
            antiSpywareRequired                          = $true
            deviceThreatProtectionEnabled                = $false
            deviceThreatProtectionRequiredSecurityLevel  = 'unavailable'
            tpmRequired                                  = $true
        }
        GracePeriodHours = 4
    }
)

# ── Tenant definitions ────────────────────────────────────────────────────────
$tenants = @(
    @{ Prefix = 'PAW-Global'; ScopeTagName = 'PAW'; GroupName = 'PAW-Global-Users'; AutoCreate = $false },
    @{ Prefix = 'EUD-Global'; ScopeTagName = 'EUD'; GroupName = 'EUD-Global-Users'; AutoCreate = $true  }
)

# ── One-time lookups ──────────────────────────────────────────────────────────
Write-Host "`nResolving scope tags and groups..." -ForegroundColor White

foreach ($tenant in $tenants) {
    $escaped = $tenant.ScopeTagName -replace "'", "''"
    $tagResp  = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags?`$filter=displayName eq '$escaped'"
    $tag = $tagResp.value | Select-Object -First 1
    if (-not $tag) { throw "Scope tag '$($tenant.ScopeTagName)' not found in Intune." }
    $tenant.ScopeTagId = $tag.id
    Write-Host "  Scope tag '$($tenant.ScopeTagName)' → $($tag.id)" -ForegroundColor DarkGray

    $escaped   = $tenant.GroupName -replace "'", "''"
    $groupResp = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$escaped'&`$select=id,displayName"
    $group = $groupResp.value | Select-Object -First 1
    if (-not $group) {
        if ($tenant.AutoCreate) {
            $mailNickname = $tenant.GroupName -replace '[^a-zA-Z0-9]', ''
            $newGroup = Invoke-MgGraphRequest -Method POST -ContentType 'application/json' `
                -Uri 'https://graph.microsoft.com/v1.0/groups' `
                -Body (@{
                    displayName     = $tenant.GroupName
                    mailEnabled     = $false
                    mailNickname    = $mailNickname
                    securityEnabled = $true
                    groupTypes      = @()
                } | ConvertTo-Json)
            $tenant.GroupId = $newGroup.id
            Write-Host "  Group '$($tenant.GroupName)' created (ID: $($newGroup.id))" -ForegroundColor Green
        } else {
            throw "Entra group '$($tenant.GroupName)' not found."
        }
    } else {
        $tenant.GroupId = $group.id
        Write-Host "  Group '$($tenant.GroupName)' → $($group.id)" -ForegroundColor DarkGray
    }
}

# ── Helper: check if policy already exists ────────────────────────────────────
function Get-CompliancePolicyId {
    param([string] $DisplayName)
    $escaped  = $DisplayName -replace "'", "''"
    $response = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?`$filter=displayName eq '$escaped'"
    ($response.value | Select-Object -First 1)?.id
}

# ── Main loop ─────────────────────────────────────────────────────────────────
foreach ($tenant in $tenants) {
    Write-Host "`n═══ $($tenant.Prefix) (scope: $($tenant.ScopeTagName) / group: $($tenant.GroupName)) ═══" -ForegroundColor Magenta

    foreach ($template in $policyTemplates) {
        $displayName = "$($tenant.Prefix)-$PAWCSMVersion-$($template.Suffix)"
        Write-Host "`n  ─── $displayName ───" -ForegroundColor Cyan

        # 1. Skip if already exists
        $policyId = Get-CompliancePolicyId -DisplayName $displayName
        if ($policyId) {
            Write-Host "    Already exists (ID: $policyId)" -ForegroundColor Yellow
        }
        else {
            # 2. Build policy body (baseline + per-template overrides)
            $body = $baseline.Clone()
            foreach ($key in $template.Override.Keys) { $body[$key] = $template.Override[$key] }

            $body['displayName']      = $displayName
            $body['description']      = $template.Description
            $body['roleScopeTagIds']  = @($tenant.ScopeTagId)
            $body['scheduledActionsForRule'] = @(
                @{
                    ruleName = $null
                    scheduledActionConfigurations = @(
                        @{
                            gracePeriodHours        = $template.GracePeriodHours
                            actionType              = 'block'
                            notificationTemplateId  = '00000000-0000-0000-0000-000000000000'
                            notificationMessageCCList = @()
                        }
                    )
                }
            )

            $created  = Invoke-MgGraphRequest -Method POST -ContentType 'application/json' `
                -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies' `
                -Body ($body | ConvertTo-Json -Depth 10)
            $policyId = $created.id
            Write-Host "    Created (ID: $policyId)" -ForegroundColor Green
        }

        # 3. Assign to group
        $assignUri  = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$policyId/assign"
        $assignBody = @{
            assignments = @(
                @{
                    target = @{
                        '@odata.type'                              = '#microsoft.graph.groupAssignmentTarget'
                        groupId                                    = $tenant.GroupId
                        deviceAndAppManagementAssignmentFilterType = 'none'
                        deviceAndAppManagementAssignmentFilterId   = $null
                    }
                }
            )
        } | ConvertTo-Json -Depth 5

        Invoke-MgGraphRequest -Method POST -ContentType 'application/json' `
            -Uri $assignUri -Body $assignBody | Out-Null
        Write-Host "    Assigned to '$($tenant.GroupName)'." -ForegroundColor Green
    }
}

Write-Host "`nDone." -ForegroundColor Cyan
