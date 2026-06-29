<#
.SYNOPSIS
    Configures Privileged Identity Management (PIM) settings for 42 Entra ID roles.
.DESCRIPTION
    For each of 29 Entra ID roles this script:
      - Creates a role-assignable security group named PIM-2606-<RoleName> (skips if already exists)
      - Permanently assigns the group to the corresponding Entra ID role (active, no expiration)
      - Configures the PIM role policy:
          Tier 1 roles (9 high-privilege): 2-hour max activation, 6-month max eligibility
          Tier 2 roles (20 standard):      4-hour max activation, 12-month max eligibility
      - Requires MFA and justification for every activation
      - Requires approval for activation of all roles except Global Administrator;
        the approver group is PIM-2606-Global-Administrator

    Role definition IDs are resolved from the tenant at runtime to avoid hardcoded-GUID drift.
    Installs NuGet and the Microsoft.Graph.Authentication module if not present.
    Reuses an existing Microsoft Graph session when required scopes are already granted.
.PARAMETER TenantId
    Optional tenant ID for explicit tenant targeting. Omit to authenticate interactively
    against the home tenant.
.EXAMPLE
    .\Import-PIMSettings.ps1
.EXAMPLE
    .\Import-PIMSettings.ps1 -TenantId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
#>

<#
DISCLAIMER
----------
This script is provided "AS IS" without warranty of any kind, express or implied,
including but not limited to warranties of merchantability, fitness for a particular
purpose, or non-infringement. Use at your own risk.

The author and contributors shall not be held liable for any direct, indirect,
incidental, special, exemplary, or consequential damages (including but not limited
to data loss, service disruption, compliance violations, or security incidents)
arising from the use or inability to use this script, even if advised of the
possibility of such damage.

This script modifies Privileged Identity Management policies and creates security
groups in your Entra ID tenant. Review all changes in a non-production environment
before executing in production. Ensure you have appropriate authorisation and that
your organisation's change management processes have been followed.

The author assumes no responsibility for misuse, misconfiguration, or unintended
consequences of running this script.
#>

[CmdletBinding()]
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

foreach ($mod in @('Microsoft.Graph.Authentication')) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "Installing module $mod ..." -ForegroundColor Cyan
        Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber
    }
    if (-not (Get-Module -Name $mod)) {
        Import-Module -Name $mod -ErrorAction Stop
    }
}

#endregion Prerequisites

#region Authentication

$requiredScopes = @(
    'RoleManagement.ReadWrite.Directory',     # permanent role assignments + role-assignable group creation
    'RoleManagementPolicy.ReadWrite.Directory', # PIM role policy rule PATCH
    'Group.ReadWrite.All'
)

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

#region Role Definitions

# Tier 1: 2-hour max activation, 6-month max eligibility
# Tier 2: 4-hour max activation, 12-month max eligibility
# RequiresApproval: $false only for Global Administrator
# Role definition IDs are resolved from the tenant at runtime (see Main region) to avoid
# hardcoded-GUID drift as Microsoft occasionally changes or adds role definitions.
$roles = @(
    [PSCustomObject]@{ Name = 'Global Administrator';                          Tier = 1; RequiresApproval = $false }
    [PSCustomObject]@{ Name = 'Intune Administrator';                          Tier = 1; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Exchange Administrator';                        Tier = 1; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Conditional Access Administrator';              Tier = 1; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Authentication Administrator';                  Tier = 1; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Authentication Policy Administrator';           Tier = 1; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Privileged Authentication Administrator';       Tier = 1; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Privileged Role Administrator';                 Tier = 1; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Security Administrator';                        Tier = 1; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Application Administrator';                     Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Cloud Application Administrator';               Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Cloud Device Administrator';                    Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Compliance Administrator';                      Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Compliance Data Administrator';                 Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Exchange Recipient Administrator';              Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'External ID User Flow Administrator';           Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'External ID User Flow Attribute Administrator'; Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Global Reader';                                 Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Groups Administrator';                          Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Helpdesk Administrator';                        Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Hybrid Identity Administrator';                 Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Identity Governance Administrator';             Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Knowledge Administrator';                       Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Password Administrator';                        Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Security Operator';                             Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'SharePoint Administrator';                      Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Teams Administrator';                           Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'User Administrator';                            Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Application Developer';                         Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Agent ID Administrator';                        Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'AI Administrator';                              Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'AI Reader';                                     Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Attribute Provisioning Administrator';          Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Attribute Provisioning Reader';                 Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Authentication Extensibility Administrator';    Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Authentication Extensibility Password Administrator'; Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'B2C IEF Keyset Administrator';                 Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Directory Writers';                             Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Domain Name Administrator';                     Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'External Identity Provider Administrator';      Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Lifecycle Workflows Administrator';             Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Name = 'Security Reader';                               Tier = 2; RequiresApproval = $true  }
)

#endregion Role Definitions

#region Helper Functions

function Get-RoleDefinitionId {
    param([string] $DisplayName)
    $filter   = [Uri]::EscapeDataString("displayName eq '$DisplayName' and isBuiltIn eq true")
    $response = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$filter=$filter&`$select=id,displayName"
    $roleDef = $response.value | Select-Object -First 1
    if (-not $roleDef) { throw "Role definition not found in tenant: '$DisplayName'" }
    return $roleDef.id
}

function Get-OrCreateGroup {
    param(
        [string] $DisplayName,
        [string] $Description
    )
    $filter   = [Uri]::EscapeDataString("displayName eq '$DisplayName'")
    $response = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=$filter&`$select=id,displayName,isAssignableToRole"
    $group = $response.value | Select-Object -First 1
    if ($group) {
        if (-not $group.isAssignableToRole) {
            Write-Warning "Group '$DisplayName' already exists but is NOT role-assignable. Delete it in Entra ID and re-run this script to recreate it correctly (isAssignableToRole cannot be set on existing groups)."
        } else {
            Write-Host "    Group already exists: $DisplayName" -ForegroundColor DarkGray
        }
        return $group
    }
    $mailNickname = $DisplayName -replace '[^a-zA-Z0-9\-]', '-'
    $body = @{
        displayName        = $DisplayName
        description        = $Description
        mailEnabled        = $false
        mailNickname       = $mailNickname
        securityEnabled    = $true
        isAssignableToRole = $true
        groupTypes         = @()
    } | ConvertTo-Json -Depth 3
    $created = Invoke-MgGraphRequest -Method POST `
        -Uri 'https://graph.microsoft.com/v1.0/groups' `
        -ContentType 'application/json' `
        -Body $body
    Write-Host "    Created role-assignable group: $DisplayName - waiting 20s for Entra ID replication..." -ForegroundColor Green
    Start-Sleep -Seconds 20
    return $created
}

function Set-PermanentRoleAssignment {
    param(
        [string] $RoleId,
        [string] $GroupId
    )
    $filter   = [Uri]::EscapeDataString(
        "principalId eq '$GroupId' and roleDefinitionId eq '$RoleId' and directoryScopeId eq '/'"
    )
    $existing = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules?`$filter=$filter"
    if ($existing.value -and $existing.value.Count -gt 0) {
        Write-Host '    Permanent role assignment already exists for this group.' -ForegroundColor DarkGray
        return
    }
    $startTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $body = @{
        action           = 'adminAssign'
        justification    = 'Permanent role assignment for PIM access group - via Import-PIMSettings.ps1'
        roleDefinitionId = $RoleId
        directoryScopeId = '/'
        principalId      = $GroupId
        scheduleInfo     = @{
            startDateTime = $startTime
            expiration    = @{ type = 'noExpiration' }
        }
    } | ConvertTo-Json -Depth 5
    $assignUri   = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests'
    $maxAttempts = 6
    $retryDelay  = 15
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Invoke-MgGraphRequest -Method POST -Uri $assignUri -ContentType 'application/json' -Body $body | Out-Null
            Write-Host '    Group permanently assigned to role (no expiration).' -ForegroundColor Green
            return
        }
        catch {
            $errText = $_.ToString()
            if ($attempt -lt $maxAttempts -and ($errText -match 'SubjectNotFound' -or $errText -match '404')) {
                Write-Host "    Group not yet replicated; retrying in $retryDelay s (attempt $attempt/$maxAttempts)..." -ForegroundColor Yellow
                Start-Sleep -Seconds $retryDelay
            } else {
                throw
            }
        }
    }
}

function Get-PolicyIdForRole {
    param([string] $RoleId)
    $filter   = [Uri]::EscapeDataString(
        "scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$RoleId'"
    )
    $response = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?`$filter=$filter"
    $assignment = $response.value | Select-Object -First 1
    if (-not $assignment) {
        throw "No PIM policy assignment found for role '$RoleId'. Ensure PIM is enabled in this tenant."
    }
    return $assignment.policyId
}

function Set-PolicyExpirationRule {
    param(
        [string] $PolicyId,
        [string] $RuleId,
        [string] $Duration,
        [bool]   $ForceExpirationRequired = $false
    )
    $ruleUri = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/$PolicyId/rules/$RuleId"
    # GET the live rule so all system-required fields are preserved; hand-built bodies are rejected
    $rule = Invoke-MgGraphRequest -Method GET -Uri $ruleUri
    $rule.Remove('@odata.context')
    # isExpirationRequired may not be writable for Expiration_Admin_Eligibility on built-in roles;
    # only force it for the activation rule where it is known to be accepted
    if ($ForceExpirationRequired) { $rule['isExpirationRequired'] = $true }
    $rule['maximumDuration'] = $Duration
    Invoke-MgGraphRequest -Method PATCH -Uri $ruleUri -ContentType 'application/json' `
        -Body ($rule | ConvertTo-Json -Depth 10) | Out-Null
}

function Set-PolicyEnablementRule {
    param(
        [string]   $PolicyId,
        [string[]] $EnabledRules
    )
    $ruleUri = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/$PolicyId/rules/Enablement_EndUser_Assignment"
    $rule = Invoke-MgGraphRequest -Method GET -Uri $ruleUri
    $rule.Remove('@odata.context')
    $rule['enabledRules'] = $EnabledRules
    Invoke-MgGraphRequest -Method PATCH -Uri $ruleUri -ContentType 'application/json' `
        -Body ($rule | ConvertTo-Json -Depth 10) | Out-Null
}

function Set-PolicyApprovalRule {
    param(
        [string] $PolicyId,
        [bool]   $RequiresApproval,
        [string] $ApproverGroupId,
        [string] $ApproverGroupName
    )
    if ($RequiresApproval) {
        $setting = @{
            '@odata.type'                    = '#microsoft.graph.approvalSettings'
            isApprovalRequired               = $true
            isApprovalRequiredForExtension   = $false
            isRequestorJustificationRequired = $true
            approvalMode                     = 'SingleStage'
            approvalStages                   = @(
                @{
                    '@odata.type'                   = '#microsoft.graph.unifiedApprovalStage'
                    approvalStageTimeOutInDays      = 1
                    isApproverJustificationRequired = $true
                    escalationTimeInMinutes         = 0
                    isEscalationEnabled             = $false
                    primaryApprovers                = @(
                        @{
                            '@odata.type' = '#microsoft.graph.groupMembers'
                            isBackup      = $false
                            id            = $ApproverGroupId
                            description   = $ApproverGroupName
                        }
                    )
                    escalationApprovers = @()
                }
            )
        }
    } else {
        $setting = @{
            '@odata.type'                    = '#microsoft.graph.approvalSettings'
            isApprovalRequired               = $false
            isApprovalRequiredForExtension   = $false
            isRequestorJustificationRequired = $true
            approvalMode                     = 'SingleStage'
            approvalStages                   = @()
        }
    }
    $body = @{
        '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyApprovalRule'
        id            = 'Approval_EndUser_Assignment'
        target        = @{
            '@odata.type'       = 'microsoft.graph.unifiedRoleManagementPolicyRuleTarget'
            caller              = 'EndUser'
            operations          = @('all')
            level               = 'Assignment'
            inheritableSettings = @()
            enforcedSettings    = @()
        }
        setting = $setting
    } | ConvertTo-Json -Depth 10
    Invoke-MgGraphRequest -Method PATCH `
        -Uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/$PolicyId/rules/Approval_EndUser_Assignment" `
        -ContentType 'application/json' `
        -Body $body | Out-Null
}

#endregion Helper Functions

#region Main

Write-Host ''
Write-Host 'Resolving role definition IDs from tenant...' -ForegroundColor Cyan
foreach ($role in $roles) {
    $role | Add-Member -NotePropertyName 'Id' -NotePropertyValue (Get-RoleDefinitionId -DisplayName $role.Name) -Force
    Write-Host "  $($role.Name): $($role.Id)" -ForegroundColor DarkGray
}
Write-Host "  All $($roles.Count) role IDs resolved." -ForegroundColor Green

$approverGroupName = 'PIM-2606-Global-Administrator'
Write-Host ''
Write-Host "Resolving approver group '$approverGroupName' ..." -ForegroundColor Cyan
$approverGroup   = Get-OrCreateGroup -DisplayName $approverGroupName `
    -Description 'PIM access group and activation approver group for Global Administrator role'
$approverGroupId = $approverGroup.id
Write-Host "  Approver group ID: $approverGroupId" -ForegroundColor DarkGray

$total   = $roles.Count
$current = 0

foreach ($role in $roles) {
    $current++
    $groupName = 'PIM-2606-' + ($role.Name -replace ' ', '-')

    if ($role.Tier -eq 1) {
        $activationDuration  = 'PT2H'
        $eligibilityDuration = 'P180D'   # 6 months in days — PIM API rejects P6M
    } else {
        $activationDuration  = 'PT4H'
        $eligibilityDuration = 'P365D'   # 1 year in days — PIM API rejects P1Y
    }

    Write-Host ''
    Write-Host "[$current/$total] $($role.Name)  (Tier $($role.Tier)  |  approval: $($role.RequiresApproval))" -ForegroundColor White

    try {
        # 1. Security group
        Write-Host '  [1/7] Security group...' -ForegroundColor DarkGray
        $group   = Get-OrCreateGroup -DisplayName $groupName `
            -Description "PIM access group for Entra ID role: $($role.Name)"
        $groupId = $group.id

        # 2. Assign group permanently to role (no expiration)
        Write-Host '  [2/7] Assigning group permanently to role...' -ForegroundColor DarkGray
        Set-PermanentRoleAssignment -RoleId $role.Id -GroupId $groupId

        # 3. Role PIM policy ID
        Write-Host '  [3/7] Retrieving role PIM policy...' -ForegroundColor DarkGray
        $policyId = Get-PolicyIdForRole -RoleId $role.Id
        Write-Host "    Policy ID: $policyId" -ForegroundColor DarkGray

        # 4. Max activation time
        Write-Host "  [4/7] Setting max activation to $activationDuration ..." -ForegroundColor DarkGray
        Set-PolicyExpirationRule -PolicyId $policyId `
            -RuleId                  'Expiration_EndUser_Assignment' `
            -Duration                $activationDuration `
            -ForceExpirationRequired $true

        # 5. Max eligibility period
        Write-Host "  [5/7] Setting max eligibility to $eligibilityDuration ..." -ForegroundColor DarkGray
        Set-PolicyExpirationRule -PolicyId $policyId `
            -RuleId   'Expiration_Admin_Eligibility' `
            -Duration $eligibilityDuration

        # 6. Require MFA and justification for every activation
        Write-Host '  [6/7] Requiring MFA and justification for activation...' -ForegroundColor DarkGray
        Set-PolicyEnablementRule -PolicyId $policyId `
            -EnabledRules @('MultiFactorAuthentication', 'Justification')

        # 7. Approval rule
        Write-Host '  [7/7] Configuring approval rule...' -ForegroundColor DarkGray
        Set-PolicyApprovalRule -PolicyId $policyId `
            -RequiresApproval  $role.RequiresApproval `
            -ApproverGroupId   $approverGroupId `
            -ApproverGroupName $approverGroupName

        Write-Host '  OK' -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to process role '$($role.Name)': $_"
    }
}

Write-Host ''
Write-Host "PIM configuration complete. $total roles processed." -ForegroundColor Green

#endregion Main
