<#
.SYNOPSIS
    Configures Privileged Identity Management (PIM) settings for 29 Entra ID roles.
.DESCRIPTION
    For each of 29 Entra ID roles this script:
      - Creates a security group named PIM-2606-<RoleName> (skips if it already exists)
      - Assigns the group as eligible for the corresponding role
      - Configures the PIM policy activation duration and maximum eligibility period:
          Tier 1 roles (9 high-privilege): 2-hour max activation, 6-month max eligibility
          Tier 2 roles (20 standard):      4-hour max activation, 12-month max eligibility
      - Requires approval for activation of all roles except Global Administrator;
        the approver group is PIM-2606-Global-Administrator

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
    'RoleManagement.ReadWrite.Directory',        # required to create role-assignable groups
    'RoleManagementPolicy.ReadWrite.Directory',
    'RoleEligibilitySchedule.ReadWrite.Directory',
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
$roles = @(
    [PSCustomObject]@{ Id = '62e90394-69f5-4237-9190-012177145e10'; Name = 'Global Administrator';                     Tier = 1; RequiresApproval = $false }
    [PSCustomObject]@{ Id = '3a2c62db-5318-420d-8d74-23affee5d9d5'; Name = 'Intune Administrator';                    Tier = 1; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = '9360feb5-f418-4baa-8175-e2a00bac4301'; Name = 'Exchange Administrator';                  Tier = 1; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'; Name = 'Conditional Access Administrator';        Tier = 1; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = 'c4e39bd9-1100-46d3-8c65-fb160da0071f'; Name = 'Authentication Administrator';            Tier = 1; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = '0526716b-113d-4c15-b2c8-68e3c22b9f80'; Name = 'Authentication Policy Administrator';     Tier = 1; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'; Name = 'Privileged Authentication Administrator'; Tier = 1; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'; Name = 'Privileged Role Administrator';           Tier = 1; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = '5d6b6bb7-de71-4623-b4af-96380a352509'; Name = 'Security Administrator';                  Tier = 1; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'; Name = 'Application Administrator';              Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = '158c047a-c907-4556-b7ef-446551a6b5f7'; Name = 'Cloud Application Administrator';         Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = '7698a772-787b-4ac8-901f-60d6b08affd2'; Name = 'Cloud Device Administrator';              Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = 'cf1c38e5-3621-4004-a7cb-879624dced7c'; Name = 'Compliance Administrator';                Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = 'ecb2c6bf-0ab6-418e-bd87-7986f8d63bbe'; Name = 'Compliance Data Administrator';           Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = '29232cdf-9323-42fd-ade2-1d097af3e4de'; Name = 'Exchange Recipient Administrator';        Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = 'be2f45a1-457d-42af-a067-6ec1fa63bc45'; Name = 'External ID User Flow Administrator';     Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = '59d46f88-662b-457b-bceb-5c3809e5908f'; Name = 'External ID Attribute Administrator';     Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = 'f2ef992c-3afb-46b9-b7cf-a126ee74c451'; Name = 'Global Reader';                           Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = 'fdd7a751-b60b-444a-984c-02652fe8fa1c'; Name = 'Groups Administrator';                    Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = '729827e3-9c14-49f7-bb1b-9608f156bbb8'; Name = 'Helpdesk Administrator';                  Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = '8329153b-31d0-4727-b945-745eb3bc5f31'; Name = 'Hybrid Identity Administrator';           Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = '194ae4cb-b126-40b2-bd5b-6091b380977d'; Name = 'Identity Governance Administrator';       Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = 'aaf43236-0c0d-4d5f-883a-6955382ac081'; Name = 'Knowledge Administrator';                 Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = '966707d0-3269-4727-9be2-8c3a10f19b9d'; Name = 'Password Administrator';                  Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = '5f2222b1-57c3-48ba-8ad5-d4759f1fde6f'; Name = 'Security Operator';                       Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = 'fe930be7-5e62-47db-91af-98c3a49a38b1'; Name = 'SharePoint Administrator';                Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = '422218e4-db15-4ef9-bbe0-8afb41546d79'; Name = 'Teams Administrator';                     Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = 'e8611ab8-c189-46e8-94e1-60213ab1f814'; Name = 'User Administrator';                      Tier = 2; RequiresApproval = $true  }
    [PSCustomObject]@{ Id = '25a516ed-2fa0-40ea-a2d0-12923a21473a'; Name = 'Application Developer';                   Tier = 2; RequiresApproval = $true  }
)

#endregion Role Definitions

#region Helper Functions

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

function Get-PolicyIdForRole {
    param([string] $RoleId)
    $filter   = [Uri]::EscapeDataString(
        "scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$RoleId'"
    )
    $response = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?`$filter=$filter"
    $assignment = $response.value | Select-Object -First 1
    if (-not $assignment) {
        throw "No PIM policy assignment found for role ID '$RoleId'. Ensure PIM is enabled in this tenant."
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

function Set-RoleEligibility {
    param(
        [string] $RoleId,
        [string] $GroupId,
        [string] $Duration
    )
    $filter   = [Uri]::EscapeDataString(
        "principalId eq '$GroupId' and roleDefinitionId eq '$RoleId' and directoryScopeId eq '/'"
    )
    $existing = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=$filter"
    if ($existing.value -and $existing.value.Count -gt 0) {
        Write-Host '    Eligibility assignment already exists for this group/role.' -ForegroundColor DarkGray
        return
    }
    $startTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $body = @{
        action           = 'adminAssign'
        justification    = 'PIM group eligibility - automated assignment via Import-PIMSettings.ps1'
        roleDefinitionId = $RoleId
        directoryScopeId = '/'
        principalId      = $GroupId
        scheduleInfo     = @{
            startDateTime = $startTime
            expiration    = @{
                type     = 'afterDuration'
                duration = $Duration
            }
        }
    } | ConvertTo-Json -Depth 5
    $eligUri     = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests'
    $maxAttempts = 6
    $retryDelay  = 15   # seconds between retries for Entra ID group replication lag
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Invoke-MgGraphRequest -Method POST -Uri $eligUri -ContentType 'application/json' -Body $body | Out-Null
            Write-Host "    Eligibility assigned (duration: $Duration)" -ForegroundColor Green
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

#endregion Helper Functions

#region Main

$approverGroupName = 'PIM-2606-Global-Administrator'
Write-Host ''
Write-Host "Resolving approver group '$approverGroupName' ..." -ForegroundColor Cyan
$approverGroup   = Get-OrCreateGroup -DisplayName $approverGroupName `
    -Description 'PIM eligible group and activation approver group for Global Administrator role'
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
        Write-Host '  [1/5] Security group...' -ForegroundColor DarkGray
        $group   = Get-OrCreateGroup -DisplayName $groupName `
            -Description "PIM eligible group for Entra ID role: $($role.Name)"
        $groupId = $group.id

        # 2. PIM policy ID
        Write-Host '  [2/5] Retrieving PIM policy...' -ForegroundColor DarkGray
        $policyId = Get-PolicyIdForRole -RoleId $role.Id
        Write-Host "    Policy ID: $policyId" -ForegroundColor DarkGray

        # 3. Activation duration
        Write-Host "  [3/5] Setting max activation to $activationDuration ..." -ForegroundColor DarkGray
        Set-PolicyExpirationRule -PolicyId $policyId `
            -RuleId                  'Expiration_EndUser_Assignment' `
            -Duration                $activationDuration `
            -ForceExpirationRequired $true

        # 4. Eligibility duration
        Write-Host "  [4/5] Setting max eligibility to $eligibilityDuration ..." -ForegroundColor DarkGray
        Set-PolicyExpirationRule -PolicyId $policyId `
            -RuleId    'Expiration_Admin_Eligibility' `
            -Duration  $eligibilityDuration
        # note: isExpirationRequired is intentionally not forced here — it is read-only
        #       on built-in Entra ID roles; actual assignment duration is set in step 6

        # 5. Approval rule
        Write-Host "  [5/5] Configuring approval rule..." -ForegroundColor DarkGray
        Set-PolicyApprovalRule -PolicyId $policyId `
            -RequiresApproval  $role.RequiresApproval `
            -ApproverGroupId   $approverGroupId `
            -ApproverGroupName $approverGroupName

        # 6. Eligibility assignment
        Write-Host '  [+] Assigning group as eligible for role...' -ForegroundColor DarkGray
        Set-RoleEligibility -RoleId $role.Id -GroupId $groupId -Duration $eligibilityDuration

        Write-Host "  OK" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to process role '$($role.Name)': $_"
    }
}

Write-Host ''
Write-Host "PIM configuration complete. $total roles processed." -ForegroundColor Green

#endregion Main
