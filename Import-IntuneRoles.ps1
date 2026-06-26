#Requires -Version 5.1
if ($PSVersionTable.PSVersion.Major -lt 7) {
    $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($pwsh) {
        Write-Host "Relaunching in PowerShell 7..." -ForegroundColor Yellow
        & $pwsh.Source -ExecutionPolicy Bypass -File $MyInvocation.MyCommand.Path
        exit $LASTEXITCODE
    } else {
        Write-Warning "PowerShell 7 is not installed. Microsoft.Graph v2.x requires PS7+. Install it from https://aka.ms/powershell and re-run."
        exit 1
    }
}
<#
DISCLAIMER The sample scripts are not supported under any Microsoft standard support program or service.
The sample codes are provided AS IS without warranty of any kind. Microsoft further disclaims all implied
warranties including, without limitation, any implied warranties of merchantability or of fitness for a
particular purpose. The entire risk arising out of the use or performance of the sample codes and documentation
remains with you. In no event shall Microsoft, its authors, owners of this repository or anyone else involved
in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without
limitation, damages for loss of business profits, business interruption, loss of business information, or other
pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if
Microsoft has been advised of the possibility of such damages.
#>

#region Module

if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Write-Host "Installing package provider 'NuGet'..." -ForegroundColor Yellow
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
} else {
    Write-Host "Package provider 'NuGet' is already installed." -ForegroundColor Green
}

$requiredModules = @(
    'Microsoft.Graph.Authentication'
)

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing module '$module'..." -ForegroundColor Yellow
        Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
    } else {
        Write-Host "Module '$module' is already installed." -ForegroundColor Green
    }
    Import-Module $module -ErrorAction Stop
}

#endregion

#region Connection

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes @(
    'DeviceManagementRBAC.ReadWrite.All'
    'Group.ReadWrite.All'
) -NoWelcome -ErrorAction Stop

$context = Get-MgContext
Write-Host "Connected as: $($context.Account) | Tenant: $($context.TenantId)" -ForegroundColor Green

#endregion

#region Scope Tags

$scopeTags = @(
    @{ displayName = 'EUD'; description = 'Enterprise User Devices' }
    @{ displayName = 'PAW'; description = 'Privileged Access Workstations' }
)

$existingTags = (Invoke-MgGraphRequest -Method GET -Uri 'beta/deviceManagement/roleScopeTags' -OutputType PSObject).value

foreach ($tag in $scopeTags) {
    if ($existingTags.displayName -contains $tag.displayName) {
        Write-Host "Scope tag '$($tag.displayName)' already exists." -ForegroundColor Green
    } else {
        Write-Host "Creating scope tag '$($tag.displayName)'..." -ForegroundColor Yellow
        try {
            Invoke-MgGraphRequest -Method POST -Uri 'beta/deviceManagement/roleScopeTags' `
                -Body $tag -OutputType PSObject -ErrorAction Stop | Out-Null
            Write-Host "Scope tag '$($tag.displayName)' created." -ForegroundColor Green
        } catch {
            $errDetail = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
            Write-Warning "Failed to create scope tag '$($tag.displayName)': $errDetail"
        }
    }
}

# Refresh and capture IDs — used by role definitions and role assignments below
$allTags  = (Invoke-MgGraphRequest -Method GET -Uri 'beta/deviceManagement/roleScopeTags' -OutputType PSObject).value
$eudTagId = ($allTags | Where-Object { $_.displayName -eq 'EUD' }).id
$pawTagId = ($allTags | Where-Object { $_.displayName -eq 'PAW' }).id

if ([string]::IsNullOrEmpty($eudTagId) -or [string]::IsNullOrEmpty($pawTagId)) {
    Write-Error "Could not resolve scope tag IDs (EUD='$eudTagId' PAW='$pawTagId'). Cannot continue."
    exit 1
}

#endregion

#region Entra ID Groups

function New-EntraGroupIfNotExists {
    param(
        [string]$DisplayName,
        [string]$MailNickname,
        [string]$Description
    )
    $encoded  = [System.Uri]::EscapeDataString("displayName eq '$DisplayName'")
    $existing = (Invoke-MgGraphRequest -Method GET `
        -Uri "v1.0/groups?`$filter=$encoded&`$select=id,displayName" `
        -OutputType PSObject -ErrorAction SilentlyContinue).value
    if ($existing) {
        Write-Host "Group '$DisplayName' already exists." -ForegroundColor Green
        return $existing[0].id
    }
    Write-Host "Creating group '$DisplayName'..." -ForegroundColor Yellow
    try {
        $result = Invoke-MgGraphRequest -Method POST -Uri 'v1.0/groups' -OutputType PSObject -ErrorAction Stop -Body @{
            displayName     = $DisplayName
            description     = $Description
            mailEnabled     = $false
            securityEnabled = $true
            mailNickname    = $MailNickname
        }
        return $result.id
    } catch {
        $errDetail = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        Write-Warning "Failed to create group '${DisplayName}': $errDetail"
        return $null
    }
}

$eudGroupId      = New-EntraGroupIfNotExists -DisplayName 'EUD-Intune-Operator' `
                       -MailNickname 'EUDIntuneOperator' `
                       -Description 'Intune operators for End User Devices'

$pawGroupId      = New-EntraGroupIfNotExists -DisplayName 'PAW-Intune-Operator' `
                       -MailNickname 'PAWIntuneOperator' `
                       -Description 'Intune operators for Privileged Access Workstations'

$eudAdminGroupId = New-EntraGroupIfNotExists -DisplayName 'EUD-Intune-Administrators' `
                       -MailNickname 'EUDIntuneAdministrators' `
                       -Description 'Intune administrators for End User Devices'

$pawAdminGroupId = New-EntraGroupIfNotExists -DisplayName 'PAW-Intune-Administrators' `
                       -MailNickname 'PAWIntuneAdministrators' `
                       -Description 'Intune administrators for Privileged Access Workstations'

if ([string]::IsNullOrEmpty($eudGroupId)      -or [string]::IsNullOrEmpty($pawGroupId) -or
    [string]::IsNullOrEmpty($eudAdminGroupId) -or [string]::IsNullOrEmpty($pawAdminGroupId)) {
    Write-Error "Could not resolve one or more Entra group IDs. Cannot continue."
    exit 1
}

#endregion

#region Custom Intune Roles

# Use the built-in Help Desk Operator permissions as the template for operator roles.
# Adjust allowedResourceActions in the portal or replace $templatePermissions here
# with a custom array of Microsoft.Intune resource action strings.
$helpDeskRole = (Invoke-MgGraphRequest -Method GET `
    -Uri "beta/deviceManagement/roleDefinitions?`$filter=isBuiltIn eq true and displayName eq 'Help Desk Operator'" `
    -OutputType PSObject).value

if (-not $helpDeskRole) {
    Write-Error "Built-in 'Help Desk Operator' role not found. Cannot derive permissions for custom roles."
    exit 1
}

# A JSON round-trip (ConvertTo-Json | ConvertFrom-Json) strips all ETS methods that
# Invoke-MgGraphRequest attaches to PSObjects, producing clean PSCustomObjects that
# ConvertTo-Json can serialise without hitting circular-reference loops.
function ConvertTo-CleanPermissionsJson {
    param([object[]]$Permissions)
    # The GET response returns resourceActions as a single object; the beta POST schema expects
    # resourceActions to be an array of resourceAction objects. Build the JSON entirely via
    # string concatenation so PS array serialisation never touches the nested structure.
    $permParts = @($Permissions | ForEach-Object {
        $ra = $_.resourceActions
        # resourceActions from the GET may itself be an array (unwrapped by PS pipeline) or
        # a single PSObject — handle both by always reading .allowedResourceActions directly.
        $allowed = [string[]]@($ra.allowedResourceActions | Where-Object { $_ })
        $allowedJson = ConvertTo-Json -InputObject $allowed -Compress
        '{"resourceActions":[{"allowedResourceActions":' + $allowedJson + ',"notAllowedResourceActions":[]}]}'
    })
    return '[' + ($permParts -join ',') + ']'
}

$templatePermissionsJson = ConvertTo-CleanPermissionsJson -Permissions $helpDeskRole[0].rolePermissions

function New-IntuneRoleIfNotExists {
    param(
        [string]  $DisplayName,
        [string]  $Description,
        [string]  $RolePermissionsJson,
        [string[]]$ScopeTagIds
    )
    $allRoles = (Invoke-MgGraphRequest -Method GET -Uri 'beta/deviceManagement/roleDefinitions' -OutputType PSObject).value
    $existing = $allRoles | Where-Object { $_.displayName -eq $DisplayName -and $_.isBuiltIn -eq $false }
    if ($existing) {
        Write-Host "Intune role '$DisplayName' already exists." -ForegroundColor Green
        return $existing.id
    }
    Write-Host "Creating Intune role '$DisplayName'..." -ForegroundColor Yellow
    try {
        # Inject the pre-serialised permissions string directly so ConvertTo-Json never
        # touches it again. A second ConvertTo-Json pass on a single-element PS array
        # inside a hashtable collapses it to a bare object regardless of -Depth.
        $scopeTagsJson = ConvertTo-Json -InputObject @($ScopeTagIds) -Compress
        $bodyJson = '{"@odata.type":"#microsoft.graph.roleDefinition"' +
                    ',"displayName":'    + (ConvertTo-Json $DisplayName -Compress) +
                    ',"description":'   + (ConvertTo-Json $Description -Compress) +
                    ',"isBuiltIn":false' +
                    ',"rolePermissions":' + $RolePermissionsJson +
                    ',"roleScopeTagIds":' + $scopeTagsJson + '}'

        $result = Invoke-MgGraphRequest -Method POST -Uri 'beta/deviceManagement/roleDefinitions' `
            -Body $bodyJson -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
        Write-Host "Intune role '$DisplayName' created." -ForegroundColor Green
        return $result.id
    } catch {
        $errMsg  = $_.Exception.Message
        $errBody = $_.ErrorDetails.Message
        Write-Warning "Failed to create Intune role '${DisplayName}':"
        Write-Warning "  Exception : $errMsg"
        if ($errBody) { Write-Host $errBody -ForegroundColor Red }
        return $null
    }
}

$eudRoleId = New-IntuneRoleIfNotExists -DisplayName 'EUD-Intune-Operator' `
                 -Description 'Intune operator role scoped to End User Devices' `
                 -RolePermissionsJson $templatePermissionsJson `
                 -ScopeTagIds @($eudTagId)

$pawRoleId = New-IntuneRoleIfNotExists -DisplayName 'PAW-Intune-Operator' `
                 -Description 'Intune operator role scoped to Privileged Access Workstations' `
                 -RolePermissionsJson $templatePermissionsJson `
                 -ScopeTagIds @($pawTagId)

# Use the built-in School Administrator permissions as the template for administrator roles
$schoolAdminRole = (Invoke-MgGraphRequest -Method GET `
    -Uri "beta/deviceManagement/roleDefinitions?`$filter=isBuiltIn eq true and displayName eq 'School Administrator'" `
    -OutputType PSObject).value

if (-not $schoolAdminRole) {
    Write-Error "Built-in 'School Administrator' role not found. Cannot derive permissions for administrator roles."
    exit 1
}
$adminTemplatePermissionsJson = ConvertTo-CleanPermissionsJson -Permissions $schoolAdminRole[0].rolePermissions

$eudAdminRoleId = New-IntuneRoleIfNotExists -DisplayName 'EUD-Intune-Administrators' `
                      -Description 'Intune administrator role scoped to End User Devices' `
                      -RolePermissionsJson $adminTemplatePermissionsJson `
                      -ScopeTagIds @($eudTagId)

$pawAdminRoleId = New-IntuneRoleIfNotExists -DisplayName 'PAW-Intune-Administrators' `
                      -Description 'Intune administrator role scoped to Privileged Access Workstations' `
                      -RolePermissionsJson $adminTemplatePermissionsJson `
                      -ScopeTagIds @($pawTagId)

if ([string]::IsNullOrEmpty($eudRoleId)      -or [string]::IsNullOrEmpty($pawRoleId) -or
    [string]::IsNullOrEmpty($eudAdminRoleId) -or [string]::IsNullOrEmpty($pawAdminRoleId)) {
    Write-Error "Could not resolve one or more Intune role IDs. Cannot continue."
    exit 1
}

#endregion

#region Role Assignments

# roleScopeTagIds on the assignment controls which devices are in scope.
# Omitting the default scope tag ID ("0") removes it from the assignment scope.

function New-IntuneRoleAssignmentIfNotExists {
    param(
        [string]  $DisplayName,
        [string]  $Description,
        [string]  $RoleDefinitionId,
        [string[]]$MemberGroupIds,
        [string[]]$ScopeTagIds
    )
    $existing = (Invoke-MgGraphRequest -Method GET -Uri 'beta/deviceManagement/roleAssignments' -OutputType PSObject).value |
        Where-Object { $_.displayName -eq $DisplayName }
    if ($existing) {
        Write-Host "Role assignment '$DisplayName' already exists." -ForegroundColor Green
        return
    }
    Write-Host "Creating role assignment '$DisplayName'..." -ForegroundColor Yellow
    try {
        Invoke-MgGraphRequest -Method POST -Uri 'beta/deviceManagement/roleAssignments' `
            -OutputType PSObject -ErrorAction Stop -Body @{
                '@odata.type'                    = '#microsoft.graph.deviceAndAppManagementRoleAssignment'
                displayName                      = $DisplayName
                description                      = $Description
                members                          = $MemberGroupIds
                scopeType                        = 'allDevices'
                roleScopeTagIds                  = $ScopeTagIds
                'roleDefinition@odata.bind'      = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions/$RoleDefinitionId"
            } | Out-Null
        Write-Host "Role assignment '$DisplayName' created." -ForegroundColor Green
    } catch {
        $errDetail = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        Write-Warning "Failed to create role assignment '${DisplayName}': $errDetail"
    }
}

New-IntuneRoleAssignmentIfNotExists `
    -DisplayName        'EUD-Intune-Operator' `
    -Description        'Assigns EUD-Intune-Operator role to EUD operators, scoped to EUD devices only' `
    -RoleDefinitionId   $eudRoleId `
    -MemberGroupIds     @($eudGroupId) `
    -ScopeTagIds        @($eudTagId)

New-IntuneRoleAssignmentIfNotExists `
    -DisplayName        'PAW-Intune-Operator' `
    -Description        'Assigns PAW-Intune-Operator role to PAW operators, scoped to PAW devices only' `
    -RoleDefinitionId   $pawRoleId `
    -MemberGroupIds     @($pawGroupId) `
    -ScopeTagIds        @($pawTagId)

New-IntuneRoleAssignmentIfNotExists `
    -DisplayName        'EUD-Intune-Administrators' `
    -Description        'Assigns EUD-Intune-Administrators role to EUD admins, scoped to EUD devices only' `
    -RoleDefinitionId   $eudAdminRoleId `
    -MemberGroupIds     @($eudAdminGroupId) `
    -ScopeTagIds        @($eudTagId)

New-IntuneRoleAssignmentIfNotExists `
    -DisplayName        'PAW-Intune-Administrators' `
    -Description        'Assigns PAW-Intune-Administrators role to PAW admins, scoped to PAW devices only' `
    -RoleDefinitionId   $pawAdminRoleId `
    -MemberGroupIds     @($pawAdminGroupId) `
    -ScopeTagIds        @($pawTagId)

#endregion

Disconnect-MgGraph | Out-Null
Write-Host "Disconnected." -ForegroundColor Gray
