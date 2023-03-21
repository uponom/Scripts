<#
.SYNOPSIS
    Show all permanent and eligible Azure Roles assignments (except custom roles)

.DESCRIPTION
    The script shows all permanent and eligible assignments of Azure aRoles to principals. Output can by grouped either by roles (default) or by principals.

.PARAMETER GroupBy
    Select grouping type: Role or Principal.
    Default is Role.

.NOTES
    Version:        0.2
    Author:         Yurii Ponomarenko

    v0.2
    [+] Added Eligible assignments.

    v0.1
    [+] Initial release. Shows permanent role assignments only.

    TO DO:
    Add support for custom roles.
  
.EXAMPLE
    Get-RoleAssignments.ps1 -GroupBy Principal
    Show assignments, grouped by principals.
#>

[cmdletbinding()]
param(
    [Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [ValidateSet('Role', 'Principal')]
    [string]$GroupBy = 'Role'
)

function Write-RoleAssignments {
    [cmdletbinding()]
    param (
        $Assignments,

        $RoleDefinitions,

        [ValidateSet('Role', 'Principal')]
        [string]$GroupBy = 'Role',

        [ConsoleColor]$HighlighColor = 'Yellow'
    )

    $gassignments = $Assignments | Select-Object @{n='Role';e={$RoleDefinitions[$_.RoleDefinitionId]}}, @{n='Principal';e={$_.Principal.AdditionalProperties.displayName}} | Group-Object $GroupBy
    if ($GroupBy -eq 'Role') {
        $Ent = 'Principal'
    } else {
        $Ent = 'Role'
    }

    foreach ($r in ($gassignments | Sort-Object Name)) {
        Write-Host "`t$($r.Name)" -ForegroundColor $HighlighColor
        foreach ($i in ($r.Group.$Ent | Sort-Object)) {
            Write-Host "`t`t$($i)"
        }
    }
    
}

Connect-MgGraph -Scopes RoleManagement.Read.Directory,Directory.Read.All

$roleDefinitions = @{}
Get-MgRoleManagementDirectoryRoleDefinition | ForEach-Object { $roleDefinitions.Add($_.Id, $_.DisplayName) }

# Array of permanent assignments
$aRoles = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal
Write-Host '  ASSIGNED  ' -ForegroundColor Black -BackgroundColor Yellow
Write-RoleAssignments -Assignments $aRoles -RoleDefinitions $roleDefinitions -GroupBy $GroupBy

# Array of eligible assignments
Write-Host '  ELIGIBLE  ' -ForegroundColor Black -BackgroundColor Green
$eRoles = Get-mgRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty Principal
Write-RoleAssignments -Assignments $eRoles -RoleDefinitions $roleDefinitions -GroupBy $GroupBy -HighlighColor Green

