<#
.SYNOPSIS
    Create Active Directory Group Policies management delegation.
.DESCRIPTION
    The script implements delegation settings to provide people GP management rights without providing them Domain Admins rights.
    In addition to the standard AD group "Group Policy Creator Owners" (which allows to create new group policies), 
    the script creates 3 new access groups, which provide:
    - edit settings, delete, modify security over all Group Policies
    - create and remove GPO links on specified OU
    - generate Resultant Set of Policies in planning and logging modes on specified OU
    Also will be created a group, which assigns "Group Policies Admins" role, which includes all permissions mentioned above.
.PARAMETER DelegatedOUDN
    Distinguished Name of OU where GPO links management and RSoP generation has to be delegated.
.PARAMETER DomainDN
    Domain Distinguished Name. The current domain will be taken, if omitted.
.PARAMETER BaseDN
    Default distinguished name of the parent path for GroupsDN.
    If omitted, it will be set to "OU=Tier1,$DomainDN".
.PARAMETER GroupsDN
    Default base path (distinguished name) for "Role" and "Access" OUs.
    If omitted, it will be set to "OU=Groups,$BaseDN".
    The parameter will be ignored if -RolesGroupsDN and/or -AccessGroupsDN is set.    
.PARAMETER RolesGroupsDN
    Path to OU where Role groups will be stored.
    If omitted, it will be set to "OU=Roles,$GroupsDN" (see "GroupsDN" parameter).
.PARAMETER RolesT2GroupsDN
    Path to OU where "Tier2" Role groups (GPAuthorsRoleGroup, OUAdminsGroup) will be stored.
    If omitted, it will be the same as RolesGroupsDN
.PARAMETER AccessGroupsDN
    Path to OU where Access groups will be stored.
    If omitted, it will be set to "OU=Access,$GroupsDN" (see "GroupsDN" parameter).
.PARAMETER GroupPolicyCreatorOwnersGroup
    Localized name of the standard group "Group Policy Creator Owners". Ignore it if you have English-localized AD.
    For German-localized AD must be set to "Richtlinien-Ersteller-Besitzer"
.PARAMETER GPModifyGroup
    Name for the group which allows to Edit settings, Delete, Modify security on all GPOs in the domain.
.PARAMETER GPOLinksModifyGroup
    Name for the group which allows to create and remove link for GPOs in the delegated OU.
    If omitted, the name will be created basing on DelegatedOUDN and ended with "_GPOLinks_Manage"
.PARAMETER RsopGenerateGroup
    Name for the group which allows to generate RSoP (planning and modeling modes) in the delegated OU.
    If omitted, the name will be created basing on DelegatedOUDN and ended with "_RSoP_Generate"
.PARAMETER DelegatedFullAccessGroup
    Name for the group which provides full control over AD objects in the delegated OU.
    If omitted, the name will be created basing on DelegatedOUDN and ended with "_AD_Full"   
.PARAMETER RootRsopGroup
    Name of the group which allows to generate RSoP (planning and modeling modes) domain-wide.
    If omitted, "Global_RSoP_Generate" name will be used.
.PARAMETER GPAdminsRoleGroup
    Name for the group which assigns Group Policies Admins role.
    If omitted, will be named as "GroupPolicies_Admins".
.PARAMETER GPAuthorsRoleGroup
    Name of the group for assigning Group Policies Authors role, which provides permissions to create new GPO, modify your own GPOs and generate RSoP.   
    If omitted, will be named as "GroupPolicy_Authors".
.PARAMETER OUAdminsGroup
    Name for the group which assigns administrators role for the specified DelegatedOUDN.
    This role provides full access over all AD objects inside DelegatedOUDN, including RSoP generation and GPO-links manage.

.NOTES
    Version:        1.3
    Author:         Yurii Ponomarenko
  
.EXAMPLE
    .\Set-GPDelegation.ps1 -DelegatedOUDN "OU=MyCompany,DC=contoso,DC=com"

    It will create in the current domain:
        "GroupPolicies_Admins" and "OUMyCompany_Admins" role groups in "OU=Roles,OU=Tier1,DC=contoso,DC=com",
        "GroupPolicies_Modify", "Global_RSoP_Generate", "OU_MyCompany_GPOLinks_Manage", "OU_MyCompany_RSoP_Generate", "OU_MyCompany_AD_Full" access groups in "OU=Access,OU=Tier1,DC=contoso,DC=com",
        and provide them with appropiate permissions.
#>

[cmdletbinding(
    SupportsShouldProcess
)]

param(
    [Parameter(Mandatory=$true)]
    [string]$DelegatedOUDN,
    
    [string]$GPOLinksModifyGroup = "$(($DelegatedOUDN.Substring(0, $DelegatedOUDN.IndexOf(','))).Replace('=','_'))_GPOLinks_Manage",
    
    [string]$RsopGenerateGroup = "$(($DelegatedOUDN.Substring(0, $DelegatedOUDN.IndexOf(','))).Replace('=','_'))_RSoP_Generate",

    [string]$OUAdminsGroup = "$(($DelegatedOUDN.Substring(0, $DelegatedOUDN.IndexOf(','))).Replace('=',''))_Admins",

    [string]$DelegatedFullAccessGroup = "$(($DelegatedOUDN.Substring(0, $DelegatedOUDN.IndexOf(','))).Replace('=','_'))_AD_Full",

    [string]$GPModifyGroup = 'GroupPolicies_Modify',
    
    [string]$GPAdminsRoleGroup = 'GroupPolicies_Admins',

    [string]$GPAuthorsRoleGroup = 'GroupPolicy_Authors',

    [string]$RootRsopGroup = 'Global_RSoP_Generate',

    [string]$DomainDN = ((Get-ADDomain -ErrorAction Stop).DistinguishedName),

    [string]$BaseDN = ("OU=Tier1,$DomainDN"),

    [string]$GroupsDN = ("OU=Groups,$BaseDN"),

    [string]$RolesGroupsDN = ("OU=Roles,$GroupsDN"),

    [string]$RolesT2GroupsDN = $RolesGroupsDN,

    [string]$AccessGroupsDN = ("OU=Access,$GroupsDN"),

    [string]$GroupPolicyCreatorOwnersGroup = 'Group Policy Creator Owners' # Can be different in non-English AD
)

($DelegatedOUDN, $BaseDN, $GroupsDN, $RolesGroupsDN, $AccessGroupsDN, $RolesT2GroupsDN) | ForEach-Object{
    if ($_ -notlike "*$DomainDN") {
        Write-Host "ERROR: The OU `"$_`" is not in the current domain namespace ($DomainDN)." -ForegroundColor Red
        exit 1
    }
    if (!(Test-Path "AD:\$_")) {
        Write-Host "ERROR: The OU `"$_`" does not exist." -ForegroundColor Red
        exit 2
    }
}


#region Vars

$GPModifyGroupPath = $AccessGroupsDN
$GPModifyGroupDesc = 'Allows to Edit settings, Delete, Modify security on all GPOs in the domain'

$RootRsopGroupPath = $AccessGroupsDN
$RootRsopGroupDesc = "Allow to generate RSoP (planning and logging modes) in `"$DomainDN`""

$GPOLinksModifyGroupPath = $AccessGroupsDN
$GPOLinksModifyGroupDesc = "Allows to create and remove link for GPOs in `"$DelegatedOUDN`""
$GPOLinksModifyScope = $DelegatedOUDN

$RsopGenerateGroupPath = $AccessGroupsDN
$RsopGenerateGroupDesc = "Allow to generate RSoP (planning and logging modes) in `"$DelegatedOUDN`""
$RsopGenerateScope = $DelegatedOUDN

$GPAdminsRoleGroupPath = $RolesGroupsDN
$GPAdminsRoleGroupDesc = "Group Policies Administrators role group. Allows to Create/Modify/Delete all GPOs and generate RSoP domain-wide" 
$GPAdminsRoleGroupMemberOf = @($GPModifyGroup, $RootRsopGroup, $GroupPolicyCreatorOwnersGroup)

$GPAuthorsRoleGroupPath = $RolesT2GroupsDN
$GPAuthorsRoleGroupDesc = "Allows to create new GPO, modify your own GPOs and generate RSoP. " 
$GPAuthorsRoleGroupMemberOf = @($RootRsopGroup, $GroupPolicyCreatorOwnersGroup)

$DelegatedFullAccessGroupPath = $AccessGroupsDN
$DelegatedFullAccessGroupDesc = "Full access over all AD objects in `"$DelegatedOUDN`""
$DelegatedFullAccessGroupScope = $DelegatedOUDN

$OUAdminsGroupPath = $RolesT2GroupsDN
$OUAdminsGroupDesc = "Full access over all AD objects (including RSoP and GPO-links) in `"$DelegatedOUDN`""
$OUAdminsGroupMemberOf = @($GPOLinksModifyGroup, $RsopGenerateGroup, $DelegatedFullAccessGroup)

#endregion Vars


#region Functions

function Set-RsopDelegation {
<#
.SYNOPSIS
    Creates AD group and delegates it an access to generate RSoP for specified scope.
#>
    [cmdletbinding(
        SupportsShouldProcess
    )]
    param (
        [string]$GroupName,
        [string]$GroupPath,
        [string]$GroupDesc,
        [string]$Scope
    )

    $adRights = [System.DirectoryServices.ActiveDirectoryRights]'ExtendedRight'
    $type = [System.Security.AccessControl.AccessControlType]'Allow'
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'All'
    
    $gRSOPLogging = [GUID]'b7b1b3de-ab09-4242-9e30-9980e5d322f7'
    $gRSOPPlanning = [GUID]'b7b1b3dd-ab09-4242-9e30-9980e5d322f7'

    Write-Verbose "Creation of $GroupName ($GroupPath)..."
    try {
        $SID = (New-ADGroup -Name $GroupName -Description $GroupDesc -Path $GroupPath -GroupCategory Security -GroupScope DomainLocal -ErrorAction Stop -PassThru).SID
        $path = "AD:\$Scope"
        $acl = Get-ACl -Path $path -ErrorAction Stop
        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, $adRights, $type, $gRSOPLogging, $inheritanceType))
        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, $adRights, $type, $gRSOPPlanning, $inheritanceType))
        Write-Verbose "Assigning permissions to $GroupName ..."
        if($PSCmdlet.ShouldProcess($path, "Allow `"$GroupName`" to generate RSoP")) {
            Set-ACL -Path $path -AclObject $acl -Passthru -ErrorAction Stop | Out-Null
        }        
    } catch {        
        return $_.Exception.Message
    }
    return $null     
}

function Set-GPOLinkManageDelegation {
<#
.SYNOPSIS
    Creates AD group and delegates it an access to manage GPO-links for specified scope.
#>
    [cmdletbinding(
        SupportsShouldProcess
    )]
    param (
        [string]$GroupName,
        [string]$GroupPath,
        [string]$GroupDesc,
        [string]$Scope
    )

    $gpOptions = [GUID]'f30e3bbf-9ff0-11d1-b603-0000f80367c1'
    $gpLink = [GUID]'f30e3bbe-9ff0-11d1-b603-0000f80367c1'
            
    $type = [System.Security.AccessControl.AccessControlType]'Allow'
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'All'

    Write-Verbose "Creation of $GroupName ($GroupPath)..."
    try {
        $SID = (New-ADGroup -Name $GroupName -Description $GroupDesc -Path $GroupPath -GroupCategory Security -GroupScope DomainLocal -ErrorAction Stop -PassThru).SID
        $path = "AD:\$Scope"
        $acl = Get-ACl -Path $path -ErrorAction Stop
        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, 'GenericAll', $type, $gpOptions, $inheritanceType))
        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, 'GenericAll', $type, $gpLink, $inheritanceType))
        Write-Verbose "Assigning permissions to $GroupName ..."
        if($PSCmdlet.ShouldProcess($path, "Allow `"$GroupName`" to manage GPO-links")) {
            Set-ACL -Path $path -AclObject $acl -Passthru -ErrorAction Stop | Out-Null
        }        
    } catch {        
        return $_.Exception.Message
    }
    return $null     
}

function Set-FullControllDelegation {
<#
.SYNOPSIS
    Creates AD group and delegates it full control over all AD objects in specified scope.
#>
    [cmdletbinding(
        SupportsShouldProcess
    )]
    param (
        [string]$GroupName,
        [string]$GroupPath,
        [string]$GroupDesc,
        [string]$Scope
    )
            
    $type = [System.Security.AccessControl.AccessControlType]'Allow'
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'All'
        
    Write-Verbose "Creation of $GroupName ($GroupPath)..."
    try {
        $SID = (New-ADGroup -Name $GroupName -Description $GroupDesc -Path $GroupPath -GroupCategory Security -GroupScope DomainLocal -ErrorAction Stop -PassThru).SID
        $path = "AD:\$Scope"
        $acl = Get-ACl -Path $path -ErrorAction Stop
        $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, 'GenericAll', $type, $inheritanceType))
        Write-Verbose "Assigning permissions to $GroupName ..."
        if($PSCmdlet.ShouldProcess($path, "Allow `"$GroupName`" Full control")) {
            Set-ACL -Path $path -AclObject $acl -Passthru -ErrorAction Stop | Out-Null
        }        
    } catch {        
        return $_.Exception.Message
    }
    return $null     
}

#endregion Functions


#region Configuring GP full control access group
"Creation of $GPModifyGroup ($GPModifyGroupPath)..."
New-ADGroup -Name $GPModifyGroup -Description $GPModifyGroupDesc -Path $GPModifyGroupPath -GroupCategory Security -GroupScope DomainLocal -ErrorAction Stop
"Assingning GpoEditDeleteModifySecurity to $GPModifyGroup for all existing GPOs..."
Set-GPPermission -All -TargetName $GPModifyGroup -TargetType Group -PermissionLevel GpoEditDeleteModifySecurity -ErrorAction Stop | Format-Table DisplayName, Owner
#endregion Configuring GP full control access group

# Configuring domain root RSoP-generate access group
$r = Set-RsopDelegation -GroupName $RootRsopGroup -GroupPath $RootRsopGroupPath -GroupDesc $RootRsopGroupDesc -Scope $DomainDN
if (![string]::IsNullOrEmpty($r)) {
    Write-Host "ERROR: Cannot setup a delegation: $r"
    exit 3
}

# Configuring GPO RSoP Planning and Logging access group
$r = Set-RsopDelegation -GroupName $RsopGenerateGroup -GroupPath $RsopGenerateGroupPath -GroupDesc $RsopGenerateGroupDesc -Scope $RsopGenerateScope
if (![string]::IsNullOrEmpty($r)) {
    Write-Host "ERROR: Cannot setup a delegation: $r"
    exit 4
}

# Configuring GPO Links access group
$r = Set-GPOLinkManageDelegation -GroupName $GPOLinksModifyGroup -GroupPath $GPOLinksModifyGroupPath -GroupDesc $GPOLinksModifyGroupDesc -Scope $GPOLinksModifyScope
if (![string]::IsNullOrEmpty($r)) {
    Write-Host "ERROR: Cannot setup a delegation: $r"
    exit 5
}

# Configuring Full control access group for the delegated OU
$r = Set-FullControllDelegation -GroupName $DelegatedFullAccessGroup -GroupPath $DelegatedFullAccessGroupPath -GroupDesc $DelegatedFullAccessGroupDesc -Scope $DelegatedFullAccessGroupScope
if (![string]::IsNullOrEmpty($r)) {
    Write-Host "ERROR: Cannot setup a delegation: $r"
    exit 6
}

#region Creation the role group for Group Policies Administrators
"Creation of $GPAdminsRoleGroup ($GPAdminsRoleGroupPath)..."
New-ADGroup -Name $GPAdminsRoleGroup -Description $GPAdminsRoleGroupDesc -Path $GPAdminsRoleGroupPath -GroupCategory Security -GroupScope Global -ErrorAction Stop
$GPAdminsRoleGroupMemberOf | ForEach-Object { 
    "Adding $GPAdminsRoleGroup as a member of $_ ..."
    Add-ADGroupMember -Identity $_ -Members $GPAdminsRoleGroup -ErrorAction Stop 
}
#endregion Creation the role group for Group Policies Administrators

#region Creation the role group for Group Policies Authors
"Creation of $GPAuthorsRoleGroup ($GPAuthorsRoleGroupPath)..."
New-ADGroup -Name $GPAuthorsRoleGroup -Description $GPAuthorsRoleGroupDesc -Path $GPAuthorsRoleGroupPath -GroupCategory Security -GroupScope Global -ErrorAction Stop
$GPAuthorsRoleGroupMemberOf | ForEach-Object { 
    "Adding $GPAuthorsRoleGroup as a member of $_ ..."
    Add-ADGroupMember -Identity $_ -Members $GPAuthorsRoleGroup -ErrorAction Stop 
}
#endregion Creation the role group for Group Policies Authors

#region Creation the role group for Administrators of the delegated OU 
"Creation of $OUAdminsGroup ($OUAdminsGroupPath)..."
New-ADGroup -Name $OUAdminsGroup -Description $OUAdminsGroupDesc -Path $OUAdminsGroupPath -GroupCategory Security -GroupScope Global -ErrorAction Stop
$OUAdminsGroupMemberOf | ForEach-Object { 
    "Adding $OUAdminsGroup as a member of $_ ..."
    Add-ADGroupMember -Identity $_ -Members $OUAdminsGroup -ErrorAction Stop 
}
#endregion Creation the role group for Administrators of the delegated OU 