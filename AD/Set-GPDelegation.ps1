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
.PARAMETER DelegatedOUGroupsDN
    The place to put GPOLinksModify and RSOPGenerate groups. It is usually inside of DelegatedOUDN.
    "OU=Groups,$DelegatedOUDN" will be used, if omitted.     
.PARAMETER GlobalDomainGroupsDN
    The place to put GPModify and GPAdmins groups to. Will be used standard "Users" container in the root of the domain, if omitted. 
.PARAMETER DomainDN
    Domain Distinguished Name. The current domain will be taken, if omitted.
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
.PARAMETER GPAdminsRoleGroup
    Name for the group which assigns Group Policies Admins role.
    If omitted, will be named "GroupPolicies_Admins".

.NOTES
    Version:        1.0
    Author:         Yurii Ponomarenko
  
.EXAMPLE
    .\Set-GPDelegation.ps1 -DelegatedOUDN "OU=MyCompany,DC=contoso,DC=com"

    It will create in the current domain:
        "GroupPolicies_Modify" and "GroupPolicies_Admins" groups in "OU=Users,DC=contoso,DC=com",
        "OU_MyCompany_GPOLinks_Manage" and "OU_MyCompany_RSoP_Generate" in "OU=Groups,OU=MyCompany,DC=contoso,DC=com"
        and provide them with appropiate delegated permissions.
#>

[cmdletbinding(
    SupportsShouldProcess
)]

param(
    [Parameter(Mandatory=$true)]
    [string]$DelegatedOUDN,
    
    [string]$DelegatedOUGroupsDN = "OU=Groups,$DelegatedOUDN",
    
    [string]$GPModifyGroup = 'GroupPolicies_Modify',
    
    [string]$GPOLinksModifyGroup = "$(($DelegatedOUDN.Substring(0, $DelegatedOUDN.IndexOf(','))).Replace('=','_'))_GPOLinks_Manage",
    
    [string]$RsopGenerateGroup = "$(($DelegatedOUDN.Substring(0, $DelegatedOUDN.IndexOf(','))).Replace('=','_'))_RSoP_Generate",
    
    [string]$GPAdminsRoleGroup = 'GroupPolicies_Admins',

    [string]$DomainDN = ((Get-ADDomain -ErrorAction Stop).DistinguishedName),

    [string]$GlobalDomainGroupsDN = ("CN=Users,$DomainDN"),

    [string]$GroupPolicyCreatorOwnersGroup = 'Group Policy Creator Owners' # Can be different in non-English AD
)


if ($DelegatedOUDN -notlike "*$DomainDN") {
    Write-Host "ERROR: The delegated OU `"$DelegatedOUDN`" is not in the current domain namespace ($DomainDN)." -ForegroundColor Red
    exit 1
}

$GPModifyGroupDN = $GlobalDomainGroupsDN
$GPModifyGroupDesc = 'Allows to Edit settings, Delete, Modify security on all GPOs in the domain'

$GPOLinksModifyGroupDN = $DelegatedOUGroupsDN
$GPOLinksModifyGroupDesc = "Allows to create and remove link for GPOs in `"$DelegatedOUDN`""
$GPOLinksModifyScope = $DelegatedOUDN

$RsopGenerateGroupDN = $DelegatedOUGroupsDN
$RsopGenerateGroupDesc = "Allow to generate RSoP (planning and logging modes) in `"$DelegatedOUDN`""
$RsopGenerateScope = $DelegatedOUDN

$GPAdminsRoleGroupDesc = "Group Policies Administrators role group. Allows to Create/Modify/Delete all GPOs, Link/Unlink GPOs and generate RSoP on `"$DelegatedOUDN`"" 
$GPAdminsRoleGroupMemberOf = @($GPModifyGroup, $GPOLinksModifyGroup, $RsopGenerateGroup, $GroupPolicyCreatorOwnersGroup)
$GPAdminsRoleGroupDN = $GlobalDomainGroupsDN

$gRSOPLogging = [GUID]'b7b1b3de-ab09-4242-9e30-9980e5d322f7'
$gRSOPPlanning = [GUID]'b7b1b3dd-ab09-4242-9e30-9980e5d322f7'
$gpOptions = [GUID]'f30e3bbf-9ff0-11d1-b603-0000f80367c1'
$gpLink = [GUID]'f30e3bbe-9ff0-11d1-b603-0000f80367c1'
      
$adRights = [System.DirectoryServices.ActiveDirectoryRights]'ExtendedRight'
$type = [System.Security.AccessControl.AccessControlType]'Allow'
$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'All'

# Configuring GP full control access group
"Creation of $GPModifyGroup ..."
New-ADGroup -Name $GPModifyGroup -Description $GPModifyGroupDesc -Path $GPModifyGroupDN -GroupCategory Security -GroupScope DomainLocal -ErrorAction Stop -PassThru
"Assingning GpoEditDeleteModifySecurity to $GPModifyGroup ..."
Set-GPPermission -All -TargetName $GPModifyGroup -TargetType Group -PermissionLevel GpoEditDeleteModifySecurity | Format-Table DisplayName, Owner

# Configuring GPO Links access group
"Creation of $GPOLinksModifyGroup ..."
$SID = (New-ADGroup -Name $GPOLinksModifyGroup -Description $GPOLinksModifyGroupDesc -Path $GPOLinksModifyGroupDN -GroupCategory Security -GroupScope DomainLocal -ErrorAction Stop -PassThru).SID
$path = "AD:\$GPOLinksModifyScope"
$acl = Get-ACl -Path $path -ErrorAction Stop
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, 'GenericAll', $type, $gpOptions, $inheritanceType))
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, 'GenericAll', $type, $gpLink, $inheritanceType))
"Assingning parmissions to $GPOLinksModifyGroup ..."
Set-ACL -Path $path -AclObject $acl -Passthru -ErrorAction Stop 

# Configuring GPO RSoP Planning and Logging access group
"Creation of $RsopGenerateGroup ..."
$SID = (New-ADGroup -Name $RsopGenerateGroup -Description $RsopGenerateGroupDesc -Path $RsopGenerateGroupDN -GroupCategory Security -GroupScope DomainLocal -ErrorAction Stop -PassThru).SID
$path = "AD:\$RsopGenerateScope"
$acl = Get-ACl -Path $path -ErrorAction Stop
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, $adRights, $type, $gRSOPLogging, $inheritanceType))
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, $adRights, $type, $gRSOPPlanning, $inheritanceType))
"Assingning parmissions to $RsopGenerateGroup ..."
Set-ACL -Path $path -AclObject $acl -Passthru -ErrorAction Stop 

# Creation the role group for Group Policies Administrators
"Creation of $GPAdminsRoleGroup ..."
New-ADGroup -Name $GPAdminsRoleGroup -Description $GPAdminsRoleGroupDesc -Path $GPAdminsRoleGroupDN -GroupCategory Security -GroupScope Global -ErrorAction Stop -PassThru
$GPAdminsRoleGroupMemberOf | ForEach-Object { 
    "Adding $GPAdminsRoleGroup as a member of $_ ..."
    Add-ADGroupMember -Identity $_ -Members $GPAdminsRoleGroup -ErrorAction Stop 
}
