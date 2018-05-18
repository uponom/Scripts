# Script force users to change their password at next logon
# if password has not been changed for "PasswordAgeThreshold" days and user is member of "TargetADGroup" group

param(
    [Parameter( Position = 0, Mandatory = $True )]
    [ValidateNotNullOrEmpty()]
    [string]$TargetADGroup,
    [Parameter( Mandatory = $True )]
    [int]$PasswordAgeThreshold,
    [switch]$WhatIf,
    [string]$ExportFilename='',
    [switch]$ClearPasswordNeverExpires
)

$Now = Get-date
$MustChangeCounter = 0
$UsersCounter = 0
$ExpiredPasswordAndPasswordNeverExpired = 0
if ($WhatIf) {"*** WhatIf mode ***"}
if ((![string]::IsNullOrEmpty($ExportFilename)) -and (Test-Path -LiteralPath $ExportFilename)) {Remove-Item -LiteralPath $ExportFilename -WhatIf:$WhatIf -Force}
$PDCEmulator = (Get-ADDomain).PDCEmulator
foreach ($User in Get-adgroup $TargetADGroup | Get-ADGroupMember | Sort-Object name ) {
    $UsersCounter++
    Get-ADUser $User -Properties pwdLastSet, PasswordNeverExpires -server $PDCEmulator | Where-Object Enabled -eq $true |
        Select-Object samaccountname, PasswordNeverExpires, `
                #@{n='PasswordLastSet'; e={[DateTime]::FromFileTime($_.pwdLastSet)}}, `
                @{n='timestamp';e={(Get-Date).ToUniversalTime()}}, `
                @{n='PasswordLastSet'; e={[DateTime]::FromFileTime($_.pwdLastSet).ToString('yyyy-MM-dd')}}, `
                @{n='PasswordAge'; e={($Now - ([DateTime]::FromFileTime($_.pwdLastSet))).Days}} |
                    Add-Member -MemberType ScriptProperty -Name 'MustChange' -Value {$_.PasswordAge -gt $PasswordAgeThreshold} -PassThru -Force | 
                        ForEach-Object{
                            if (![string]::IsNullOrEmpty($ExportFilename)) {
                                $_ | Select-Object timestamp, samaccountname, PasswordNeverExpires, PasswordLastSet, PasswordAge, MustChange | Export-Csv -LiteralPath $ExportFilename -NoTypeInformation -Encoding Default -Append -WhatIf:$WhatIf
                            }
                            $_ | Select-Object samaccountname, PasswordNeverExpires, PasswordLastSet, PasswordAge, MustChange
                            if ($_.MustChange) {
                                $MustChangeCounter++
                                if ($_.PasswordNeverExpires) {
                                    $ExpiredPasswordAndPasswordNeverExpired++
                                    if ($ClearPasswordNeverExpires) {
                                        Set-ADUser -Identity $_.samaccountname -WhatIf:$WhatIf -PasswordNeverExpires $false -server $PDCEmulator
                                    }
                                }
                                Set-ADUser -Identity $_.samaccountname -WhatIf:$WhatIf -ChangePasswordAtLogon $true -server $PDCEmulator
                            }
                        }
}
"$UsersCounter users found in `"$TargetADGroup`" group"
"$MustChangeCounter users must change their password"
"$ExpiredPasswordAndPasswordNeverExpired of them had PasswordNeverExpires option"
