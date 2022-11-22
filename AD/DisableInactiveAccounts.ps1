<#
.SYNOPSIS
    Disable users' or/and computers' accounts in Active Directory which have been inactive during period of time
.DESCRIPTION
    Script scans Active Directory domain for accounts (user or/and computer) where the attribute "lastLogontimestamp" have value older than current date minus specified number of days. Founded accounts can be disabled and moved to specified AD container.
.VERSION
    1.3
.WHATS NEW
    1.3
        [+] Added the switch parameter "DisableNeverLoggedComputers" for disabling computer accounts who was created more than "MaxInactiveDays" days ago and had no one login
    1.2 
        [+] Added parameters "ExcludeComputersGroup" and "ExcludeUsersGroup". Members of these groups will be excluded from processing.
        [*] Fixed sorting in a report
        [*] Fixed account type in a report for user accounts
    1.1
        [+] Added switch "ExtendedReport" - for display when an user account was expired
.PARAMETER Domain
    Active Directory domain name
.PARAMETER MaxInactiveDays
    Limit of inactivity period id days. If the parameter is ommitted 365 days period will be assigned.
.PARAMETER UsersSearchBase
    Specifies an Active Directory path to search users' accounts under
.PARAMETER DisabledUsersPath
    Specifies an Active Directory path to move users' accounts into
.PARAMETER ComputersSearchBase
    Specifies an Active Directory path to search computers' accounts under
.PARAMETER DisabledComputersPath
    Specifies an Active Directory path to move computers' accounts into
.PARAMETER MailReport
    Send mail report
.PARAMETER MailFrom
    Specifies the address from which the mail is sent
.PARAMETER MailTo
    Specifies the addresses to which the mail is sent
.PARAMETER SmtpServer
    Specifies the name of the SMTP server that sends the email message
.PARAMETER ExportReportPath
    Specifies path to report file. If ommited - report won't be exported to file
.PARAMETER LogFile
    Specifies path to log file. By default log file will be created in temporary directory (%temp%) with name DisableInactiveADAccounts.log
.PARAMETER ProcessUsers
    Process users' accounts
.PARAMETER ProcessComputers
    Process computers' accounts
.PARAMETER DisableAccounts
    Accounts meet with the described criteria will be disabled.
.PARAMETER DisableNeverLoggedComputers
    Disables computer accounts who was created more than "MaxInactiveDays" days ago and had no one login
.PARAMETER MoveAccounts
    Accounts meet with the described criteria will be moved. Users' accounts will be moved to path, specified by DisabledUsersPath parameter. Computers' accounts will be moved to path, specified by DisabledComputersPath parameter.
.PARAMETER ExcludeComputersGroup
    Accounts of computers which are members of this group will be excluded from processing (won't be disabled in any case)
    NOTE: No nested groups allowed!
.PARAMETER ExcludeUsersGroup
    Accounts of users which are members of this group will be excluded from processing (won't be disabled in any case)
    NOTE: No nested groups allowed!
.PARAMETER ExtendedReport
    Show an additional information about accounts
.PARAMETER EmailComment
    Add extra comment to the report email. Just put here any additional info that will be sent along with an email body (at the top of it).
.PARAMETER Verbose
    Enable verbose output
.PARAMETER Debug
    Enable extended debug output
.PARAMETER WhatIf
    Enable read-only mode
.EXAMPLE
    DisableInactiveAccounts.ps1 -Domain "contoso.local" -MaxInactiveDays 60 -ProcessUsers -UsersSearchBase "OU=CompanyUsers,DC=contoso,DC=local" -DisableAccounts
    Script will scan users' accounts in OU "CompanyUsers" and disable acconts which are inactive more then 60 day
.EXAMPLE
    DisableInactiveAccounts.ps1 -Domain "contoso.local" -MaxInactiveDays 90 -ProcessUsers -UsersSearchBase "OU=CompanyUsers,DC=contoso,DC=local" -DisabledUsersPath "OU=DisabledUsers,DC=contoso,DC=local" -ProcessComputers -ComputersSearchBase "OU=CompanyComputers,DC=contoso,DC=local" -DisabledComputersPath "OU=DisabledComputers,DC=contoso,DC=local" -DisableAccounts -MoveAccounts -MailReport -MailFrom "ADAccountsChecker@contoso.com" -MailTo "admins@contoso.com" -SmtpServer "mail.contoso.com"
    Script will scan, disable and move users' and computers' accounts which are inactive for 90 days, then send mail report
#>

#version 0.2

param(
    [PARAMETER(Mandatory=$True)]
    [string]$Domain,
    [PARAMETER(Mandatory=$True)]
    [int]$MaxInactiveDays = 365,
    [switch]$DisableAccounts,
    [switch]$MoveAccounts,
    [switch]$ProcessUsers,
    [string]$UsersSearchBase,
    [string]$DisabledUsersPath,
    [switch]$ProcessComputers,
    [string]$ComputersSearchBase,
    [string]$DisabledComputersPath,
    [switch]$MailReport,
    [string]$MailFrom,
    [string]$MailTo,
    [string]$SmtpServer,
    [string]$ExportReportPath = '',
    [string]$LogFile = "$($env:TEMP)\DisableInactiveADAccounts.log",
    [switch]$WhatIf,
    [switch]$ExtendedReport,
    [string]$ExcludeComputersGroup = '',
    [string]$ExcludeUsersGroup = '',
    [string]$EmailComment = '',
    [switch]$DisableNeverLoggedComputers
)

$AccountNeverExpires = 9223372036854775807 # https://docs.microsoft.com/en-us/windows/win32/adschema/a-accountexpires

function Write-Log {
    param(
        [string]$Str, 
        [string]$FilePath = ($LogFile)
    )
    $Str = "$(get-date -uformat '%Y.%m.%d %H:%M:%S')`t$Str"
    Write-Verbose $Str
    if (![string]::IsNullOrEmpty($FilePath)) {
        $Str | Out-File -LiteralPath $FilePath -Encoding default -Append -Force
    }
}

function FormatResults ($Inp){
    [PSObject[]]$Result = $null
    foreach ($I in $Inp) {
        if ($I.ObjectClass -eq 'user') {
            $Enabled = (Get-ADUser $I.SamAccountName -Server $Domain).Enabled
        } elseif ($I.ObjectClass -eq 'computer') {
            $Enabled = (Get-ADComputer $I.SamAccountName -Server $Domain).Enabled
        } else {
            $Enabled = 'N/A'
        }
        $SAN = $I.SamAccountName
        $Properties = [ordered]@{
            'Class' = $I.ObjectClass
            'SamAccountName' = $I.SamAccountName
            'Enabled' = $Enabled
            'OriginalDN' = $I.DistinguishedName
            'CurrentDN' = (Get-ADObject -filter {SamAccountName -eq $SAN } -Server $Domain).DistinguishedName
            'LastLogon' = [datetime]::FromFileTime($I.LastLogonTimestamp)
            'DaysAgo' = ($CurrDate-[datetime]::FromFileTime($I.LastLogonTimestamp)).Days
            'Created' = $I.whenCreated
        }
        if ($ExtendedReport) {
            if ($I.ObjectClass -eq 'user') {
                if (($I.accountExpires -eq $AccountNeverExpires) -or ($I.accountExpires -eq $null)) {
                    $Expires = 'never'
                } else {
                    $Expires = ([datetime]::FromFileTime($I.accountExpires)).ToShortDateString()
                }
            } else { 
                $Expires = 'N/A' 
            }
            $Properties.Add('Expires', $Expires)
        }
        $Result += New-Object –TypeName PSObject –Prop $Properties
    }
    $Result | sort Class, DaysAgo
}

function ListExceptions ( $ADGroupName ) {
    $Result = @()
    try {
        if (![string]::IsNullOrEmpty($ADGroupName)) { $Result += (Get-ADGroup $ADGroupName -ErrorAction Stop | Get-ADGroupMember).SamAccountName }
    } catch {
        Write-Log "ERROR: $($Error[0].Exception.Message)"
        Write-Log "!!! Script stopped with error !!!"
        Exit
    }
    $Result
}

#if ($Verbose) {$VerbosePreference = 'Continue'}
#if ($Debug) {$DebugPreference = 'Continue'}

$strWhatIfMode = "*** WhatIf mode ***"
$ExcludeComps = ListExceptions $ExcludeComputersGroup
$ExcludeUsers = ListExceptions $ExcludeUsersGroup
if ($ProcessComputers -and $ExcludeComps.Count -gt 0) {
    Write-Log 'Computers are listed below will be excluded from processing:'
    $ExcludeComps | ForEach-Object { Write-Log "`t- $_"}
}
if ($ProcessUsers -and $ExcludeUsers.Count -gt 0) {
    Write-Log 'Users are listed below will be excluded from processing:'
    $ExcludeUsers | ForEach-Object { Write-Log "`t- $_"}
}
$CurrDate = Get-Date
$MaxAge = ($CurrDate).AddDays(-$MaxInactiveDays)
$Accounts = New-Object System.Collections.ArrayList
Write-Debug "Log file path: $($LogFile)"
Write-Log "*** Script started ***"
if ($WhatIf) {Write-Log $strWhatIfMode}
Write-Log "Procesing domain $Domain"
$SkippedUsers = New-Object System.Collections.ArrayList
$SkippedComps = New-Object System.Collections.ArrayList

if ($ProcessUsers) {
    Write-Log "DisableUsers switch is set"
    Get-ADUser -Filter {LastLogonTimeStamp -lt $MaxAge -and Enabled -eq $true} -Server $Domain -Properties lastLogontimestamp, accountExpires, whenCreated -SearchBase $UsersSearchBase |
        ForEach-Object {
            Write-Debug "$($_.name)`tlastLogontimestamp: $([datetime]::FromFileTime($_.lastLogontimestamp))`tMaxAge: $MaxAge"
            if ($_.SamAccountName -in $ExcludeUsers) {
                Write-Log "[-] Skipped user:`t$($_.DistinguishedName)"
                $SkippedUsers.Add($_) | Out-Null
            } else {
                Write-Log "[+] Found user:`t$($_.DistinguishedName)"
                $Accounts.Add($_) | Out-Null
            }
        }      
}

if ($ProcessComputers) {
    Write-Log "DisableComputers switch is set"

    Get-ADComputer -Filter {Enabled -eq $true -and whenCreated -lt $MaxAge} -Properties lastLogontimestamp, whenCreated -SearchBase $ComputersSearchBase -Server $Domain |
        Where-Object { ($_.LastLogonTimeStamp -ne $null -or $DisableNeverLoggedComputers) -and ([datetime]::FromFileTime($_.LastLogonTimeStamp) -lt $MaxAge) } |
            ForEach-Object {
                Write-Debug "$($_.name)`tlastLogontimestamp: $([datetime]::FromFileTime($_.lastLogontimestamp))`tMaxAge: $MaxAge`tCreated:$($_.whenCreated)"
                if ($_.SamAccountName -in $ExcludeComps) {
                    Write-Log "[-] Skipped:`t$($_.DistinguishedName)"
                    $SkippedComps.Add($_) | Out-Null
                } else {
                    Write-Log "[+] Found:`t$($_.DistinguishedName)"
                    $Accounts.Add($_) | Out-Null
                }
            }      
}

Write-Debug "Processing (disabling and moving)..."
$AccountsProcessed = New-Object System.Collections.ArrayList
$AccountsErrors = New-Object System.Collections.ArrayList
foreach ($Acc in $Accounts) {
    Write-Debug "Processing: $Acc"
    try {
        $ProcPhase = ''
        if ($DisableAccounts) {
            Disable-ADAccount $Acc -Server $Domain -WhatIf:$WhatIf -ErrorAction Stop
            $ProcPhase = 'disabled'
        }
        if ($MoveAccounts) {
            if ($Acc.ObjectClass -eq 'user') {
                $MoveTo = $DisabledUsersPath
            } elseif ($Acc.ObjectClass -eq 'computer') {    
                $MoveTo = $DisabledComputersPath
            }
            Move-ADObject $Acc -TargetPath $MoveTo -Server $Domain -WhatIf:$WhatIf
            if ($ProcPhase -ne '') {$ProcPhase += ' and '}
            $ProcPhase += "moved to $MoveTo"
        }
        $AccountsProcessed.Add($Acc) | Out-Null
        Write-Log "$Acc - $ProcPhase"
    } catch {
        $AccountsErrors.Add($Acc) | Out-Null
        Write-Log "! Error processing account $Acc : $($Error[0].Exception.Message)"
    }
}

if ($MailReport) {
    if ($Accounts.Count -gt 0) {
        $ReportHead = @"
<style>
BODY{font-family: Verdana, Arial, Helvetica, sans-serif;}
TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;}
TD{border-width: 1px;padding: 5px;border-style: solid;border-color: black;}
</style>
<h2>In domain $Domain found $($Accounts.Count) account(s) inactive for $MaxInactiveDays days</h2>
<h3>List of succesfully processed accounts:</h3>
"@
        $MailSubj = "Report: $($Accounts.Count) accounts are inactive for $MaxInactiveDays days"
        if ($WhatIf) {
            $MailSubj += " $strWhatIfMode"
            $ReportHead += "<h3>$strWhatIfMode</h3>"
        }
        [string]$MailBody = FormatResults $AccountsProcessed | ConvertTo-Html -Head $ReportHead
        
        if ($SkippedComps.Count -gt 0) {
            $MailBody += FormatResults $SkippedComps | ConvertTo-Html -Head '<p><h2><font color="blue">There is list of skipped computers:</font></h2>'
        }

        if ($SkippedUsers.Count -gt 0) {
            $MailBody += FormatResults $SkippedUsers | ConvertTo-Html -Head '<p><h2><font color="blue">There is list of skipped users:</font></h2>'
        }

        if ($AccountsErrors.Count -gt 0) {
            $MailBody += FormatResults $AccountsErrors | ConvertTo-Html -Head '<p><h2><font color="red">There were errors while processing:</font></h2>'
        }

    } else {
        $MailBody = "<font color=`"green`">Inactive for $MaxInactiveDays accounts not found.</font>"
    }
    if ($EmailComment -ne '') { $MailBody = "<p>$EmailComment`n<p>$MailBody" }
    Write-Debug $MailBody
    try {
        Send-MailMessage  -Body $MailBody -SmtpServer $SMTPServer -Encoding ([System.Text.Encoding]::Default) -From $MailFrom -Subject $MailSubj -To $MailTo -BodyAsHtml -ErrorAction Stop
        Write-Log "Report sent to $MailTo"
    } catch {
        Write-Log "! Error sending report: $($Error[0].Exception.Message)"
    }
    if (![string]::IsNullOrEmpty($ExportReportPath)) { 
        try {
            $mailbody | Out-File -LiteralPath $ExportReportPath -Encoding default -Force -ErrorAction Stop
            Write-Log "Report exported to $ExportReportPath"
        } catch {}
    }
} 

Write-Log "*** Script finished ***"
