<#
.SYNOPSIS
    Disable users' or/and computers' accounts in Active Directory which have been inactive during period of time
.DESCRIPTION
    Script scans Active Directory domain for accounts (user or/and computer) where the attribute "lastLogontimestamp" have value older than current date minus specified number of days. Founded accounts can be disabled and moved to specified AD container.
.VERSION
    1.2
.WHATS NEW
    1.2 
        [+] Added parameters "ExcludeComputersGroup" and "ExcludeUsersGroup". Members of these groups will be excluded from processing.
        [*] Fixed sorting in a report
        [*] Fixed account type in a report for user accounts
    1.1
        [+] Added switch "ExtendedReport" - for display when an user account was expired
.PARAMETER Domain
    Active Directory domain name
.PARAMETER MaxInactiveDays
    Limit of inactivity period id days
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
    [string]$ExcludeUsersGroup = ''
)

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
<#
    $Inp | select ObjectClass, SamAccountName, `
                    @{n='Enabled';e={if ($_.ObjectClass -eq 'user') {(Get-ADUser $_.SamAccountName -Server $Domain).Enabled} elseif ($_.ObjectClass -eq 'computer') {(Get-ADComputer $_.SamAccountName -Server $Domain).Enabled} else {'N/A'} }}, `
                    @{n='OriginalDN';e={$_.DistinguishedName}}, `
                    @{n='CurrentDN';e={$SAN = $_.SamAccountName; (Get-ADObject -filter {SamAccountName -eq $SAN } -Server $Domain).DistinguishedName}}, `
                    @{n='LastLogon';e={[datetime]::FromFileTime($_.LastLogonTimestamp)}}, `
                    @{n='DayAgo';e={($CurrDate-[datetime]::FromFileTime($_.LastLogonTimestamp)).Days}} |
                        sort ObjectClass, DayAgo
#>
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
        }
        if ($ExtendedReport) {
            if ($I.ObjectClass -eq 'user') {
                #Write-host "$($I.SamAccountName) ==> $($I.accountExpires)" -foreground Green
                #$ae = (Get-ADUser $I.SamAccountName -Server $Domain).accountExpires
                if (($I.accountExpires -eq 9223372036854775807) -or ($I.accountExpires -eq $null)) {
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
    Write-Log 'Computes which are listed below will be excluded from processing:'
    $ExcludeComps | %{ Write-Log "`t- $_"}
}
if ($ProcessUsers -and $ExcludeUsers.Count -gt 0) {
    Write-Log 'Users which are listed below will be excluded from processing:'
    $ExcludeUsers | %{ Write-Log "`t- $_"}
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
    Get-ADUser -Filter {LastLogonTimeStamp -lt $MaxAge -and Enabled -eq $true} -Server $Domain -Properties lastLogontimestamp, accountExpires -SearchBase $UsersSearchBase | # ?{($_.lastLogontimestamp -ne $null) -and ([datetime]::FromFileTime($_.lastLogontimestamp) -lt $MaxAge ) } | 
        %{
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
    Get-ADComputer -Filter {LastLogonTimeStamp -lt $MaxAge -and Enabled -eq $true} -Server $Domain -Properties lastLogontimestamp -SearchBase $ComputersSearchBase | # ?{($_.lastLogontimestamp -ne $null) -and ([datetime]::FromFileTime($_.lastLogontimestamp) -lt $MaxAge ) } | 
        %{
            Write-Debug "$($_.name)`tlastLogontimestamp: $([datetime]::FromFileTime($_.lastLogontimestamp))`tMaxAge: $MaxAge"
            if ($_.SamAccountName -in $ExcludeComps) {
                Write-Log "[-] Skipped comp:`t$($_.DistinguishedName)"
                $SkippedComps.Add($_) | Out-Null
            } else {
                Write-Log "[+] Found comp:`t$($_.DistinguishedName)"
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
            $MailBody += FormatResults $SkippedComps | ConvertTo-Html -Head '<p><h2><font color="blue">There are skipped computers:</font></h2>'
        }

        if ($SkippedUsers.Count -gt 0) {
            $MailBody += FormatResults $SkippedUsers | ConvertTo-Html -Head '<p><h2><font color="blue">There are skipped users:</font></h2>'
        }

        if ($AccountsErrors.Count -gt 0) {
            $MailBody += FormatResults $AccountsErrors | ConvertTo-Html -Head '<p><h2><font color="red">There were errors while processing:</font></h2>'
        }

    } else {
        $MailBody = "<font color=`"green`">Inactive for $MaxInactiveDays accounts not found.</font>"
    }
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

# SIG # Begin signature block
# MIIKzgYJKoZIhvcNAQcCoIIKvzCCCrsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUQsm244TZHKm4VU0N0KSmTc3z
# j0igggc/MIIHOzCCBiOgAwIBAgIKPjsvgwAAAAABozANBgkqhkiG9w0BAQsFADBK
# MRMwEQYKCZImiZPyLGQBGRYDTEFOMRYwFAYKCZImiZPyLGQBGRYGSE9NRTI0MRsw
# GQYDVQQDExJIT01FMjQtRlBDLURDMDEtQ0EwHhcNMTgwNTI4MDg0MzQwWhcNMjIw
# NjI5MjAxNTIyWjCBkjETMBEGCgmSJomT8ixkARkWA0xBTjEWMBQGCgmSJomT8ixk
# ARkWBkhPTUUyNDEPMA0GA1UECxMGSE9NRTI0MQ0wCwYDVQQLEwR1c2VyMQswCQYD
# VQQLEwJJVDEaMBgGA1UECwwRdGVzdF9IYW5nb3V0c0NoYXQxGjAYBgNVBAMTEVl1
# cmlpIFBvbm9tYXJlbmtvMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# nAnArMW46ndumw8D26xMN0EzqrZfy3jWpGbuErbvo104MFkA0M9B+YRBIBpg9pyc
# jJHbD3gJt+DnL/PJvrlfQqNnBZ+0wamCjpZ3Fyxi4zZohJYR9U9luDxzLHlPTlVP
# kDyCUWK/8BnjYI2F+PkICl439hLKIgJFNtgWjiqoqkkHcal5pmDHExvnPYN236e/
# rLNy5QG4fMCeJVAMBEMxK3yqHVKHUabGuqoleXS+D0ZeENJjBv+dtwM69+IaOgbx
# H9rsNg2NFIeqBSRPedZlEO4J6HHyOMEMZaOoJ7SalJzd6glX3TVyZg3oQ5kA9mKg
# 17dG21qSzXbDZLQebzTpupyfF4cJzfgtuF5HKGJI+h1YUmxUkb88kzD4xq4p+6Ac
# FMQCRNBdjNQ3epabsH6Y1/YYhYaKFQ7FHsjHpCLXcJK5IsL+Sdeos2JBToSCPS57
# oY6SGLzoCgW+5a+3fL1ltjdwgQOeY+pOAavDMhdA1XD6gx98r0jttY4kQGkQb0FG
# vtxOir+byCW8ylasybN81m6FlfrTjCtcTJk0hHVDXyAnKwitLwVubk4igzh3gdY+
# Oe4qaOXu27crd8gHpBShl82OxGlT8dSA3+CG4r39iVBN2SfDYxUQ4CgvH/yTr5pq
# 8QsfmmrODYQQ4NeZ93mUExvhA5vgZGfh7E+Ac5JYT5ECAwEAAaOCAtgwggLUMD0G
# CSsGAQQBgjcVBwQwMC4GJisGAQQBgjcVCIKe4wCE4OtDhbGPLoLe9wOFkbFkgSCr
# +ACHtK9ZAgFkAgEDMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIH
# gDAbBgkrBgEEAYI3FQoEDjAMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBR+J9qFfyQ6
# OUAFeor4elWZLMMrgjAfBgNVHSMEGDAWgBT5txsgAMNmojURI9R4BRyOej9UNzCC
# AREGA1UdHwSCAQgwggEEMIIBAKCB/aCB+oaBuWxkYXA6Ly8vQ049SE9NRTI0LUZQ
# Qy1EQzAxLUNBLENOPUZQQy1EQzAxLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBT
# ZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPUhPTUUyNCxE
# Qz1MQU4/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNz
# PWNSTERpc3RyaWJ1dGlvblBvaW50hjxodHRwOi8vZnBjLWRjMDEuaG9tZTI0Lmxh
# bi9DZXJ0RW5yb2xsL0hPTUUyNC1GUEMtREMwMS1DQS5jcmwwgcMGCCsGAQUFBwEB
# BIG2MIGzMIGwBggrBgEFBQcwAoaBo2xkYXA6Ly8vQ049SE9NRTI0LUZQQy1EQzAx
# LUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNl
# cyxDTj1Db25maWd1cmF0aW9uLERDPUhPTUUyNCxEQz1MQU4/Y0FDZXJ0aWZpY2F0
# ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwNgYDVR0R
# BC8wLaArBgorBgEEAYI3FAIDoB0MG3l1cmlpLnBvbm9tYXJlbmtvQGhvbWUyNC5k
# ZTANBgkqhkiG9w0BAQsFAAOCAQEAKjUiMzO4ZMECYjavWwPk8Conw0Ye9Jbex/yD
# qFtIUllpRpArN505Mvj3qVrkz8F6bpKVzCa4vmqFR7G9wmtsWnIK+OOcXtdVGr+0
# J7/ZD2pMZUVoGgHIiw3MCli48vbNTjHpKuLGjyFEtlKvbWWQyB6pRpZ0ZF4MES71
# lh+TMhvA7D1KKf2+cXlrd1Y5qqjtCMgYkhT/dheHkVJ8+tesnHkRA6BAmZpTmaYv
# exMFlE6PY5YGYcbVgqDE+ZzOz34YLlDjJ6at7FygfSADt8i3zYtvs87YeXBB+yHK
# 3dU67MUsllvJzfKIEBVGK39a8ULjZeJf92FKSjKuTyERPnSo3TGCAvkwggL1AgEB
# MFgwSjETMBEGCgmSJomT8ixkARkWA0xBTjEWMBQGCgmSJomT8ixkARkWBkhPTUUy
# NDEbMBkGA1UEAxMSSE9NRTI0LUZQQy1EQzAxLUNBAgo+Oy+DAAAAAAGjMAkGBSsO
# AwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEM
# BgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqG
# SIb3DQEJBDEWBBSSmrG6OMgYES96f0LKS6fUGb7lHjANBgkqhkiG9w0BAQEFAASC
# AgBMUiKxYX323noKQdEpJ0iz4hH41MpMO+KHP0abEbKq6XPJlqL8Cv+qy89QRZn6
# VqdynVWDm0s+KjEweOzuU7MzM83sKC8fwzxb+Ys059BqUwwjQsC+nYe6sykvc+ct
# u76X55oWXfGs2IXkBcR2PrRkwkwEIEv2RToz/9g5tI4HDBaefhIdL0OxpMZcwdaI
# 5iQ93jq8sllDHbkRQRUbfYNMNTFXpfpQEDSBeR4I6/ooSmIX5gRCBbZh+hAF4laG
# mofLFJz1/tWutmVmo+LHHCFPZYySKRqh7Sw92Bbbc9l3Aq1Td8O3L1N9e0sByi0x
# Bsz2Aq0rwt6YjjBzaOQNQGdQBWCyxejo3w2gQ8xHAXkGtwT4gP/+WVEdjYvgZCW1
# 0gPyQn3I8HHzxCYeRd59kASRRh5ecBIvC83Q8XlBdyNOwFfEaRZ0qQUE1vwcNtNs
# Cm2n5hkhrnUSm0EiupurTExY5QC/iiXlRlnJYIiQQUOhvV4sFjSjfUnAtsM2tWps
# MCjz1y3m0jVYdbwrB5y27x89TjQbTX605uHWSUZxCSbfqlCRQUTNTQCUGJP+0UY/
# hXaM77wmbLt7P7OLEiUFL6pxNPYBxa15H597lm7nNaA7pV9ZnOs0UYdZzouyPmcs
# RxKcmsCQLmribm19XbEf6NsVWocUkPwtIq0OVdLWtIgcWw==
# SIG # End signature block
