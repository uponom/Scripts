<#
.SYNOPSIS
    Goes thru computer accounts in Active Directory and change statically assigned DNS server address.
.DESCRIPTION
    Goes thru computer accounts in Active Directory and change statically assigned DNS server address. 
    You must specify an original IP address to change and a new IP address.
    You should define exact Organization Unit distinguished name. Also you can specify Operating System filter – only accounts which match to that filter will be processed. The default filter is “*Server*”.
.PARAMETER ReplaceFrom
    The DNS server IP address to replace in a network adapters settings. If this IP address is not found, the DNS server setting will be ignored.
.PARAMETER ReplaceTo
    The new DNS server IP address to be set in a network adapters settings.
.PARAMETER SearchBase
    The distinguished name of AD Organization Unit where computer accounts to be processed are located.
.PARAMETER OperationSystemLike
    Template for operation system names to be processed. By default only OS like "*Server*" will be processed. You can set "*" to ignore operation system name and process all computer accounts.
.PARAMETER Pause
    Wait for Enter pressed after each computer processed
.PARAMETER v
    Verbose: list of NICs with DNS server addresses assigned
.NOTES
    Author:         Yurii Ponomarenko
.EXAMPLE
    ChangeDNSAddress.ps1 -ReplaceFrom 10.0.0.10 -ReplaceTo 10.20.0.20 -SearchBase "OU=Computers,OU=Contoso,DC=Contoso,DC=LAN" -OperationSystemLike "Windows Server 2022*"

    It will replace the DNS server address in NIC IP settings from 10.0.0.10 to 10.20.0.20 at all computers in OU "OU=Computers,OU=Contoso,DC=Contoso,DC=LAN" which have OS "Windows Server 2022".
#>

[cmdletbinding(
)]

param(
    [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [Alias('From')]
    [string]$ReplaceFrom,
    
    [Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [Alias('To')]
    [string]$ReplaceTo,
    
    [Parameter(Mandatory=$true,Position=2,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [string]$SearchBase,
    
    [Alias('OS')]
    [string]$OperationSystemLike = '*Server*',

    [switch]$Pause,

    [switch]$v,

    [switch]$WhatIf
)

$remoteScript = @'
    $ReplaceFrom = '#FROM_PLACEHOLDER#'
    $ReplaceTo = '#TO_PLACEHOLDER#'
    try {
        Import-Module dnsclient -ErrorAction Stop
        foreach ($i in Get-DnsClientServerAddress -AddressFamily IPv4) {
            if ($Using:v) { $i | ? ServerAddresses -ne $null | %{ "`nVERBOSE: $($_.InterfaceAlias) : $($i.ServerAddresses)" } }
            if ($i | ? ServerAddresses -eq $ReplaceFrom) {
                $s = ($i.ServerAddresses | select @{n='a';e={if ($_ -eq $ReplaceFrom) {$ReplaceTo} else {$_}}}).a
                try {
                    if ($Using:WhatIf) {
                        "`nWHATIF: Replace [$($i.InterfaceIndex)] $($i.InterfaceAlias) ($($i.ServerAddresses)) ==> ($s)"
                    } else {
                        Set-DnsClientServerAddress -InterfaceIndex $i.InterfaceIndex -ServerAddresses $s -ErrorAction Stop
                        "`nREPLACED: [$($i.InterfaceIndex)] $($i.InterfaceAlias) ($($i.ServerAddresses)) ==> ($s)"
                    }
                } catch {
                    "`nERROR: Set-DnsClientServerAddress: $($Error[0].Exception.Message)"
                }
            } else {
                "`nOK: [$($i.InterfaceIndex)] $($i.InterfaceAlias)"

            } 
        }
    } catch {
        "ERROR: $($Error[0].Exception.Message)"
    }
'@

$remoteScript = $remoteScript.Replace('#FROM_PLACEHOLDER#', $ReplaceFrom) 
$remoteScript = $remoteScript.Replace('#TO_PLACEHOLDER#', $ReplaceTo) 

$sb = [Scriptblock]::Create($remoteScript)

$NoPause = 'n'
$WErr = 0
$IsOK = 0
$IsFixed = 0
$counter = 0

[string[]]$FixedList = @()
[string[]]$IsOKList = @()
$ErrorList = @{}



foreach ($i in (Get-ADComputer -Filter {Enabled -eq $true -and OperatingSystem -like '*Server*'} -Properties OperatingSystem -SearchBase $SearchBase)) {
    $counter++
    Write-Host " $($i.name) " -ForegroundColor White -BackgroundColor DarkCyan -NoNewline
    try {
        $R = ''
        $R = Invoke-Command -ComputerName $i.name -ScriptBlock $sb -ErrorAction Stop
        if ($R -like '*REPLACED: *') {
            $IsFixed++
            $FixedList += $i.name
            $color = 'Green'
        } elseif ($R -like '*OK: *') {
            $IsOK++
            $IsOKList += $i.name
            $color = 'Cyan'
        } elseif ($R -like '*ERROR: *') {
            $WErr++
            $ErrorList.Add($i.name, $R)
            $color = 'Red'
        } else { $color = 'white' }
        Write-Host $R -ForegroundColor $color
        if ($Pause) {
            if ($NoPause -ne 'y') { $NoPause = Read-Host -Prompt "`n`n[Enter] to continue, [y][Enter] to continue without stops..." }
        }
    } catch {
        $EM = $Error[0].Exception.Message
        Write-Host ' Connect error.' -ForegroundColor Red
        $WErr++
        $ErrorList.Add($i.name, $EM)
    }
}

"Total: $counter"
"Fixed: $IsFixed"
"OK:    $IsOK"
"Error: $WErr"

### Workaroupnd for pre-Windows2012 machines ###
#
# $nodnsclient = {
#     $ReplaceFrom = '10.10.0.64'
#     $ReplaceTo = '10.216.1.33'
#     $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.DNSServerSearchOrder -ne $null}
#     foreach ($a in $adapters) {
#         $a.DNSServerSearchOrder
#         $s = ($a.DNSServerSearchOrder | select @{n='a';e={if ($_ -eq $ReplaceFrom) {$ReplaceTo} else {$_}}}).a
#         $a.SetDNSServerSearchOrder($s)
#     }
#     Get-WmiObject Win32_NetworkAdapterConfiguration | ft Description, DNSServerSearchOrder -AutoSize
# }
#
# foreach ($i in $ErrorList.GetEnumerator()) {
    #     if ($i.Value -like '*dnsclient*') {
        #         "***** $($i.key) ******"
        #         Invoke-Command -ComputerName $i.key -ScriptBlock $nodnsclient
        #         Read-Host -pro 'Press Enter to continue' | Out-Null
        #     }
# }