param(
    $ReplaceFrom,
    $ReplaceTo,
    $SearchBase
)

$remoteScript = @'
    $ReplaceFrom = #FROM_PLACEHOLDER#
    $ReplaceTo = #TO_PLACEHOLDER#
    try {
        Import-Module dnsclient -ErrorAction Stop
        foreach ($i in Get-DnsClientServerAddress -AddressFamily IPv4) {
            if ($i | ? ServerAddresses -eq $ReplaceFrom) {
                $s = ($i.ServerAddresses | select @{n='a';e={if ($_ -eq $ReplaceFrom) {$ReplaceTo} else {$_}}}).a
                try {
                    Set-DnsClientServerAddress -InterfaceIndex $i.InterfaceIndex -ServerAddresses $s -ErrorAction Stop
                    "`nREPLACED: [$($i.InterfaceIndex)] $($i.InterfaceAlias) ($($i.ServerAddresses)) ==> ($s)"
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
'@ -f $ReplaceFrom, $ReplaceTo

$remoteScript = $remoteScript.Replace('#FROM_PLACEHOLDER#', $ReplaceFrom) 
$remoteScript = $remoteScript.Replace('#TO_PLACEHOLDER#', $ReplaceTo) 

$remoteScript
Read-Host -Prompt 'Press Enter'

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
        if ($NoPause -ne 'y') { $NoPause = Read-Host -Prompt "`n`n[Enter] to continue, [y][Enter] to continue without stops..." }
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
$IsFixed+$isok+$WErr

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