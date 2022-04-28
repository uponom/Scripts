[cmdletbinding(
    SupportsShouldProcess,
    DefaultParameterSetName='Default'
)]

param(
    [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='Default')]
    [ValidateNotNullOrEmpty()]
    [Alias("Host")]  
    [string]$ComputerName,
    
    [Parameter(Position=1,ValueFromPipelineByPropertyName=$true,ParameterSetName='Default')]
    [string]$CommonTCPPort = '',
    [int]$SleepSeconds = 15,
    [int]$Repeat = 0,
    [string]$Warnings = 'SilentlyContinue'
)

$FormatSuccess = $PSStyle.Formatting.FormatAccent
$FormatError = $PSStyle.Formatting.Error
$FormatReset = $PSStyle.Reset

if ($Repeat -eq 0) {
    $Infinite = $true
    Write-Host 'Infinite mode - press Ctrl-C to break.'
} else {
    $Infinite = $false
}

$Params = @{ 
    ComputerName = $ComputerName
    WarningAction = $Warnings 
}
if ([string]::IsNullOrEmpty($CommonTCPPort)) {
    Write-Host 'Ping check.'
} else { 
    $Params.Add( 'CommonTCPPort', $CommonTCPPort )
    Write-Host "$($CommonTCPPort.ToUpper()) port test." 
}

$PSStyle.Progress.View = 'Classic'

while (($Repeat -gt 0) -or $Infinite) {
    Write-Host "$(get-date -UFormat '%Y.%m.%d %H:%M:%S') " -NoNewline
    if($PSCmdlet.ShouldProcess("$ComputerName", "Test network connection")) {
        try {
            $res = Test-NetConnection @Params
            $out = "$($res.ComputerName) [$($res.RemoteAddress)]"
            if ($res.PingSucceeded) { $out += "$FormatSuccess Ping Succeeded.$FormatReset" }
            if ($res.RemotePort -ne 0) { $out += " RemotePort=$($res.RemotePort)." }
            if ($res.TcpTestSucceeded) { 
                $out += "$FormatSuccess Tcp Test Succeeded.$FormatReset" 
            } elseif (!$res.PingSucceeded) {
                $out += "$FormatError Ping and TCP test are FAILED.$FormatReset"
            } else {
                $out += "$FormatError Tcp Test FAILED.$FormatReset" 
            }
        } catch {
            $out += "$FormatError $($Error[0].Exception.Message)$FormatReset"
        }
        Write-Host $out
    }
    Start-Sleep -Seconds $SleepSeconds
    $Repeat--
}