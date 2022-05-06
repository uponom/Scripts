<#
.SYNOPSIS
    Network connectivity test to a specified host
.DESCRIPTION
    This scrips is wrapper for Test-NetConnection cmdlet to provide ping-like functionality. It can check network connectivity by simple ping or by connecting to TCP port. 
.PARAMETER ComputerName
    Remote host
.PARAMETER CommonTCPPort
    Protocol to test by TCP connection. It can be SMB, HTTP, RDP or WINRM. Simple ping will be used if parameter omitted.

.PARAMETER SleepSeconds
    Time interval between tests. Default value is 5 seconds.

.PARAMETER Repeat
    How many times to repeat the test. Infinite repetitions if the parameter omitted or 0.
     
.PARAMETER Warnings
    Configures displaying of warnings messages. "SilentlyContinue" by default.    

.PARAMETER UntilSuccess
    Continue testing a connection until get success.
    It will stop testing even if you set -Repeat parameter.
     
.NOTES
    Version:        0.1
    Author:         Yurii Ponomarenko
  
.EXAMPLE
    pingp.ps1 -ComputerName somehost.contoso.com CommonTCPPort RDP -SleepSeconds 3
    Test network connectivity to somehost.contoso.com by TCP port 3389 in an infinite loop every 3 seconds.
#>

[cmdletbinding(
    SupportsShouldProcess,
    DefaultParameterSetName='Default'
)]

param(
    [Parameter(Mandatory=$true,
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName='Default',
        HelpMessage="Enter a computer name")]
    [ValidateNotNullOrEmpty()]
    [Alias("Host")]  
    [string]$ComputerName,
    
    [Parameter(Position=1,ValueFromPipelineByPropertyName=$true,ParameterSetName='Default')]
    [ValidateSet("SMB", "HTTP", "RDP", "WINRM")]
    [string]$CommonTCPPort = '',

    [int]$SleepSeconds = 5,
    [int]$Repeat = 0,
    [string]$Warnings = 'SilentlyContinue',
    [switch]$UntilSuccess
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
$OrigProgressPreference = $Global:ProgressPreference
$Global:ProgressPreference = 'SilentlyContinue'
$IsSuccessful = $false

do {
    Write-Host "$(get-date -UFormat '%Y.%m.%d %H:%M:%S') " -NoNewline
    if($PSCmdlet.ShouldProcess("$ComputerName", "Test network connection")) {
        try {
            $res = Test-NetConnection @Params
            $out = "$($res.ComputerName) [$($res.RemoteAddress)"
            # if ($res.PingSucceeded) { $out += "$FormatSuccess Ping Succeeded.$FormatReset" }
            if ($res.RemotePort -ne 0) { 
                $out += ":$($res.RemotePort)]" 
                if ($res.TcpTestSucceeded) { 
                    $out += "$FormatSuccess Tcp Test Succeeded.$FormatReset" 
                    $IsSuccessful = $true 
                } elseif (!$res.PingSucceeded) {
                    $out += "$FormatError Ping and TCP test are FAILED.$FormatReset"
                } else {
                    $out += "$FormatError Tcp Test FAILED.$FormatReset" 
                }
            } elseif ($res.PingSucceeded) {
                $out += "] $FormatSuccess Ping Succeeded.$FormatReset" 
                $IsSuccessful = $true 
            }
        } catch {
            $out += "$FormatError $($Error[0].Exception.Message)$FormatReset"
        }
        Write-Host $out
    }
    $Repeat--
    if (($UntilSuccess -and $IsSuccessful) -or ($Repeat -le 0 -and !$Infinite)) {break}
    $stayIn = ($Repeat -gt 0) -or $Infinite
    if ($stayIn) { Start-Sleep -Seconds $SleepSeconds }
} while ($stayIn)

$Global:ProgressPreference = $OrigProgressPreference

