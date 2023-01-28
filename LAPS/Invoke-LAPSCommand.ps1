<#
.SYNOPSIS
Executes a scriptblock with a local administrator credential at LAPS-enabled computer.

.DESCRIPTION
The script remotely executes a scriptblock using credentials of an .\Administrator account provided by LAPS.
Password will be retrieved from an computer's Active Directory account.

.PARAMETER ComputerName
Specifies the computers on which the command runs.

.PARAMETER Scriptblock
A scriptblock to be executed.

.PARAMETER FlushDNS
Flush DNS cache before invokation.

.PARAMETER LAPSOnly
The script will not try to use current user credentials to access to remote computer if no LAPS password found in Active Directory.

.EXAMPLE
Invoke-LAPSCommand -ComputerName TestComp -Scriptblock { Get-EventLog -LogName Application -InstanceId 865 -Newest 5 | fl time, Message } -FlushDNS

Script will flush the local DNS cache then execute Get-EventLog cmdlet at remote computer TestComp

#>

param (
    [Parameter(Mandatory=$true,Position=0)]
    [string]$ComputerName,

    [Parameter(Mandatory=$true,Position=1)]
    [ScriptBlock]$Scriptblock,

    [switch]$FlushDNS,

    [switch]$LAPSOnly,

    [switch]$NoLogFile,

    [string]$Account = 'Administrator'
)

$PassAttrName = 'ms-mcs-admpwd'

function Write-Log {
    param(
        [string]$Message, 
        [string]$FilePath = ($LogFilename),
        [int]$Category = 0 # 0 - info, 1 - Warn, 2 - Error, 100 - Critical error (terminate program)
    )
    $TSStr = get-date -uformat '%Y.%m.%d %H:%M:%S'
    Write-Host "$TSStr " -NoNewline
    switch ($Category) {
        0 { $Color = 'White'; $Prefix = '' }
        1 { $Color = 'Yellow'; $Prefix = 'Warning:' }
        2 { $Color = 'Red'; $Prefix = 'Error:' }
        Default { $Color = 'Red'; $Prefix = 'FATAL ERROR:' }
    }
    $Message = ("$Prefix $Message").Trim()
    Write-Host $Message -ForegroundColor $Color
    if (!$NoLogFile -and ![string]::IsNullOrEmpty($FilePath)) { "$TSStr $Message" | Out-File -LiteralPath $FilePath -Encoding default -Append -Force }
    if ($Category -ge 100) { exit }
}

if ($NoLogFile) {
    Write-log "Logging to file is disabled"
} else {
    if ([string]::IsNullOrEmpty($LogFilename)) { $LogFilename = (New-TemporaryFile).FullName }
    Write-Log "Log filename: $LogFilename"
}

if ($FlushDNS) { 
    Write-Log "Flushing DNS cache"
    try {Clear-DnsClientCache} catch {Write-Host $Error[0].Exception.Message -ForegroundColor Yellow} 
}

$Login = "$ComputerName\$Account"
Write-Log "Using `"$Login`" as a remote local administrator login"

Write-Log "Getting credentials for $ComputerName"
$domaininfo = New-Object DirectoryServices.DirectoryEntry("")
$searcher = New-Object System.DirectoryServices.DirectorySearcher($domaininfo, "(&(objectClass=computer)(sAMAccountName=$ComputerName$))", $PassAttrName)
[string]$PPass = $searcher.FindOne().Properties.$PassAttrName
if ([string]::IsNullOrEmpty($PPass)) { 
    Write-Log "No password found in Active Directory for computer `"$ComputerName`""
    if ($LAPSOnly) {
        Write-Log "Exiting since -LAPSOnly switch is set"
        return 
    } else {
        Write-Log "Using current user credentials to access to the remote computer"
        try { 
            Write-Log $(Invoke-Command -ComputerName $ComputerName -ScriptBlock $Scriptblock -ErrorAction Stop)
        } catch {
            Write-Log $Error[0].Exception.Message -Category 2
        }
    }
} else {
    $Password = $PPass | ConvertTo-SecureString -asPlainText -Force
    Remove-Variable PPass
    $LACredential = New-Object System.Management.Automation.PSCredential($Login,$Password)
    Write-Log "Using AD-stored password for Administrator account"
    try { 
        Write-Log $(Invoke-Command -ComputerName $ComputerName -ScriptBlock $Scriptblock -Credential $LACredential -ErrorAction Stop)
    } catch {
        Write-Log $Error[0].Exception.Message -Category 2
    }
}
