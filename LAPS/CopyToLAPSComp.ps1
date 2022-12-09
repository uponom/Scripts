<#
.SYNOPSIS
Copies a file to LAPS-enabled computer(s)

.DESCRIPTION
The CopyToLAPSComp script copies a file from a localy-reachable location to a disk at a computer (or computers) what is runned under the LAPS extension and can be reached only by local administrator credential.
The script try to get a local administrator password from Active Directory and use it for a remote connection.

.EXAMPLE
CopyToLAPSComp.ps1 -Sourse d:\distr\installer.msi -Destination c:\installs -ComputerName comp1,comp2,comp3 -Force

The script will copy a local file d:\distr\installer.msi to a folder c:\installs at remote computers comp1, comp2 and comp3

.NOTES
The destination path must be exist, otherwise script will rename a file to Destination name during copying.
#>

[cmdletbinding(
    DefaultParameterSetName='FromArgs'
)]
param(
    [Parameter(ParameterSetName='FromArgs', Mandatory=$true,Position=0)]
    [Parameter(ParameterSetName='FromFile', Mandatory=$true,Position=0)]
    [string]$Source,

    [Parameter(ParameterSetName='FromArgs', Mandatory=$true,Position=1)]
    [Parameter(ParameterSetName='FromFile', Mandatory=$true,Position=1)]
    [string]$Destination,

    [Parameter(ParameterSetName='FromArgs')]
    [Parameter(ParameterSetName='FromFile')]
    [switch]$CreatePath,

    [Parameter(ParameterSetName='FromArgs', Mandatory=$true)]
    [string[]]$ComputerName,

    [Parameter(ParameterSetName='FromFile', Mandatory=$true)]
    [string[]]$ComputersList,

    [Parameter(ParameterSetName='FromArgs')]
    [Parameter(ParameterSetName='FromFile')]
    [string]$LogFilename = '',

    [Parameter(ParameterSetName='FromArgs')]
    [Parameter(ParameterSetName='FromFile')]
    [string]$Login,

    [Parameter(ParameterSetName='FromArgs')]
    [Parameter(ParameterSetName='FromFile')]
    [switch]$Force,

    [Parameter(ParameterSetName='FromArgs')]
    [Parameter(ParameterSetName='FromFile')]
    [switch]$TestCredential,

    [Parameter(ParameterSetName='FromArgs')]
    [Parameter(ParameterSetName='FromFile')]
    [switch]$NoLogFile    

    # [switch]$Recurse # !!! TODO
    # $Domain # !!! TODO
    # $Credentials # !!! TODO   
)

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

Import-Module activedirectory -ErrorAction Stop

if ($NoLogFile) {
    Write-log "Logging to file is disabled."
} else {
    if ([string]::IsNullOrEmpty($LogFilename)) { $LogFilename = (New-TemporaryFile).FullName }
    Write-Log "Log filename: $LogFilename"
}

if ($ComputerName.Count -lt 1) { # Getting list of destination computers from a text file }
$ComputerName = @(Get-Content -LiteralPath $ComputersList)
}

$SourceFile = Get-Item $Source -ErrorAction Stop

if ([string]::IsNullOrEmpty($Login)) {
    $Login = (get-localuser | Where-Object SID -like 'S-1-5-21-*-500').Name
}

foreach ($comp in $ComputerName) {
    Write-Log "Processing `"$comp`"..."
    $Login = "$comp\$Login"
    Write-Log "Using `"$Login`" as a remote local administrator login."
    Write-Log "Getting credentials for $comp ..."
    [string]$PPass = (Get-ADComputer $comp -Properties ms-Mcs-AdmPwd).'ms-Mcs-AdmPwd'
    if ([string]::IsNullOrEmpty($PPass)) {
        Write-Log 'No password found in AD' -Category 2
        continue
    }
    $Password = $PPass | ConvertTo-SecureString -asPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential($Login,$Password)
    
    # Test credentials
    if ($TestCredential) {
        Write-Log 'Requesting the remote computer name to test credentials...'
        try {
            $RCN = Invoke-Command -ComputerName $comp -Credential $Credential -ScriptBlock {$env:COMPUTERNAME} -ErrorAction Stop
            Write-Log "Remote responded: $RCN"
            if ($RCN -ne $comp) { Write-Log "The remote response ($RCN) doesn't match the requested computer name ($comp)" -Category 1 }
        } catch {
            Write-Log $Error[0].Exception.Message -Category 2
            return
        }
    }
    
    # Getting a free drive letter
    $TmpDriveLetter = (Get-ChildItem function:[d-z]: -n | Where-Object { !(Test-Path $_) } | Get-random)[0]
    
    $DestinationPath = "\\$comp\$($Destination[0])$"
    Write-Log "Connecting to $DestinationPath ..."
    try {
        $TmpDrive = New-PSDrive -Name $TmpDriveLetter -PSProvider FileSystem -Root $DestinationPath -ErrorAction Stop -Credential $Credential
        $FullDestPath = "$TmpDriveLetter$($Destination.Substring(1))"

        # Checking if destnation path is exists
        if (!(Test-Path -LiteralPath $FullDestPath -PathType Container)) {
            if ($CreatePath) {
                Write-Log "Creating a destination directory `"$FullDestPath`" ..."
                $NewDir = mkdir -Path $FullDestPath -ErrorAction Stop
                Write-Log "`"$($NewDir.FullName)`" was created."
            } else {
                throw "Destination path does not exist at the computer $comp"
            }
        }

        $FullDestFilename = Join-Path $FullDestPath $SourceFile.Name
        Write-Log "Copying `"$($SourceFile.FullName)`" to `"$Destination`" at $comp..."
        Copy-Item -LiteralPath $SourceFile.FullName -Destination $FullDestFilename -ErrorAction Stop -force:$Force
        Write-Log "File is copied."
        Remove-PSDrive $TmpDrive -ErrorAction Stop
    } catch {
        Write-Log $Error[0].Exception.Message -Category 2
        if (Test-path "$($TmpDriveLetter):\") {Remove-PSDrive $TmpDrive -ErrorAction SilentlyContinue}
    }
}
