<#
.SYNOPSIS
    The script recursuvely copies files from SFTP to a local path.

.DESCRIPTION
    The script recursuvely copies files from SFTP to a local path.

    The script uses "Posh-SSH" module. It can be installed by following command:
    Install-Module -Name Posh-SSH
    
.PARAMETER RemoteHost
    Remote host name or IP address.

.PARAMETER Username
    User name for login to SFTP.

.PARAMETER Password
    Password for login to SFTP.

.PARAMETER CredentialFile
    Encrypted file with credentials for login to SFTP.
    Instead of using plain text login/password in parameners, you can store credentials in an encrypted file.
    To prepare an credential file use following command:
        Get-Credential | Export-CliXml CredentialFilename.xml

.PARAMETER SourcePath
    Source path at SFTP.

.PARAMETER TargetPath
    Target (local) path. 

.PARAMETER Filter
    Filter for source files. Defaul value is "*". 

.PARAMETER Force
    Overwrite target files.

.PARAMETER LogFile
    Full file name for a log file. Log won't be written if the parameter ommited.

.PARAMETER CreateJsonParamsFile
    Create a parameters file.
    Instead of putting all parameters to a command line every script execution, you can run the script with all necessary parameters once and save them to a file by using -CreateJsonParamsFile. 
    Then you can call the script with the saved parameters by using -JsonParams

.PARAMETER JsonParams
    Load script parameters from a file.

.INPUTS
    None

.OUTPUTS
    None

.NOTES
    Version:        1.0
    Author:         Yurii Ponomarenko
    Creation Date:  2021-01-08
  
    Using SSH-keys has not implemented yet.
    The script uses "Posh-SSH" module.
    
.EXAMPLE
    CopyFromSFTP.ps1 -RemoteHost sftp.example.com -SourcePath "/Reports/Annual/" -TargetPath "d:\myreports\" -Force -CredentialFile "c:\creds\sftpcreds.xml" -LogFile "d:\logs\sftpdownload.log"

    In this example the script downloads all files from sftp.example.com:/Reports/Annual (including subdirectories) to d:\myreports. Existing target files will be overwritten. Log will be save to d:\logs\sftpdownload.log. Credentials will be taken from c:\creds\sftpcreds.xml.

#>

#requires -version 5

[cmdletbinding(
    DefaultParameterSetName='LoginPassword'
)]

param(
    [Parameter(Mandatory=$true,ParameterSetName='LoginPassword')]
    [Parameter(Mandatory=$true,ParameterSetName='CredentialFile')]
    [Parameter(Mandatory=$true,ParameterSetName='CreateJson')]
    [string]$RemoteHost,

    [Parameter(Mandatory=$true,ParameterSetName='LoginPassword')]
    [Parameter(ParameterSetName='CreateJson')]
    [string]$Username,

    [Parameter(Mandatory=$true,ParameterSetName='LoginPassword')]
    [Parameter(ParameterSetName='CreateJson')]
    [string]$Password,

    [Parameter(Mandatory=$true,ParameterSetName='CredentialFile')]
    [Parameter(ParameterSetName='CreateJson')]
    [string]$CredentialFile,

    [Parameter(Mandatory=$true,ParameterSetName='LoginPassword')]
    [Parameter(Mandatory=$true,ParameterSetName='CredentialFile')]
    [Parameter(Mandatory=$true,ParameterSetName='CreateJson')]
    [string]$SourcePath,

    [Parameter(ParameterSetName='LoginPassword')]
    [Parameter(ParameterSetName='CredentialFile')]
    [Parameter(ParameterSetName='CreateJson')]
    [string]$Filter = '*',

    [Parameter(Mandatory=$true,ParameterSetName='LoginPassword')]
    [Parameter(Mandatory=$true,ParameterSetName='CredentialFile')]
    [Parameter(Mandatory=$true,ParameterSetName='CreateJson')]
    [string]$TargetPath,

    [Parameter(ParameterSetName='LoginPassword')]
    [Parameter(ParameterSetName='CredentialFile')]
    [Parameter(ParameterSetName='CreateJson')]
    [switch]$Force,

    [Parameter(ParameterSetName='LoginPassword')]
    [Parameter(ParameterSetName='CredentialFile')]
    [Parameter(ParameterSetName='CreateJson')]
    [string]$LogFile = '',

    [Parameter(Mandatory=$true,ParameterSetName='JsonParams')]
    [string]$JsonParamsFile,

    [Parameter(Mandatory=$true,ParameterSetName='CreateJson')]
    [string]$CreateJsonParamsFile
)

[string]$DependModule = 'Posh-SSH'

function Write-Log {
    <#
        .SYNOPSIS
            Writes logging information to the host screen and to a log file

        .DESCRIPTION
            Function writes a given message to the host screen (unless -NoWriteHost parameter) and writes to a log file in a text format.

        .PARAMETER Message
            The message to be logged.

        .PARAMETER FilePath
            The log file path. Function will write nothing to a file if parameter is ommited.

        .PARAMETER Category
            The message importance category. 0 is Information, 1 is Warning, 2 is Error, 100 is Critical. The Critical category will stop the program.
            Default value is 0.

        .PARAMETER TimestampFormat
            The output message Timestamp format.
            See https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-date?view=powershell-7#notes for details.
            Default value is %Y.%m.%d %H:%M:%S

        .PARAMETER Encoding
            The output log file encoding.
            Default value is Default.

        .PARAMETER NoWriteHost
            Suppress output to the host screen

        .OUTPUT $null
    #>
    param(
        [string]$Message, 
        [string]$FilePath = '',
        [int]$Category = 0, # 0 - info, 1 - Warn, 2 - Error, 100 - Critical error (terminate program)
        [string]$TimestampFormat = '%Y.%m.%d %H:%M:%S',
        [switch]$NoWriteHost,
        [string]$Encoding = 'default'
    )
    $TSStr = get-date -uformat $TimestampFormat
    if (!$NoWriteHost) { Write-Host "$TSStr " -NoNewline }
    switch ($Category) {
        0 { $Color = 'White'; $Prefix = '' }
        1 { $Color = 'Yellow'; $Prefix = 'Warning:' }
        2 { $Color = 'Red'; $Prefix = 'Error:' }
        Default { $Color = 'Red'; $Prefix = 'FATAL ERROR:' }
    }
    $Message = ("$Prefix $Message").Trim()
    if (!$NoWriteHost) { Write-Host $Message -ForegroundColor $Color }
    if (![string]::IsNullOrEmpty($FilePath)) { "$TSStr $Message" | Out-File -LiteralPath $FilePath -Encoding $Encoding -Append -Force }
    if ($Category -ge 100) { exit }
}


#region Main

if (!([string]::IsNullOrEmpty($CreateJsonParamsFile))) {    $properties = [ordered]@{        Username = $Username        Password = $Password        CredentialFile = $CredentialFile        RemoteHost = $RemoteHost        SourcePath = $SourcePath        Filter = $Filter
        TargetPath = $TargetPath
        Force = $Force.ToBool()
        LogFile = $LogFile
    }
    $object = New-Object –TypeName PSObject –Prop $properties    $object | fl *
    try {
        $object | ConvertTo-Json -depth 100 | Out-File $CreateJsonParamsFile -Encoding utf8 -ErrorAction Stop
    } catch {
        Write-Log -Message $Error[0].Exception.Message -Category 2
        return
    }
    Write-Log -Message "JSON Paramenets file is created: $JsonParamsFile"
    return
} elseif (![string]::IsNullOrEmpty($JsonParamsFile)) {
    if (Test-Path $JsonParamsFile) {
        Write-Host "Loading parameters from file $JsonParamsFile"
        try {
            $object = Get-Content $JsonParamsFile -Encoding UTF8 | ConvertFrom-Json
        $Username = $object.Username         $Password = $object.Password        $CredentialFile = $object.CredentialFile         $RemoteHost = $object.RemoteHost        $SourcePath = $object.SourcePath        $Filter = $object.Filter
        $TargetPath = $object.TargetPath
        $Force = $object.Force
        $LogFile = $object.LogFile
        } catch {
            Write-Host $Error[0].Exception.Message -ForegroundColor Red
            return
        }
    } else {
        Write-Host "ERROR: File not found: $JsonParamsFile" -ForegroundColor Red
        return
    }
}

Write-Log -Message '+++ Script started +++' -FilePath $LogFile
if (![string]::IsNullOrEmpty($LogFile)) { Write-log "Log filename: $LogFile" -FilePath $LogFile }
if ($Force) { Write-log '"Force" switch in enabled - files will be overwritten in the target' -FilePath $LogFile }

if (!(Get-Module $DependModule)) {
    Write-Host "$DependModule module is not installed." -ForegroundColor Yellow
    Install-Module -Name $DependModule -Scope CurrentUser
}

Import-Module $DependModule -ErrorAction Stop

# Set the credentials
if ([string]::IsNullOrEmpty($Username)) {
    Write-Log -Message "Loading credendials from $CredentialFile" -FilePath $LogFile
    # Get credentials from a file
    if (Test-Path $CredentialFile) {
        try {
            $Credential = Import-CliXml -LiteralPath $CredentialFile -ErrorAction Stop
        } catch {
            Write-Log $Error[0].Exception.Message -Category 3
            return
        }
    } else {
        Write-Log "The credential file `"$CredentialFile`" not found." -FilePath $LogFile -Category 3
        return
    }
} else {
    Write-Log -Message 'Using provided login/password as credentials' -FilePath $LogFile
    # Get credentials from input parameters
    $SecPassword = ConvertTo-SecureString $Password -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential($Username, $SecPassword)
}

# Establish the SFTP connection
try {
    $ThisSession = New-SFTPSession -ComputerName $RemoteHost -Credential $Credential -AcceptKey -ErrorAction Stop
} catch {
    Write-Log $Error[0].Exception.Message -FilePath $LogFile -Category 3
    return
}

$SourceFiles = @(Get-SFTPChildItem -SessionId ($ThisSession).SessionId -Path $SourcePath -Recursive | 
    ? {($_.IsDirectory) -or ($_.name -like $Filter)})

Write-Log -Message "$($SourceFiles.Count) item(s) to be copied." -FilePath $LogFile

$CounterOfCopied = 0

foreach ($File in $SourceFiles) {
    Write-Log -Message "Downloading $($File.FullName)" -FilePath $LogFile    
    try {
        # Download file from SFTP
        Get-SFTPItem -SessionId ($ThisSession).SessionId -Path $File.FullName -Destination $TargetPath -Force:$Force -ErrorAction Stop
        $CounterOfCopied++
    } catch {
        Write-Log $Error[0].Exception.Message -FilePath $LogFile -Category 2
    }
}

Write-Log -Message "$CounterOfCopied items(s) are copied." -FilePath $LogFile

#Disconnect all SFTP Sessions
Get-SFTPSession | % { Remove-SFTPSession -SessionId ($_.SessionId) | Out-Null }

Write-Log -Message '+++ Script finished +++' -FilePath $LogFile

#endregion Main
