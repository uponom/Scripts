# Initial params
$DefaultDirectory = 'C:\Program Files\Scripts'
$StoreTranscripts = $true
$TranscriptsDirectoryName = 'transcripts'
$TranscriptsParentDirectory = join-path ([Environment]::GetFolderPath("MyDocuments")) $FolderName

#region Main

# Check if the session is elevated
$IsElevated=$false            
foreach ($sid in [Security.Principal.WindowsIdentity]::GetCurrent().Groups) {            
    if ($sid.Translate([Security.Principal.SecurityIdentifier]).IsWellKnown([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)) { $IsElevated=$true }            
}  

# Make a fancy prompt
function prompt {            
    [Environment]::CurrentDirectory=(Get-Location -PSProvider FileSystem).ProviderPath            
    $host.ui.rawui.windowtitle = "$($env:userdomain)\$($env:username) on $($env:computername)"            
    $path = (Get-Location).path
    $prefix = "PS"             
    #$path = (Get-Location).path -replace '^(.*?[^:]:\\).+(\\.+?)$',('$1'+[char]8230+'$2') -replace '^.+?::' -replace '^(\\\\.+?\\).+(\\.+?)$',('$1'+[char]8230+'$2')            
    #$id = ([int](Get-History -Count 1).Id) + 1            
    #$prefix = "PS <$id> "
    #if ($NestedPromptLevel){$prefix += "($NestedPromptLevel)"}
    if ($env:username -like '_*') { Write-Host '_!_' -BackgroundColor Red -ForegroundColor White -NoNewline }
    if ($isElevated) {
       Write-Host $prefix -BackgroundColor Red -ForegroundColor White -NoNewline
    } else {
       Write-Host $prefix -NoNewline
    }            
    write-host " $path" -foregroundcolor DarkCyan -NonewLine            
    "$('>' * ($nestedPromptLevel + 1)) "           
} 

# Go to default working directory
cd $DefaultDirectory

# Configure a transcript file
if ($StoreTranscripts) {
    if (!(Test-Path $TranscriptsParentDirectory)) { md $TranscriptsParentDirectory }
    $Filename = Join-Path $TranscriptsParentDirectory "PowerShell_transcript.HOME24-1244.$([System.Environment]::ExpandEnvironmentVariables("%USERNAME%")).$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
    Start-Transcript -LiteralPath $Filename
}

#endregion Main