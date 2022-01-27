<#
.SYNOPSIS
    Copies recursively from one directory to another without overwritting existing files of same size.
.DESCRIPTION
    Unlike Copy-Item cmdlet this script won't overwrite files in destination if they are same size with source. Also it can preserve file timestamps ("PreserveTime" parameter).
.PARAMETER From
    Source directory.
.PARAMETER To
    Destination directory.   
.PARAMETER PreserveTime
    Set timestamps of items as at source.      
.PARAMETER DontShowSize
    Do not show size of a file to be copied.   
.PARAMETER DontShowTotalSize
    Do not show the total copied volume.   
.PARAMETER DontSnowTotalTime
    Do not show the total time spent.   
.PARAMETER DontShowTotalSpeed
    Do not show the average copy speed.   
.PARAMETER ProgressBar
    Show progress bar. (It may slow down the copying process!)
.PARAMETER ProgressBarDepth
    Limit nested progress bars. Default value is 3.    
.NOTES
    Version:        1.4
    Author:         Yurii Ponomarenko
.EXAMPLE
    Copy-Dir -From c:\source_directory -To d:\destination_directory
#>

[cmdletbinding(
    SupportsShouldProcess
    #DefaultParameterSetName='Default'
)]

##Requires -Version <N>[.<n>]
##Requires -PSSnapin <PSSnapin-Name> [-Version <N>[.<n>]]
##Requires -Modules { <Module-Name> | <Hashtable> }
##Requires -PSEdition <PSEdition-Name>
##Requires -ShellId <ShellId> -PSSnapin <PSSnapin-Name> [-Version <N>[.<n>]]
##Requires -RunAsAdministrator
##Requires -Assembly path\to\foo.dll

param(
    [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [ValidateNotNullOrEmpty()]
    [Alias("Source")]  
    [string]$From,

    [Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [ValidateNotNullOrEmpty()]
    [Alias("Destination")]  
    [string]$To,

    [switch]$PreserveTime,

    [switch]$DontShowSize,
    [switch]$DontShowTotalSize,
    [switch]$DontSnowTotalTime,
    [switch]$DontShowTotalSpeed,
    [switch]$ProgressBar,
    [int]$ProgressBarDepth = 2,

    [ValidateSet('Classic', 'Minimal')]
    [string]$ProgressBarStyle = 'Classic'
)


#region Constants and variables

[int64]$global:TotalSize = 0
[int64]$global:TotalItemsProcessed = 0
[int64]$global:TotalFilesCopied = 0
[int64]$global:TotalDirsCreated = 0
[int64]$global:TotalDirsProcessed = 0
[int64]$global:TotalFilesProcessed = 0

#endregion Constants and variables


#region Functions

Function ConvertTo-PrettyCapacity {
    Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True
            )
        ]
    [Int64]$Bytes,
    [Int64]$RoundTo = 1
    )
    If ($Bytes -Gt 0) {
        $Base = 1024
        $Labels = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
        $Order = [Math]::Floor( [Math]::Log($Bytes, $Base) )
        $Rounded = [Math]::Round($Bytes/( [Math]::Pow($Base, $Order) ), $RoundTo)
        [String]($Rounded) + $Labels[$Order]
    }
    Else {
        "0"
    }
    Return
}

function ShowProgressBar {
    param (
        [string]$Name,
        [int]$Depth = 0,
        [int64]$TotalItems,
        [int64]$ItemsProcessed
    )
    if ($ProgressBar -and $Depth -lt $ProgressBarDepth) {
        $percentProcessed = [int]($ItemsProcessed*100/$TotalItems)
        Write-Progress -Id $Depth -Activity $Name -PercentComplete $percentProcessed #-Status "$percentProcessed%"
    }            
}

function Copy-FilesRecursively {
    <#
        .SYNOPSIS
            ...
        .DESCRIPTION
            ...
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [string]$From,
        [string]$To,
        [int]$Depth = 0
    )

    begin {
        $FillDepth = '>'*$Depth
        Write-Host $FillDepth -ForegroundColor Gray -NoNewline
        Write-Host "$From" -ForegroundColor Yellow
    }
    
    process {
        [int64]$ItemsProcessed = 0
        try {
            $Items = @(Get-ChildItem -Force -LiteralPath $From -ErrorAction Stop | Sort-Object Mode, Name)
            foreach ($i in $Items) {
                $global:TotalItemsProcessed++
                ShowProgressBar $i.Name $Depth $Items.Count $ItemsProcessed
                $Dest = Join-Path $To $i.Name
                Write-Host $FillDepth -ForegroundColor Gray -NoNewline
                Write-Host $i.Name -NoNewline -ForegroundColor Blue
                Write-Host ' ==> ' -NoNewline
                Write-Host "$Dest " -ForegroundColor Cyan -NoNewline
                if ($i.GetType().Name -eq 'FileInfo') {
                    $global:TotalFilesProcessed++
                    # Check if file exists
                    try {
                        if (Test-Path -LiteralPath $Dest -ErrorAction Stop) {
                            # File exist, let's check the size
                            if ((Get-Item $Dest -Force -ErrorAction Stop).Length -eq $i.Length) {
                                Write-Host '- file exists (same size)' -ForegroundColor DarkGreen
                                continue
                            } else {
                                Write-Host '- wrong file size, overwritting' -ForegroundColor Yellow -NoNewline
                            }
                        }
                        if($PSCmdlet.ShouldProcess($i.FullName, "COPY")) {
                            # Copy file
                            try {
                                if (!$DontShowSize) { Write-Host "($(ConvertTo-PrettyCapacity $i.Length)) " -NoNewline }                               
                                $file = Copy-Item -LiteralPath $i.FullName -Destination $Dest -Force -ErrorAction Stop -PassThru
                                $global:TotalSize += $i.Length
                                $global:TotalFilesCopied++
                                if ($PreserveTime) {
                                    $file.CreationTimeUtc = $i.CreationTimeUtc                                
                                    $file.LastWriteTimeUtc = $i.LastWriteTimeUtc
                                    $file.LastAccessTimeUtc = $i.LastAccessTimeUtc
                                }
                                Write-Host '- Ok' -ForegroundColor Green -NoNewline
                                if (!$DontShowTotalSize) { Write-Host " $(ConvertTo-PrettyCapacity $global:TotalSize)" -ForegroundColor Blue -NoNewline }
                                $TotalTime = (Get-Date).Subtract($StartTimestamp)
                                if (!$DontSnowTotalTime) { Write-Host " $($TotalTime.ToString("hh\:mm\:ss"))" -ForegroundColor Blue -NoNewline }
                                if (!$DontShowTotalSpeed) { Write-Host " ($( ConvertTo-PrettyCapacity ($global:TotalSize/$TotalTime.TotalSeconds) )/s)" -ForegroundColor Blue -NoNewline }
                                Write-Host
                            } catch {
                                Write-Host "- $($_.Exception.Message)" -ForegroundColor Red
                            }
                        }
                    } catch {
                        Write-Host "- $($_.Exception.Message)" -ForegroundColor Red
                    }
                } elseif ($i.GetType().Name -eq 'DirectoryInfo') {
                    $global:TotalDirsProcessed++
                    # Check if dir exists
                    if (Test-Path -LiteralPath $Dest) {
                        Write-Host '- dir exists' -ForegroundColor DarkGreen
                    } else {
                        # Create dir
                        if($PSCmdlet.ShouldProcess($Dest, "MKDIR")) {
                            try {
                                $dir = New-Item -Path (Join-path $To $i.Name) -ItemType Directory -ErrorAction Stop -Force
                                # $dir = New-Item -Path $To -Name $i.Name -ItemType Directory -ErrorAction Stop # doesn't work with names with '[]' inside
                                if ($null -eq $dir) {throw 'Directory is not created'}
                                $global:TotalDirsCreated++
                                if ($PreserveTime) {
                                    $dir.CreationTimeUtc = $i.CreationTimeUtc                                
                                    $dir.LastWriteTimeUtc = $i.LastWriteTimeUtc
                                    $dir.LastAccessTimeUtc = $i.LastAccessTimeUtc
                                }
                                Write-Host '- Created' -ForegroundColor Green
                            } catch {
                                Write-Host "- $($_.Exception.Message)" -ForegroundColor Red
                            }                    
                        }
                    }
                    Copy-FilesRecursively $i.FullName $Dest $($Depth+1)
                }
                $ItemsProcessed++
                ShowProgressBar $i.Name $Depth $Items.Count $ItemsProcessed
            }
        } catch {
            Write-Host $_.Exception.Message -ForegroundColor Red
        }        
    }
    
    end {
        if ($ProgressBar) { Write-Progress -Id $Depth -Completed -Activity $From }
    }    
}

#endregion Functions


#region Main

$StartTimestamp = Get-Date
Write-Host "Started: $StartTimestamp"
$PBarSavedView = $PSStyle.Progress.View
$PSStyle.Progress.View = $ProgressBarStyle
Copy-FilesRecursively $From $To
$PSStyle.Progress.View = $PBarSavedView
$TimeNow = Get-Date
Write-Host "Finished: $TimeNow"
$TotalTime = $TimeNow.Subtract($StartTimestamp)
Write-Host "Time spent:      $( $TotalTime.ToString("hh\:mm\:ss") )" -ForegroundColor Cyan
Write-Host "Items processed: $global:TotalItemsProcessed" -ForegroundColor Cyan
Write-Host "Dirs processed   $global:TotalDirsProcessed" -ForegroundColor Cyan
Write-Host "Dirs created:    $global:TotalDirsCreated" -ForegroundColor Cyan
Write-Host "Files processed: $global:TotalFilesProcessed" -ForegroundColor Cyan
Write-Host "Copied:          $( ConvertTo-PrettyCapacity $global:TotalSize ) in $global:TotalFilesCopied files" -ForegroundColor Cyan
if (($global:TotalSize/$TotalTime.TotalSeconds) -ne 0) { Write-Host "Copy speed:      $( ConvertTo-PrettyCapacity ($global:TotalSize/$TotalTime.TotalSeconds) )/s" -ForegroundColor Cyan }
if ($global:TotalFilesCopied -ne 0) { Write-Host "Aver. file size: $( ConvertTo-PrettyCapacity ($global:TotalSize/$global:TotalFilesCopied))" -ForegroundColor Cyan }
#endregion Main