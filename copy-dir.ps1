<#
.SYNOPSIS
    Copies recursively from one directory to another without overwritting existing files of same size.
.DESCRIPTION
    Unlike Copy-Item cmdlet this script won't overwrite files in destination if they are same size with source.
.PARAMETER From
    Source directory
.PARAMETER To
    Destination directory   
.PARAMETER PreserveTime
    Set timestamps of items as at source      
.NOTES
    Version:        1.0
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
    [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='Default')]
    [ValidateNotNullOrEmpty()]
    [Alias("Source")]  
    [string]$From,

    [Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='Default')]
    [ValidateNotNullOrEmpty()]
    [Alias("Destination")]  
    [string]$To,

    [Alias("PreserveCreationTime")]
    [switch]$PreserveTime
)


#region Constants and variables

#endregion Constants and variables


#region Functions

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
        Write-Host $FillDepth -ForegroundColor DarkGray -NoNewline
        Write-Host "$From" -ForegroundColor Yellow -BackgroundColor DarkBlue
    }
    
    process {
        try {
            foreach ($i in (Get-ChildItem -Force -LiteralPath $From -ErrorAction Stop | sort ModeWithoutHardLink)) {
                $Dest = Join-Path $To $i.Name
                Write-Host $FillDepth -ForegroundColor DarkGray -NoNewline
                Write-Host $i.Name -NoNewline -ForegroundColor Blue
                Write-Host ' ==> ' -NoNewline
                Write-Host "$Dest " -ForegroundColor Cyan -NoNewline
                if ($i.GetType().Name -eq 'FileInfo') {
                    # Check if file exists
                    try {
                        if (Test-Path $Dest -ErrorAction Stop) {
                            # File exist, let's check the size
                            if ((Get-Item $Dest -Force -ErrorAction Stop).Length -eq $i.Length) {
                                Write-Host '- file exists (same size)' -ForegroundColor DarkGreen
                                continue
                            } else {
                                Write-Host '- wrong file size, overwritting' -ForegroundColor Yellow
                            }
                        }
                        if($PSCmdlet.ShouldProcess($i.FullName, "COPY")) {
                            # Copy file
                            try {
                                $file = Copy-Item -LiteralPath $i.FullName -Destination $Dest -Force -ErrorAction Stop -PassThru
                                if ($PreserveTime) {
                                    $file.CreationTimeUtc = $i.CreationTimeUtc                                
                                    $file.LastWriteTimeUtc = $i.LastWriteTimeUtc
                                    $file.LastAccessTimeUtc = $i.LastAccessTimeUtc
                                }
                                Write-Host '- Ok' -ForegroundColor Green
                            } catch {
                                Write-Host '- Error' -ForegroundColor Red
                            }
                        }
                    } catch {
                        Write-Host "- $($_.Exception.Message)" -ForegroundColor Red
                    }
                } elseif ($i.GetType().Name -eq 'DirectoryInfo') {
                    # Check if dir exists
                    if (Test-Path $Dest) {
                        Write-Host '- dir exists' -ForegroundColor DarkGreen
                    } else {
                        # Create dir
                        if($PSCmdlet.ShouldProcess($Dest, "MKDIR")) {
                            try {
                                $dir = New-Item -Path $To -Name $i.Name -ItemType Directory -ErrorAction Stop
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
            }
        } catch {
            Write-Host $_.Exception.Message -ForegroundColor Red
        }        
    }
    
    end {
        # ...
    }    
}

#endregion Functions


#region Main

Copy-FilesRecursively $From $To

#endregion Main