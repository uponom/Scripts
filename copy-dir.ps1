<#
.SYNOPSIS
    Copies recursively from one directory to another
.DESCRIPTION
    <Brief description of script>
.PARAMETER <Parameter_Name>
    <Brief description of parameter input required. Repeat this attribute if required>
.INPUTS
    <Inputs if any, otherwise state None>
.OUTPUTS
    <Outputs if any, otherwise state None - example: Log file stored in C:\Windows\Temp\<name>.log>
.NOTES
    Version:        1.0
    Author:         <Name>
    Creation Date:  <Date>
    Purpose/Change: Initial script development
  
.EXAMPLE
    <Example goes here. Repeat this attribute for more than one example>
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
    [string]$To

    # [string]$SlashChar = '\\',
    # [string]$EndDirChar = '/'

    

)


#region Constants and variables
$PathReplaceFrom = '\'
$PathReplaceTo = '/'

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
                Write-Host $Dest -ForegroundColor Cyan -NoNewline
                if ($i.GetType().Name -eq 'FileInfo') {
                    # Check if file exists
                    # if (Test-Path )
                    # if($PSCmdlet.ShouldProcess($i.FullName, "COPY")) {
                    #     # Copy file
                    #     try {
                    #         # ...
                            Write-Host ' - Ok' -ForegroundColor Green
                    #     } catch {
                    #         Write-Host ' - Error' -ForegroundColor Red
                    #     }
                    # }
                } elseif ($i.GetType().Name -eq 'DirectoryInfo') {
                    # Check if dir exists
                    if (Test-Path $Dest) {
                        Write-Host ' - dir exists' -ForegroundColor DarkGreen
                    } else {
                        # Create dir
                        if($PSCmdlet.ShouldProcess($Dest, "MKDIR")) {
                            try {
                                $dir = New-Item -Path $To -Name $i.Name -ItemType Directory -ErrorAction Stop
                                $dir.CreationTimeUtc = $i.CreationTimeUtc                                
                                # $dir.LastWriteTimeUtc = $i.LastWriteTimeUtc
                                # $dir.LastAccessTimeUtc = $i.LastAccessTimeUtc
                                Write-Host ' - Ok' -ForegroundColor Green
                                Copy-FilesRecursively $i.FullName $Dest $($Depth+1)
                            } catch {
                                Write-Host ' - Error' -ForegroundColor Red
                            }                    
                        }
                    }
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

# 'Collecting directories to copy...'
# $Files = Get-ChildItem -Recurse -Force -LiteralPath $From -Directory -Verbose | 
#     select @{n='FullPath'; e={$_.FullName.Replace($PathReplaceFrom, $PathReplaceTo)}} |
#         select FullPath, @{n='Depth'; e={([regex]::matches($_.FullPath, $PathReplaceTo)).Count}}

# $Files | sort Depth -Descending | ft * -AutoSize 

# foreach ( $f in ($Files | sort Depth -Descending).FullPath ) {
#     $src = $f
#     if ($src[-1] -ne $PathReplaceTo) { $src += $PathReplaceTo}
#     "FROM: $src"
# }

#endregion Main