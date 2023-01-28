<#
    .SYNOPSIS
    Screw v.0.6

    .DESCRIPTION
    "SCREW" is library of various useful functions
    Written by Yuriy Ponomarenko (except a explicit specified code of other authors)

    What's new:
    v0.6 (2020-10-19)
        + The function Write-Log was added
    v0.5 (2017-11-21)
        + The function Repair-WebRequestResult was added
    v0.4 (2017-10-03)
        + The function Get-ChildItemWithSize was added

    ToDo:
    * Archive-GPO
        * Automatic search RAR.EXE throu PATH environment.
        * Add native ZIP format support

#> 


#region === File system tools ===

function Create-DummyFile {
    <#
        .Synopsis
           Creates a dummy file

        .DESCRIPTION
           Creates a dummy file of defined size. Returns $true if file is created and no error occured.

        .OUTPUT System.Boolean

        .EXAMPLE
           Create-DummyFile -Path 'c:\temp\fillspace.tmp' -Size 2GB
    #>
    param(
        [Parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Mandatory = $True,
                   Position=0)]
        [ValidateNotNullOrEmpty()]        
        [string]$Path,        
        [Parameter(ValueFromPipelineByPropertyName=$true,
                   Mandatory = $True, 
                   Position=1)]
        [int64]$Size
    )
    $Result = $false
    try {
        $file = [io.file]::Create($Path)
        $Result = $true
    } catch {
        Write-Error $Error[0].Exception.Message              
    }
    if ($Result) {
        try {
            $file.SetLength($Size)
            $Result = $true
        } catch {
            $Result = $false
            Write-Error $Error[0].Exception.Message
        } finally { 
            $file.Close()
        }
    }
    if (!$Result) { Remove-Item -LiteralPath $Path -ErrorAction SilentlyContinue }
    return $Result
}


function Create-TempDirectory {
    <#
        .Synopsis
           Creates temporary directory

        .DESCRIPTION
           Creates a uniquely named directory in temporary directory path and returns System.IO.DirectoryInfo object of that directory

        .EXAMPLE
           Create-TempDirectory
    #>
    param(
        [switch]$WhatIf
    )
    do {
        $TempDir = Join-Path -path ([System.IO.Path]::GetTempPath()) -childPath ([System.IO.Path]::GetRandomFileName())
    } while (Test-Path $TempDir)
    Write-Verbose "Trying to create directory $TempDir ..."
    New-Item -ItemType 'Directory' -path $TempDir -ErrorAction Stop -WhatIf:$($WhatIf -or $WhatIfPreference)
}


function Get-ChildItemWithSize {
    <#
        .Synopsis
           Output child items for file system with calculated Size for directories.

        .DESCRIPTION
           Output child items for file system like Get-ChildItem and add new property "Size". So you get size for directories.

        .EXAMPLE
           Get-ChildItemWithSize c:\temp
    #>
    param(
        [Parameter(Mandatory=$true, 
                   Position=0)]
        [string]$Path
    )
    Get-ChildItem $Path -Directory | Select *, @{ n="Size"; e={ (New-Object -com  Scripting.FileSystemObject).GetFolder($_.FullName).Size } }
    Get-ChildItem $Path -File | Select *, @{ n="Size"; e={ $_.Length } }
    #Get-ChildItem $Path | Select *, @{ n="Size"; e={ if($_.PSIsContainer -eq $True) {(New-Object -com  Scripting.FileSystemObject).GetFolder($_.FullName).Size} else {$_.Length} } }
}

#endregion === File system tools ===


#region === Active Directory tools ===

function Archive-GPO {
    <#
        .Synopsis
           Achives domain's GPOs

        .DESCRIPTION
           Creates RAR achive of all Group Policy Objects of specified Active Directory Domain(s)

        .EXAMPLE
           Archive-GPO -Domain contoso.com,adatum.com,fabrikam.com -Path c:\tmp\AllGPOBackup.rar 
           Will be created archive file c:\tmp\AllGPOBackup.rar which contains backup of all group policy objects of domains "contoso.com", "adatum.com" and "fabrikam.com".

        .OUTPUT System.String
        .OUTPUTS
           Returns archive file name

        .NOTES
           You must have appropriate permissions to read GPOs in domains.
           In a earlier versions of module function called "Archive-GPO"
    #>
    [CmdletBinding()]
    [Alias()]
    [OutputType([String])]
    Param(
        # Domain name. If ommited - current domain will be used.
        [Parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$Domain,

        # File name of archive file. If ommited - the archive file be created in temporary directory with random file name.
        [Parameter(ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [string]$Path,
        [string]$RARPath,
        [string[]]$RARExtraParams,
        [switch]$WhatIf
    )
    Begin {
        if ([string]::IsNullOrEmpty($Domain)) { $Domain = (Get-ADDomain).DNSRoot }
        Write-Debug "Group Policy Objects Source Domain: $Domain"
        if (!($WhatIf -or $WhatIfPreference)) { $TempBasePath = Create-TempDirectory }
        $TempPath = New-Item -ItemType 'Directory' -Path (Join-Path -Path $TempBasePath.FullName -ChildPath $Domain) -WhatIf:$($WhatIf -or $WhatIfPreference)
        Write-Debug "Temporary directory: $TempPath"
    }
    Process {
        Backup-GPO -all -Domain $Domain -Path $TempPath -WhatIf:$($WhatIf -or $WhatIfPreference) | %{Write-Verbose "$($_.DomainName)`t$($_.DisplayName)`t$($_.Id)"}
    }
    End {
        if ([string]::IsNullOrEmpty($RARPath)) { $RARPath =  'C:\Program Files\WinRAR\Rar.exe'} # (join-path $env:SystemRoot 'system32\cmd.exe') '/c rar.exe'
        $RARParams = @('m', '-s', '-r', '-ep1', "-w$([System.IO.Path]::GetTempPath())")
        $RARParams = $RARParams + $RARExtraParams + @($Path, (Join-Path -Path $TempBasePath -ChildPath '*'))
        Write-Debug "RAR command line: $RARPath $RARParams"
        if ([string]::IsNullOrEmpty($Path)) { 
            $Path = [System.IO.Path]::GetTempFileName() 
            Remove-Item $Path -Confirm:$false
        }
        Write-Debug "Output archive file name: $Path"
        if (!($WhatIf -or $WhatIfPreference)) { (& $RARPath $RARParams) | %{Write-Debug "$_"} }
        Remove-Item $TempBasePath -Recurse -Force -Confirm:$false -WhatIf:$($WhatIf -or $WhatIfPreference)
        return $Path
    }
}


#endregion === Active Directory tools ===

 
#region === String tools ===

function Out-ReverseString {
    <#
        .SYNOPSIS
            Reverses a string

        .DESCRIPTION
            Reverses a string
        
        .PARAMETER String
            String input that will be reversed

        .NOTES
            Author: Boe Prox
            Date Created: 12August2012
            URL: https://learn-powershell.net/2012/08/12/reversing-a-string-using-powershell/

        .OUTPUT System.String

        .EXAMPLE
            Out-ReverseString -String "This is a test of a string!"
            !gnirts a fo tset a si sihT

            Description
            -----------
            Reverses a string input.

        .EXAMPLE
            [string[]]$Strings = "Simple string","Another string","1 2 3 4 5 6"
            $Strings | Out-ReverseString

            gnirts elpmiS
            gnirts rehtonA
            6 5 4 3 2 1

            Description
            -----------
            Takes a collection of strings and reverses each string.
    #>
    [cmdletbinding()]
    Param (
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string[]]$String
    )
    Process {
        ForEach ($Item in $String) {
            ([regex]::Matches($Item,'.','RightToLeft') | ForEach {$_.value}) -join ''
        }
    }
}


function Repair-WebRequestResult {
    <#
        .SYNOPSIS
            Repairs incorrent Content returned by Invoke-WebRequest cmdlet

        .DESCRIPTION
            Function corrects Invoke-RestMethod and Invoke-WebRequest Encoding bug. 
            Mistakenly convert THE! utf8("false ISO-8859-1") source string to utf8.
            (See details: https://windowsserver.uservoice.com/forums/301869-powershell/suggestions/13685217-invoke-restmethod-and-invoke-webrequest-encoding-b)
                    
        .PARAMETER Content
            String to be repaired to correct UTF8 encoding.

        .NOTES
            Author: chuanjiao10
            URL: Source: https://github.com/PowerShell/PowerShell/issues/3126

        .OUTPUT System.String
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$Content
    )
    Process {
        $utf8 = [System.Text.Encoding]::GetEncoding(65001)
        $iso88591 = [System.Text.Encoding]::GetEncoding(28591) #ISO 8859-1 ,Latin-1

        $wrong_bytes = $utf8.GetBytes($Content)

        $right_bytes = [System.Text.Encoding]::Convert($utf8,$iso88591,$wrong_bytes) #Look carefully
        $utf8.GetString($right_bytes) #Look carefully
    }
}

#endregion === String tools ===


#region === Log tools ===

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
            Default value implements ISO 8601 standard: %Y-%m-%dT%H:%M:%S%Z

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
        [string]$TimestampFormat = '%Y-%m-%dT%H:%M:%S%Z',
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
    if (!$NoLogFile -and ![string]::IsNullOrEmpty($FilePath)) { "$TSStr $Message" | Out-File -LiteralPath $FilePath -Encoding $Encoding -Append -Force }
    if ($Category -ge 100) { exit }
}

#endregion === Log tools ===


Export-ModuleMember -Function *