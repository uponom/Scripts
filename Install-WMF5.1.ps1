#region Constants
$FilenameW7x32 = '\\home24.lan\share\ressource\install\WMF5.1\W7AndW2008R2\Win7-KB3191566-x86.msu '
$FilenameW7x64 = '\\home24.lan\share\ressource\install\WMF5.1\W7AndW2008R2\Win7AndW2K8R2-KB3191566-x64.msu'
$global:LogFilename = '\\home24.lan\share\ressource\InstallWMF51.csv'
$ErrorActionPreference = 'Stop'
#endregion Constants

#region Functions
function Send-Log ($Msg) {
    $Msg | select   @{n='Timestamp';e={(get-date -format yyyy-MM-dd_HH-mm-ss)}}, `
                    @{n='Computername';e={[System.Environment]::MachineName}}, `
                    @{n='OS';e={[System.Environment]::OSVersion.VersionString}}, `
                    @{n='OSVersion';e={[System.Environment]::OSVersion.Version}}, `
                    @{n='PROCESSOR_ARCHITECTURE';e={$env:PROCESSOR_ARCHITECTURE}}, 
                    @{n='Message';e={$_}} | 
                        ConvertTo-Csv -NoTypeInformation | select -Skip 1 |
                            Out-File -Append -FilePath $global:LogFilename -Encoding default
                        # Export-Csv -path $global:LogFilename -Delimiter ',' -NoTypeInformation -Append -Force
}

function Write-ELog {
    param(
        [string]$Message,
        [string]$LogName = 'Application',
        [string]$Source = 'Group Policy',
        [int]$EventId = 1,
        [string]$EntryType = 'Information'
    )
    Write-EventLog -LogName $LogName -Source $Source -Message "WMF 5.1 Install Script message:`n$Message`n" -EventId $EventId -EntryType $EntryType
    Send-Log $Message
}

function Test-Compatibility {
    $returnValue = $true

    $BuildVersion = [System.Environment]::OSVersion.Version

    if($BuildVersion.Major -ge '10')
    {
        Write-Elog 'WMF 5.1 is not supported for Windows 10 and above.'
        $returnValue = $false
    }

    ## OS is below Windows Vista
    if($BuildVersion.Major -lt '6')
    {
        Write-Elog "WMF 5.1 is not supported on BuildVersion: {0}" -f $BuildVersion.ToString()
        $returnValue = $false
    }

    ## OS is Windows Vista
    if($BuildVersion.Major -eq '6' -and $BuildVersion.Minor -le '0')
    {
        Write-Elog "WMF 5.1 is not supported on BuildVersion: {0}" -f $BuildVersion.ToString()
        $returnValue = $false
    }

    ## Check if WMF 3 is installed
    $wmf3 = Get-WmiObject -Query "select * from Win32_QuickFixEngineering where HotFixID = 'KB2506143'"

    if($wmf3)
    {
        Write-Elog "WMF 5.1 is not supported when WMF 3.0 is installed."
        $returnValue = $false
    }

    # Check if .Net 4.5 or above is installed

    $release = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\' -Name Release -ErrorAction SilentlyContinue -ErrorVariable evRelease).release
    $installed = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\' -Name Install -ErrorAction SilentlyContinue -ErrorVariable evInstalled).install

    if($evRelease -or $evInstalled)
    {
        Write-Elog "WMF 5.1 requires .Net 4.5."
        $returnValue = $false
    }
    elseif (($installed -ne 1) -or ($release -lt 378389))
    {
        Write-Elog "WMF 5.1 requires .Net 4.5."
        $returnValue = $false
    }

    return $returnValue
}
#endregion Functions


if ($PSVersionTable.PSVersion.Major -lt 5) {



    Write-ELog "WMF 5.1 installation script has started..."

    if($env:PROCESSOR_ARCHITECTURE -eq 'x86') {
        $packagePath = $FilenameW7x32
    } else {
        $packagePath = $FilenameW7x64
    }

    if(Test-Path $packagePath) {
        if(Test-Compatibility) {
            $wusaExe = "$env:windir\system32\wusa.exe"
            #$wusaParameters = @("`"$packagePath`"", "/quiet", "/promptrestart")
            $wusaParameters = @("`"$packagePath`"", "/quiet")
            $wusaParameterString = $wusaParameters -join " "
            Write-ELog "Executing:`n $wusaExe $wusaParameterString"
            & $wusaExe $wusaParameterString
        } else {
            Write-ELog "WMF 5.1 cannot be installed as pre-requisites are not met. See Install and Configure WMF 5.1 documentation: https://go.microsoft.com/fwlink/?linkid=839022"
        }
    } else {
        Write-ELog "Expected WMF 5.1 Package: `"$packageName`" was not found."
    }
} else {
    Write-ELog "Powershell v5 (or hight) is already installed. No actions needed."
}

# SIG # Begin signature block
# MIIKzgYJKoZIhvcNAQcCoIIKvzCCCrsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUKuIi1roFQDKxGr7ivDopCk/y
# Um+gggc/MIIHOzCCBiOgAwIBAgIKPjsvgwAAAAABozANBgkqhkiG9w0BAQsFADBK
# MRMwEQYKCZImiZPyLGQBGRYDTEFOMRYwFAYKCZImiZPyLGQBGRYGSE9NRTI0MRsw
# GQYDVQQDExJIT01FMjQtRlBDLURDMDEtQ0EwHhcNMTgwNTI4MDg0MzQwWhcNMjIw
# NjI5MjAxNTIyWjCBkjETMBEGCgmSJomT8ixkARkWA0xBTjEWMBQGCgmSJomT8ixk
# ARkWBkhPTUUyNDEPMA0GA1UECxMGSE9NRTI0MQ0wCwYDVQQLEwR1c2VyMQswCQYD
# VQQLEwJJVDEaMBgGA1UECwwRdGVzdF9IYW5nb3V0c0NoYXQxGjAYBgNVBAMTEVl1
# cmlpIFBvbm9tYXJlbmtvMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# nAnArMW46ndumw8D26xMN0EzqrZfy3jWpGbuErbvo104MFkA0M9B+YRBIBpg9pyc
# jJHbD3gJt+DnL/PJvrlfQqNnBZ+0wamCjpZ3Fyxi4zZohJYR9U9luDxzLHlPTlVP
# kDyCUWK/8BnjYI2F+PkICl439hLKIgJFNtgWjiqoqkkHcal5pmDHExvnPYN236e/
# rLNy5QG4fMCeJVAMBEMxK3yqHVKHUabGuqoleXS+D0ZeENJjBv+dtwM69+IaOgbx
# H9rsNg2NFIeqBSRPedZlEO4J6HHyOMEMZaOoJ7SalJzd6glX3TVyZg3oQ5kA9mKg
# 17dG21qSzXbDZLQebzTpupyfF4cJzfgtuF5HKGJI+h1YUmxUkb88kzD4xq4p+6Ac
# FMQCRNBdjNQ3epabsH6Y1/YYhYaKFQ7FHsjHpCLXcJK5IsL+Sdeos2JBToSCPS57
# oY6SGLzoCgW+5a+3fL1ltjdwgQOeY+pOAavDMhdA1XD6gx98r0jttY4kQGkQb0FG
# vtxOir+byCW8ylasybN81m6FlfrTjCtcTJk0hHVDXyAnKwitLwVubk4igzh3gdY+
# Oe4qaOXu27crd8gHpBShl82OxGlT8dSA3+CG4r39iVBN2SfDYxUQ4CgvH/yTr5pq
# 8QsfmmrODYQQ4NeZ93mUExvhA5vgZGfh7E+Ac5JYT5ECAwEAAaOCAtgwggLUMD0G
# CSsGAQQBgjcVBwQwMC4GJisGAQQBgjcVCIKe4wCE4OtDhbGPLoLe9wOFkbFkgSCr
# +ACHtK9ZAgFkAgEDMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIH
# gDAbBgkrBgEEAYI3FQoEDjAMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBR+J9qFfyQ6
# OUAFeor4elWZLMMrgjAfBgNVHSMEGDAWgBT5txsgAMNmojURI9R4BRyOej9UNzCC
# AREGA1UdHwSCAQgwggEEMIIBAKCB/aCB+oaBuWxkYXA6Ly8vQ049SE9NRTI0LUZQ
# Qy1EQzAxLUNBLENOPUZQQy1EQzAxLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBT
# ZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPUhPTUUyNCxE
# Qz1MQU4/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNz
# PWNSTERpc3RyaWJ1dGlvblBvaW50hjxodHRwOi8vZnBjLWRjMDEuaG9tZTI0Lmxh
# bi9DZXJ0RW5yb2xsL0hPTUUyNC1GUEMtREMwMS1DQS5jcmwwgcMGCCsGAQUFBwEB
# BIG2MIGzMIGwBggrBgEFBQcwAoaBo2xkYXA6Ly8vQ049SE9NRTI0LUZQQy1EQzAx
# LUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNl
# cyxDTj1Db25maWd1cmF0aW9uLERDPUhPTUUyNCxEQz1MQU4/Y0FDZXJ0aWZpY2F0
# ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwNgYDVR0R
# BC8wLaArBgorBgEEAYI3FAIDoB0MG3l1cmlpLnBvbm9tYXJlbmtvQGhvbWUyNC5k
# ZTANBgkqhkiG9w0BAQsFAAOCAQEAKjUiMzO4ZMECYjavWwPk8Conw0Ye9Jbex/yD
# qFtIUllpRpArN505Mvj3qVrkz8F6bpKVzCa4vmqFR7G9wmtsWnIK+OOcXtdVGr+0
# J7/ZD2pMZUVoGgHIiw3MCli48vbNTjHpKuLGjyFEtlKvbWWQyB6pRpZ0ZF4MES71
# lh+TMhvA7D1KKf2+cXlrd1Y5qqjtCMgYkhT/dheHkVJ8+tesnHkRA6BAmZpTmaYv
# exMFlE6PY5YGYcbVgqDE+ZzOz34YLlDjJ6at7FygfSADt8i3zYtvs87YeXBB+yHK
# 3dU67MUsllvJzfKIEBVGK39a8ULjZeJf92FKSjKuTyERPnSo3TGCAvkwggL1AgEB
# MFgwSjETMBEGCgmSJomT8ixkARkWA0xBTjEWMBQGCgmSJomT8ixkARkWBkhPTUUy
# NDEbMBkGA1UEAxMSSE9NRTI0LUZQQy1EQzAxLUNBAgo+Oy+DAAAAAAGjMAkGBSsO
# AwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEM
# BgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqG
# SIb3DQEJBDEWBBT1sSM0IxChbFxyh9XGL2fwFMtgHTANBgkqhkiG9w0BAQEFAASC
# AgAKnJu/v0GCjI6SEqwwLonOCSdhLIlaWBX0khUAyj1cqWXYbcdnCBCCTAGMKMMy
# Y9XdmAPm6TEs4cMIYQrlNYgReyr8KQY96V0uqLpcbYw651OHw0Fg0a8luCCAbYOa
# pMjjxVJjj4b3Yh4i6IFGwtxJ+Z3GINk2Cfah2A1hLH16eDymjL5F6AwSFhCkrGIg
# Rz2UMVSHd3iQ/7yfLDqCOuRI4S5n+FkSpkWDubfRm1OKmEaFzAVV4TjMKnfbzv2v
# MlptDE/cP51YVjiNFW2hWC1WdMlNjAXhRFD0lb4T7ajDn+aAuOrh/KaEC6cj3f8N
# zQ/0su6aOvBlFK+dfdkRBUJ2knKpX8ucSC+9g2QhQixCe/DAXEvNuABog75eZY8p
# YPqEoDDTgSEzhKcnnlpIP/eqyed/pNPenQT007yx8FhxF02FROA4wgvrSnWn+i7D
# y0X0agAHqVY5mvnBUjTVAM6wwCemWjBNrec4mcrxZw9WBGNQGU4/pYw/dnRJhVL/
# p91TffSCAB8Roj/gT5+RBSEnNJJ6MPD4JX22OVC9dmagf99cmcaSS//yixt2uafC
# /bV/LUm14InlGjKPpJ1YivuM1mlwJh8MXjYnTBt1qqaaPmr38XQeGaRpu97qqgqZ
# qGzB4EcDxUnudQt0TYw+xBBn7CDU0TdY8E6MOZZNIpfeHw==
# SIG # End signature block
