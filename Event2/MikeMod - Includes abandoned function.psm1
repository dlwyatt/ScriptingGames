function Get-ProcessReport {

    # Get-Process with an additional column for the machine name

    Get-Process | 
        Select @{N='ComputerName';E={$env:COMPUTERNAME}},Name,Handles,NPM,PM,VM,WS,Id

}

function Get-ServiceReport {

    # Get-Service with an additional column for the machine name

    Get-Service | 
        Select @{N='ComputerName';E={$env:COMPUTERNAME}},Name,DisplayName,Status

}

function Get-InstalledSoftwareReportUninstall {

    Push-Location
    Set-Location HKLM:
    Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall | ForEach {

        $details = Get-ItemProperty $_

        $props = [ordered]@{
            ComputerName = $env:COMPUTERNAME
            DisplayName = $details.DisplayName
            DisplayVersion = $details.DisplayVersion
            Publisher = $details.Publisher
        }

        New-Object PsObject -Property $props

    }

    Pop-Location

}

function Get-InstalledSoftwareReportInstaller {

    Push-Location
    Set-Location HKLM:
    Get-ChildItem HKLM:\Software\Classes\Installer\Products | ForEach {

        $details = Get-ItemProperty $_

        $props = [ordered]@{
            ComputerName = $env:COMPUTERNAME
            ProductName = $details.ProductName
            Version = $details.Version
        }

        New-Object PsObject -Property $props

    }

    Pop-Location

}

function Get-InstalledSoftwareReport {

    #ABANDONED - Going with separate functions because I couldn't figure out why the objects were running into each other.....

    # HKLM:\Software\Microsoft\Windows\CurrentVersion\Installer\Products ## This doesn't exist on my system. Found in Classes\Installer\Products
    # HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall
    # HKLM:\Wow6432Node\Software\Microsoft\Windows\CurrentVersion\Installer\Products
    # HKLM:\Wow6432Node\Software\Microsoft\Windows\CurrentVersion\Uninstall

    # HKLM:\Software\Classes\Installer\Products
    
    # Split this out into a new function instead of repeating code
    # Maybe not

    # WTF, this doesn't work and I don't get it...
    # Run either alone and it outputs fine, run them together and the second run's properties just seem to get ignored or something

    <#
    Push-Location
    Set-Location HKLM:
    Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall | ForEach {

        $details = Get-ItemProperty $_

        $props = [ordered]@{
            ComputerName = $env:COMPUTERNAME
            DisplayName = $details.DisplayName
            DisplayVersion = $details.DisplayVersion
            Publisher = $details.Publisher
        }

        New-Object PsObject -Property $props

    }

    Pop-Location

    Push-Location
    Set-Location HKLM:
    Get-ChildItem HKLM:\Software\Classes\Installer\Products | ForEach {

        $details = Get-ItemProperty $_

        $props = [ordered]@{
            ComputerName = $env:COMPUTERNAME
            ProductName = $details.ProductName
            Version = $details.Version
        }

        New-Object PsObject -Property $props

    }

    Pop-Location
    #>

    #Get-InstalledSoftwareReportInstaller
    #Get-InstalledSoftwareReportUninstall

}

function Get-EnvironmentVariableReport {

    # List system environment variables with an additional column for the machine name

    [System.Environment]::GetEnvironmentVariables('Machine').GetEnumerator() | 
        Sort Name |
            Select @{N='ComputerName';E={$env:COMPUTERNAME}},Name,Value

}

function Get-SharedFolderReport {

    # Output of Win32_Share with the PSComputerName property named to match the previous functions

    Get-WmiObject Win32_Share | 
        Select @{N='ComputerName';E={$_.PSComputerName}},Name,Path,Description

}

function Get-RegistryReportHelper {

    param(
    [string]
    $regKeyPath
    )

    try {

        $details = Get-ItemProperty $regKeyPath

        $valueNames = @(($details | Get-Item).Property)

        $out = @()
    
        foreach ($valueName in $valueNames) {
    
            $props = [ordered]@{
                Name = $valueName
                Data = $details.$valueName
                Path = $details.PSParentPath.Replace('Microsoft.PowerShell.Core\Registry::','')
                Key = $details.PSChildName
            }

            $out += New-Object PsObject -Property $props
        }

        $out

    }

    catch {}

}

function Get-RegistryReport {

    #HKLM:\software\Microsoft\Windows\CurrentVersion\Run + RunOnce
    #HKLM:\software

    Get-RegistryReportHelper -regKeyPath 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
    Get-RegistryReportHelper -regKeyPath 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'


}

function Get-RegistryReportAllUsers {
    
    Push-Location
    New-PSDrive HKU Registry HKEY_USERS | Out-Null
    Set-Location HKU:

    $userKeys = Get-ChildItem | Where { ($_.Name).ToString().Length -gt 19 -and (!($_.Name).ToString().Contains('_Classes')) }

    foreach ($userKey in $userKeys) {

        $userSID = New-Object System.Security.Principal.SecurityIdentifier($userKey.Name.Replace('HKEY_USERS\',''))
        $userName = $userSID.Translate([System.Security.Principal.NTAccount])

        $userKeyPath = $userKey.Name.Replace('HKEY_USERS','HKU:')

        Get-RegistryReportHelper -regKeyPath "$userKeyPath\Software\Microsoft\Windows\CurrentVersion\Run" | 
            Select Name,Data,Path,Key,@{N='User';E={$userName}}

        Get-RegistryReportHelper -regKeyPath "$userKeyPath\Software\Microsoft\Windows\CurrentVersion\RunOnce" | 
            Select Name,Data,Path,Key,@{N='User';E={$userName}}

    }

    Pop-Location
    Remove-PSDrive HKU

}

function Generate-MD5Hash {

    param(
    [Parameter(Mandatory, ValueFromPipeline)]
    [string[]]
    $folderPath
    )

    begin {

        $hashList = @()

    }

    process {

        Get-ChildItem $folderPath -File | ForEach {

            $md5 = New-Object System.Security.Cryptography.MD5CryptoServiceProvider
            $hash = [System.BitConverter]::ToString($md5.ComputeHash([System.IO.File]::ReadAllBytes($_.FullName)))
    
            $props = [ordered]@{
                Path = $_.Directory.FullName
                File = $_.Name
                MD5Hash = $hash
            }

            $hashList += New-Object PsObject -Property $props

        }

    }

    end {
    
        $hashList
    
    }

}

function Get-FileDetailReport {

    Get-PSProvider -PSProvider FileSystem | Select -ExpandProperty Drives | ForEach {

        Get-ChildItem $_.Root -File -Recurse | 
            Select Directory,Name,@{N='SizeKB';E={ [System.Math]::Round(($_.Length / 1KB),2) }},LastWriteTime

    } 
    
}

Export-ModuleMember -Function Get-ProcessReport, Get-ServiceReport, Get-InstalledSoftwareReportUninstall, Get-InstalledSoftwareReportInstaller, Get-EnvironmentVariableReport, Get-SharedFolderReport, Get-RegistryReport, Get-RegistryReportAllUsers, Get-FileDetailReport