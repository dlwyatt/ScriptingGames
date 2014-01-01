<#
.SYNOPSIS

.DESCRIPTION

.PARAMETER 

.INPUTS

.OUTPUTS

.EXAMPLE

.EXAMPLE

.EXAMPLE

.EXAMPLE

.EXAMPLE

#>

#requires -Version 4

[CmdletBinding()]
param (
    [switch]
    $ProcessList,

    [switch]
    $ServiceList,

    [switch]
    $SoftwareList,

    [switch]
    $EnviromentVariableList,

    [switch]
    $SharedFolderList,

    [switch]
    $RegistryList,

    [switch]
    $RegistryListAllUsers,

    [switch]
    $FileDetailList,
    
    [ValidateNotNullOrEmpty()]
    [string]
    $OutputDirectory = $PSScriptRoot

)

begin {

    Import-Module .\MikeMod.psm1 -ErrorAction Stop
    
}

process {

    # Do all work generating the objects in functions in the module (not even close to complete, but there's a start)
    # There's probably a better way to do this than a ton of if statements

    If ($ProcessList) {

        $processReport = Get-ProcessReport
    }

    If ($ServiceList) {

        $serviceReport = Get-ServiceReport

    }

    If ($SoftwareList) {

        # Wow6432Node still needs to be accounted for

        $softwareReportUninstall = Get-InstalledSoftwareReportUninstall
        $softwareReportInstaller = Get-InstalledSoftwareReportInstaller

    }

    if ($EnviromentVariableList) {

        $enviromentVariableReport = Get-EnvironmentVariableReport

    }

    if ($SharedFolderList) {

        $sharedFolderReport = Get-SharedFolderReport

    }

    if ($RegistryList) {

        $registryReport = Get-RegistryReport

    }

    if ($RegistryListAllUsers) {

        $registryReportAllUsers = Get-RegistryReportAllUsers

    }

    if ($FolderCountList) {

        $folderCountReport = Get-FolderCountReport

    }

    if ($FileDetailList) {

        $fileDetailReport = Get-FileDetailReport

    }

}

end {

    # Currently this is just displaying some output to the console
    # Eventually the objects will be exported to the shared folder

    # In progress/complete:
    $processReport #| Format-Table -AutoSize #Complete
    $serviceReport #| Format-Table -AutoSize #Complete
    $softwareReportUninstall | Format-Table -AutoSize #Complete (see notes above)
    $softwareReportInstaller | Format-Table -AutoSize #Complete (see notes above)
    $enviromentVariableReport #| Format-Table -AutoSize #Complete
    $sharedFolderReport #| Format-Table -AutoSize #Complete
    $registryReport #| Format-Table -AutoSize #Complete - Add more keys?
    $registryReportAllUsers #| Format-Table -AutoSize #Complete - Add more keys?
    
    # TODO:
    $fileDetailReport
    
    Remove-Module -Name MikeMod       

}