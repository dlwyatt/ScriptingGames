<#
.Synopsis
   Creates department's folder structure.
.DESCRIPTION
   Creates folders for a department and sets their Access permissions according to a predetermined strategy 
.PARAMETER Path
   The folder where the Finance directory and its contents are to be created.  The folder specified by Path must already exist.  Defaults to the current directory.
.PARAMETER CsvDirectory
   The folder where the script's CSV output file should be created.  The folder specified by CsvDirectory must already exist.  Defaults to the current directory.
.PARAMETER Domain
   The NetBIOS name of the domain where the department's groups are found.  Can also be set to the local computer name, to use local groups.  Defaults to the same domain that authenticated the user who executes the script.
.EXAMPLE
   .\CreateFinanceDepartmentFolders.ps1

   Creates the folder structure and CSV file in the default location (current file system directory.)  Looks for groups in the same domain as the user executing the script.
.EXAMPLE
   .\CreateFinanceDepartmentFolders.ps1 -Path '\\Server\Share\Departments\' -CsvDirectory 'C:\DepartmentReports\' -Domain 'SOMEDOMAIN'

   Creates the folder structure in the \\Server\Share\Departments\ directory, creates the CSV file in C:\DepartmentReports\ , and looks for the department groups in the SOMEDOMAIN domain.
.INPUTS
   None
.OUTPUTS
   None
#>

#requires -Version 4.0
#requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param (
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if (-not (Test-Path -LiteralPath $_ -PathType Container))
        {
            throw "Path '$_' does not exist."
        }

        $pathInfo = Resolve-Path -LiteralPath $_

        if ($pathInfo.Provider.Name -ne 'FileSystem')
        {
            throw "Path '$_' refers to a location that is not on the file system."
        }

        return $true
    })]
    [string]
    $Path = (Get-Location -PSProvider FileSystem).Path,

    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if (-not (Test-Path -LiteralPath $_ -PathType Container))
        {
            throw "CsvDirectory '$_' does not exist."
        }

        $pathInfo = Resolve-Path -LiteralPath $_

        if ($pathInfo.Provider.Name -ne 'FileSystem')
        {
            throw "CsvDirectory '$_' refers to a location that is not on the file system."
        }

        return $true
    })]
    [string]
    $CsvDirectory = (Get-Location -PSProvider FileSystem).Path,

    [ValidateNotNullOrEmpty()]
    [string]
    $Domain = $env:USERDOMAIN
)

# SupportsShouldProcess is defined here just to allow users to pass in Confirm or WhatIf; the module
# functions that support those switches (New-FolderStructure) will behave accordingly, as will
# Export-Csv.

Import-Module -Name $PSScriptRoot\Event3.psm1 -ErrorAction Stop -Verbose:$false

#region Hard-coded Finance group details

$department = 'Finance'

$teams = @(
    'Receipts',
    'Payments',
    'Accounting',
    'Auditing'
)

$bigBrother = @(
    'Auditing'
)

#endregion

# Test-DapartmentGroups and New-DepartmentStructureInfo are aware of the scheme of folders and permissions currently used in this event.
# Their job is to make sure all of the necessary groups exist, and to return custom objects describing the Path and Permissions required
# for each directory in the tree (in properties called Path and SecurityDescriptor; SecurityDescriptor will be a DirectorySecurity object.)

Test-DepartmentGroups -Department $department -Teams $teams -AdditionalGroups $bigBrother -Domain $domain -ErrorAction Stop
$directoryInfo = New-DepartmentStructureInfo -Path $Path -Department $department -Domain $domain -Teams $teams -AuditorGroups $bigBrother

# New-FolderStructure is a more generic function that can accept any objects with the properties Path and SecurityDescriptor (where
# SecurityDescriptor is a DirectorySecurity object.)  For future departments that may not use quite the same scheme as Finance, their
# creation scripts can generating the objects to pipe to New-FolderStructure differently.

$directoryInfo | New-FolderStructure

#region Save report of created folders and permissions

$props = @(
    'Path',
    @{ Name = 'Sddl'; Expression = { $_.SecurityDescriptor.GetSecurityDescriptorSddlForm('Access') } }
)

$csvPath = "Create$department-$(Get-Date -Format yyyy_MM_dd).csv"
$csvPath = Join-Path -Path $CsvDirectory -ChildPath $csvPath

$directoryInfo |
Select-Object -Property $props |
Export-Csv -LiteralPath $csvPath

#endregion
