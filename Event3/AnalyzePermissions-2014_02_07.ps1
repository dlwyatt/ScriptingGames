<#
.Synopsis
   Analyzes or repairs a folder structure's Access permissions.
.DESCRIPTION
   Based on a CSV file, analyzes or repairs a folder structure's permissions.  The CSV file should contain two columns:  Path and Sddl (Where Sddl is a string in Security Descriptor Definition Language format).
   The SDDL strings are examined for two pieces of information:  Are inherited access rules being blocked at this Path, and what are any explicit ACEs defined at this Path?  This means that any "wrong" permissions
   that are being inherited from a parent folder are considered to be "correct" from the point of view of child directory.
.PARAMETER Path
   The top level folder of the directory tree that is to be checked.  For example:  '\\Server\share\Departments\Finance'
.PARAMETER CsvPath
   Path to the CSV file which contains path and permissions information about the folder structure being examined.
.PARAMETER OutputDirectory
   If only analyzing permissions, this parameter determines the folder where the resulting HTML report will be created.  The report will be named according to the last folder in the Path parameter, followed by today's date.  For example:  Finance-yyyy_MM_dd.html
.PARAMETER FixPermissions
   Switch parameter that causes the script to repair any incorrect permissions detected in the folder tree, instead of creating a report.
   Use the -Verbose switch to see which folders or files were fixed.
.EXAMPLE
   .\AnalyzePermissions.ps1 -Path '\\Server\share\Departments\Finance' -CsvPath 'C:\DepartmentReports\CreateFinance-yyyy_MM_dd.csv' -OutputDirectory 'C:\DepartmentReports'

   Analyzes the current permissions of '\\Server\share\Departments\Finance' according to the CSV file that was generated when the structure was first created. Creates a dated HTML report in C:\DepartmentReports.
.EXAMPLE
   .\AnalyzePermissions.ps1 -Path '\\Server\share\Departments\Finance' -CsvPath 'C:\DepartmentReports\CreateFinance-yyyy_MM_dd.csv' -FixPermissions -Verbose

   Uses the same folder target and CSV file as Example 1, but this example corrects any incorrect permissions and displays the paths of those files or folders to the console via the Verbose stream.
.NOTES
   The HTML report currently represents the Expected and Actual permissions as strings in SDDL format.  This is not the most user-friendly choice, but it is compact, and more importantly, complete.  (AccessToString was an alternative, but that doesn't include any information about inheritance / propagation flags on each ACE.)
.INPUTS
   None.
.OUTPUTS
   None.
#>

#requires -Version 4.0
#requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'ReportOnly')]
param (
    [Parameter(Mandatory)]
    [string]
    $Path,

    [Parameter(Mandatory)]
    [string]
    $CsvPath,

    [Parameter(Mandatory, ParameterSetName = 'ReportOnly')]
    [ValidateScript({
        if (-not (Test-Path -LiteralPath $_ -PathType Container))
        {
            throw "OutputDirectory '$_' does not exist."
        }

        $pathInfo = Resolve-Path -LiteralPath $_

        if ($pathInfo.Provider.Name -ne 'FileSystem')
        {
            throw "OutputDirectory '$_' refers to a location that is not on the file system."
        }

        return $true
    })]
    [string]
    $OutputDirectory,

    [Parameter(ParameterSetName = 'FixPermissions')]
    [switch]
    $FixPermissions
)

# SupportsShouldProcess is defined here just to allow users to pass in Confirm or WhatIf; the module
# functions that support those switches (Repair-DirectoryTreePermission and its helpers) will behave
# accordingly, as will Out-File

function Import-PermissionsFile
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $CsvPath
    )

    $hashTable = @{}

    try
    {
        $csvData = Import-Csv -LiteralPath $CsvPath -ErrorAction Stop
    }
    catch
    {
        $exception = Get-InnerException -ErrorRecord $_
        throw "Error importing CSV file '$CsvPath': $($exception.Message)"
    }

    foreach ($entry in $csvData)
    {
        if ([string]::IsNullOrEmpty($entry.Path) -or [string]::IsNullOrEmpty($entry.Sddl))
        {
            throw "CSV file '$CsvPath' contains invalid data."
        }
    
        if (-not (Test-Path -LiteralPath $entry.Path -PathType Container))
        {
            Write-Warning "CSV file '$CsvPath' contains an entry for directory '$($entry.Path)', which was not found on the file system."
        }

        $dirSec = New-Object System.Security.AccessControl.DirectorySecurity

        try
        {
            $dirSec.SetSecurityDescriptorSddlForm($entry.Sddl)
        }
        catch
        {
            throw "CSV file '$CsvPath' contains an invalid SDDL string for directory '$($entry.Path)': $($entry.Sddl)"
        }

        $hashTable[$entry.Path.TrimEnd('\')] = $dirSec
    }

    return $hashTable
}

function ConvertTo-PermissionReport
{
    #
    # Accepts objects from the Test-DirectoryTreePermission function (which contain properties called
    # Path, ExpectedPermissions, CurrentPermissions, and Correct), and uses them to create a dynamic
    # HTML table report using the EnhancedHTML2 module.
    #
    # The Path argument to this function is only used to generate titles / headers in the HTML page.
    #

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Path,

        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]
        $InputObject
    )

    begin
    {
        $list = New-Object System.Collections.ArrayList

        # I'm rubbish at coming up with anything visually pleasing, so this CSS code is straight
        # out of "Creating HTML Reports With PowerShell" by Don Jones.  Much of the HTML creation
        # code comes from the book, as well.

        $style = @"
<style>
body {
    color:#333333;
    font-family:Calibri,Tahoma;
    font-size: 10pt;
}
h1 {
    text-align:center;
}
h2 {
    border-top:1px solid #666666;
}

th {
    font-weight:bold;
    color:#eeeeee;
    background-color:#333333;
    cursor:pointer;
}
.odd  { background-color:#ffffff; }
.even { background-color:#dddddd; }
.paginate_enabled_next, .paginate_enabled_previous {
    cursor:pointer; 
    border:1px solid #222222; 
    background-color:#dddddd; 
    padding:2px; 
    margin:4px;
    border-radius:2px;
}
.paginate_disabled_previous, .paginate_disabled_next {
    color:#666666; 
    cursor:pointer;
    background-color:#dddddd; 
    padding:2px; 
    margin:4px;
    border-radius:2px;
}
.dataTables_info { margin-bottom:4px; }
.sectionheader { cursor:pointer; }
.sectionheader:hover { color:red; }
.grid { width:100% }
.red {
    color:red;
    font-weight:bold;
} 
</style>
"@
    }
    
    process
    {
        $list.AddRange($InputObject)
    }

    end
    {
        $params = @{
            As = 'Table'
            EvenRowCssClass = 'even'
            OddRowCssClass = 'odd'
            MakeTableDynamic = $true
            TableCssClass = 'grid'
            Properties = @(
                'Path'
                @{ Name = 'Expected Permissions'; Expression = { $_.ExpectedPermissions } }
                @{ Name = 'Current Permissions'; Expression = { $_.CurrentPermissions }; css = { if (-not $_.Correct) { 'red' } } }
            )
        }

        $fragment = $list | ConvertTo-EnhancedHTMLFragment @params

        $title = "Permission Report for '$Path'"

        $params = @{
            'CssStyleSheet' = $style
            'HtmlFragments' = $fragment
            'Title' = $title
            'PreContent' = "<h1>$([System.Net.WebUtility]::HtmlEncode($title))</h1>"
        }

        ConvertTo-EnhancedHTML @params
    }
}

#
# Script Entry Point
#

# Using the EnhancedHTML2 module from "Creating HTML Reports in PowerShell", by Don Jones.
# (https://github.com/PowerShellOrg/ebooks/tree/master/HTML)

Import-Module $PSScriptRoot\EnhancedHTML2.psd1 -ErrorAction Stop -Verbose:$false
Import-Module $PSScriptRoot\Event3.psm1 -ErrorAction Stop -Verbose:$false

$expectedSDs = Import-PermissionsFile -CsvPath $CsvPath -ErrorAction Stop

$Path = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path).TrimEnd('\')
if (-not $expectedSDs.ContainsKey($Path))
{
    throw "CSV file '$CsvPath' must contain an entry matching root folder '$Path'."
}

if ($FixPermissions)
{
    Repair-DirectoryTreePermission -Path $Path -ExpectedSD $expectedSDs
}
else
{    
    $reportName = '{0}-{1:yyyy_MM_dd}.html' -f (Split-Path -Path $Path -Leaf), (Get-Date)
    $reportName = Join-Path -Path $OutputDirectory -ChildPath $reportName

    Test-DirectoryTreePermission -Path $Path -ExpectedSD $expectedSDs |
    ConvertTo-PermissionReport -Path $Path |
    Out-File -FilePath $reportName
}