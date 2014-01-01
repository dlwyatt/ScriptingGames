<#
.Synopsis
   Searches a subnet for Windows computers.
.DESCRIPTION
   Pings all IP addresses on an IPv4 subnet.  For the IPs that responded to the ping, attempts to collect the Operating System and Service Pack of the computer with WMI.
   The results of this scan are saved to a CSV file.
.PARAMETER Subnet
   The IPv4 subnet to be scanned, in CIDR format.  For example:  "192.168.0.0/24" would check IPs 192.168.0.1 through 192.168.0.254.
.PARAMETER OutputDirectory
   The directory where the output CSV file should be saved.  The file name will be, for example, 192.168.0.0_24-yyyy-mm-dd.csv (where the "/" character in the subnet name has been replaced with an underscore, and yyyy-mm-dd are today's year, month and day.)
   If a file with that name already exists, the script will create a new file named 192.168.0.0_24-2014-01-10_1.csv (or _2, _3, etc.)
.NOTES
   This script requires PowerShell version 4.0, and assumes that the user running the script has permissions to query WMI on all remote machines.
.EXAMPLE
   .\Get-ComputersInSubnet.ps1 -Subnet '192.168.0.0/24' -OutputDirectory 'c:\IPScans\'

   Scans IPs 192.168.0.1 through 192.168.0.254 and saves the results to a file named c:\IPScans\192.168.0.0_24-yyyy-mm-dd.csv (assuming that file doesn't already exist.)
.EXAMPLE
   '192.168.0.0/24', '192.168.0.1/24', '10.0.0.0/22' | .\Get-ComputersInSubnet.ps1 -OutputDirectory 'c:\IPScans\'

   Performs three different subnet scans (ranges 192.168.0.1 - 192.168.0.254, 192.168.1.1 - 192.168.1.254, and 10.0.0.1 - 10.0.3.254).  Each subnet's report is placed into its own CSV file in the c:\IPScans directory.
.INPUTS
   String
.OUTPUTS
   None.  This script does not produce pipeline output.
#>

#requires -Version 4.0

[CmdletBinding()]
param (
    [Parameter(Mandatory, ValueFromPipeline)]
    [string[]]
    $Subnet,

    [ValidateNotNullOrEmpty()]
    [string]
    $OutputDirectory = '.'
)

begin
{
    Import-Module -Name .\PracticeModule.psm1 -ErrorAction Stop -Verbose:$false

    if (-not (Test-Path -Path $OutputDirectory -PathType Container))
    {
        try
        {
            $null = New-Item -Path $OutputDirectory -ItemType Directory -ErrorAction Stop
        }
        catch
        {
            throw "Error creating directory '$OutputDirectory':`r`n$($_ | Out-String)"
        }
    }
}

process
{
    foreach ($string in $Subnet)
    {
        Write-Verbose "Processing subnet $string."

        $report = Get-ComputersInSubnet -Subnet $string

        $baseFileName = '{0}-{1:yyyy-MM-dd}' -f ($string -replace '/', '_'), (Get-Date)
        $suffix = 1

        $fileName = Join-Path -Path $OutputDirectory -ChildPath "$baseFileName.csv"

        while (Test-Path -Path $fileName)
        {
            $fileName = Join-Path -Path $OutputDirectory -ChildPath "${baseFileName}_$suffix.csv"
            $suffix++
        }

        Write-Verbose "Finished processing subnet $string.  Saving report to file '$fileName'."

        $report | Export-Csv -LiteralPath $fileName -NoTypeInformation
    }
}
