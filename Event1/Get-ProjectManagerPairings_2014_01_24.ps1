<#
.Synopsis
   Generates semi-random pairings for development teams.
.DESCRIPTION
   Generatings pairings for development teams.
   
   User may specify up to 5 "Primary" team members who will never be paired with other primary members,
   and automatically saved history data guarantees that the same two people will not be paired together
   until they have each worked with at least 4 other people.
.PARAMETER Name
   The list of names in the Development team.  For the purposes of the Games, all names are assumed to be unique,
   and the script will produce an error if any duplicates are specified.
.PARAMETER Primary
   A list of up to 5 Primary team members who must never be paired with other Primary members.
   These names must be passed to both the Primary and Name parameters
.PARAMETER PairTwice
   The name of a person who will be paired twice, if an overall odd number of Names are specified.
   If the number of Names is even, PairTwice is ignored.
   If PairTwice is not specified and the number of Names is odd, the script will prompt the user to enter a choice interactively.
.PARAMETER DataFile
   The path to an XML file that will store history data.  Defaults to a file named "history.xml" in the script's folder.
.PARAMETER SendEmail
   Switch that indicates the script should email out the pairings to those involved.
   
   For simplicity's sake, the script assumes that each Name on the list is an Active Directory SamAccountName (which fits well with
   our assumption that the names have to be unique, anyway), and that it can query ActiveDirectory to obtain the 'mail' attribute from
   each user.
.PARAMETER Cc
   Optional list of addresses to be copied on all communication when the SendEmail switch is used.
.EXAMPLE
   Get-Content .\Developers.txt | .\Get-ProjectManagerPairings.ps1

   Generates pairings based on a list of developers in the Developers.txt file, using no Primary logic,
   and using the default history file of 'history.xml' in the script's directory.
.EXAMPLE
   Get-Content .\Developers.txt | .\Get-ProjectManagerPairings.ps1 -SendEmail -Cc 'projectManager@company.com'

   Like example 1, except it also sends out emails to each pair, copying projectManager@company.com on each message.
.EXAMPLE
   .\Get-ProjectManagerPairings.ps1 -Name 'Dave','Bob','Gopi','Jason','Bruce','Brent','George','Paul','Robyn' -PairTwice 'Dave' -Primary 'Bob','Brent' -DataFile '.\Data.xml'

   Generates a list of pairings based on the provided names.  'Bob' and 'Brent' will never be paired with each other;
   'Dave' will be paired twice due to the odd number of names on the list.  Uses the file '.\Data.xml' to store pairing history.
.EXAMPLE
   .\Get-ProjectManagerPairings.ps1 -Name 'Dave','Bob','Gopi','Jason','Bruce','Brent','George','Paul','Robyn' -Primary 'Bob','Brent' -DataFile '.\Data.xml'

   Like example 3, except the PairTwice parameter was not specified.  Because the Name parameter is being passed an odd number
   of names, the script will prompt the user to choose one as the PairTwice member.
.INPUTS
   [String]
.OUTPUTS
   [String]
.NOTES
   There is some use of Write-Host in this script to display a menu and prompt for user input, when needed, but the pairings themselves
   are written to the Output stream and can be redirected, if desired.
#>

#requires -Version 3.0

[CmdletBinding()]
param (
    [Parameter(Mandatory, ValueFromPipeline)]
    [string[]]
    $Name,

    [ValidateScript({
        # Using this instead of ValidateNotNullOrEmpty allows an empty collection to be passed,
        # but not a collection that contains null or empty strings.  For whatever reason, combining
        # AllowEmptyCollection and ValidateNotNullOrEmpty still throws errors if an empty collection
        # is passed.

        if ((@($_) -match '^$').Count -gt 0)
        {
            throw 'The Primary parameter may not be passed any empty strings.'
        }
        else
        {
            $true
        }
    })]
    [ValidateCount(0,5)]
    [string[]]
    $Primary = @(),

    [ValidateNotNullOrEmpty()]
    [string]
    $PairTwice,

    [ValidateNotNullOrEmpty()]
    [string]
    $DataFile = (Join-Path -Path $PSScriptRoot -ChildPath history.xml),

    [switch]
    $SendEmail,

    [ValidateNotNullOrEmpty()]
    [mailaddress[]]
    $Cc = @()
)

begin
{
    Import-Module -Name $PSScriptRoot\Event1.psm1 -ErrorAction Stop

    if ($SendEmail)
    {
        try
        {
            Import-Module ActiveDirectory -ErrorAction Stop
        }
        catch
        {
            $exception = $_.Exception

            while ($null -ne $exception.InnerException)
            {
                $exception = $exception.InnerException
            }

            throw "The SendEmail switch requires the ActiveDirectory module, which could not be loaded due to the following error: $($exception.Message)"
        }
    }

    $list = New-Object System.Collections.ArrayList

} # begin

process
{
    $list.AddRange($Name)
}

end
{
    #region Validation and user input

    $duplicate = $list |
                 Group-Object |
                 Where Count -gt 1
        
    if ($null -ne $duplicate)
    {
        throw "Strings passed to the Name parameter must be unique."
    }

    if ($list.Count % 2 -eq 1)
    {
        if ([string]::IsNullOrEmpty($PairTwice))
        {
            Write-Warning 'An odd number of names was entered, and no PairTwice choice was specified on the command line.'
            Write-Host
            Write-Host 'Names:'
            Write-Host

            for ($i = 0; $i -lt $list.Count; $i++)
            {
                Write-Host ('{0,3:D}: {1}' -f $i, $list[$i])
            }

            Write-Host
            Write-Host 'Please type the number of the person you wish to be paired twice.'
            Write-Host 'To abort the script, press Enter without typing anything.'

            while ($true)
            {
                $string = Read-Host -Prompt 'Enter a number'

                if ([string]::IsNullOrEmpty($string))
                {
                    Write-Host
                    Write-Host 'Script aborting.'
                    exit
                }

                $number = $null

                if ($string -match '^\d+$' -and [int]::TryParse($string, [ref]$number) -and
                    $number -ge 0 -and $number -lt $list.Count)
                {
                    $PairTwice = $list[$number]
                    break
                }
            }

        } # if ([string]::IsNullOrEmpty($PairTwice))

    } # if ($list.Count % 2 -eq 1)

    #endregion

    #region Load data file.

    $data = New-Object System.Collections.ArrayList
    $history = @{}

    if (Test-Path -Path $DataFile -PathType Leaf)
    {
        Write-Verbose "Loading data file '$DataFile'."

        try
        {
            $data = Import-Clixml -Path $DataFile -ErrorAction Stop
        }
        catch
        {
            $exception = $_.Exception

            while ($null -ne $exception.InnerException)
            {
                $exception = $exception.InnerException
            }

            throw "Error loading data file: $($exception.Message)"
        }

        if ($data -isnot [System.Collections.ArrayList])
        {
            throw 'Data file was successfully loaded, but contained invalid data.'
        }

        Write-Verbose 'Data file load complete.'
    }

    # Get-Pairing expects history data to be in the form of a hashtable mapping names to collections of names.

    $data |
    Sort-Object -Property DateTime -Descending |
    Select-Object -ExpandProperty Pairings |
    ForEach-Object {
        $pair = $_

        $firstList = $history[$pair.First]
        $secondList = $history[$pair.Second]

        if ($null -eq $firstList)
        {
            $firstList = New-Object System.Collections.ArrayList
            $history.Add($pair.First, $firstList)
        }

        if ($null -eq $secondList)
        {
            $secondList = New-Object System.Collections.ArrayList
            $history.Add($pair.Second, $secondList)
        }

        # There's a subtle difference in checking for Count -lt 4 here, and using -First 4 in the Select-Object
        # command above.  If the list of participants might change between each round of pairings, it's better
        # to check the count on a per-participant basis, rather than only looking at the 4 most recent rounds of
        # pairings.

        if ($firstList.Count -lt 4)
        {
            $null = $firstList.Add($pair.Second)
        }

        if ($secondList.Count -lt 4)
        {
            $null = $secondList.Add($pair.First)
        }
    }

    #endregion

    #region Generate pairings

    Write-Verbose 'Generating pairings...'
    
    try
    {
        $pairings = Get-Pairing -Name $list.ToArray() -History $history -PairTwice $PairTwice -Primary $Primary -ErrorAction Stop
    }
    catch
    {
        $exception = $_.Exception

        while ($null -ne $exception.InnerException)
        {
            $exception = $exception.InnerException
        }

        throw "Error generating pairings: $($exception.Message)"
    }

    Write-Verbose 'Pairing generation complete.'

    #endregion

    #region Output pairings and send emails

    Write-Output ''
    Write-Output 'Pairings:'
    Write-Output ''

    foreach ($pair in $pairings)
    {
        Write-Output "$($pair.First), $($pair.Second)"
    }

    if ($SendEmail)
    {
        foreach ($pair in $pairings)
        {
            Write-Verbose "Fetching email addresses for $($pair.First) and $($pair.Second)"

            $toAddresses = @(Get-EmailAddress -SamAccountName $pair.First, $pair.Second)

            if ($toAddresses.Count -gt 0)
            {
                # The script assumes that the company SMTP server supports NTLM authentication, and that the account running
                # the script is allowed to send mail.  (No need for the user to enter credentials, or to store them.)

                $mailParams = @{
                    SmtpServer = 'smtp.company.com'
                    Port = '25'
                    UseSsl = $true
                    Subject = 'Pairings Notification'
                    Body = "$($pair.First) has been paired with $($pair.Second)"
                    To = $toAddresses
                    From = 'do_not_reply@company.com'
                }

                $message = "Sending email to $($toAddresses -join ', ')."
                
                if ($Cc.Count -gt 0)
                {
                    $mailParams['Cc'] = $Cc
                    $message += "  CC: $($Cc -join ', ')"
                }


                Write-Verbose $message

                try
                {
                    Send-MailMessage @mailParams -ErrorAction Stop
                }
                catch
                {
                    $exception = $_.Exception

                    while ($null -ne $exception.InnerException)
                    {
                        $exception = $exception.InnerException
                    }

                    Write-Error "Error sending email to users '$($pair.First)' and '$($pair.Second)': $($exception.Message)"
                }

            } # if ($toAddresses.Count -gt 0)

        } # foreach ($pair in $pairings)
    
    } # if ($SendEmail)

    #endregion

    #region Update Data File

    Write-Verbose "Saving new data to file '$DataFile'..."

    $dataPairings = [pscustomobject]@{
        Pairings = $pairings
        DateTime = (Get-Date)
    }

    $null = $data.Add($dataPairings)

    try
    {
        Export-Clixml -Path $DataFile -InputObject $data -Force -ErrorAction Stop
    }
    catch
    {
        $exception = $_.Exception

        while ($null -ne $exception.InnerException)
        {
            $exception = $exception.InnerException
        }

        throw "Error saving data file: $($exception.Message)"
    }

    Write-Verbose 'Finished updating data file.'

    #endregion

} # end

