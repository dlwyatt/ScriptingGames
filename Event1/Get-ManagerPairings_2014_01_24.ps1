<#
.SYNOPSIS
    Generates pairings for morale boosting exercises.
.DESCRIPTION
    Generates pairings for morale boosting exercises.

    Takes a list of names as input and pairs the individuals together.
    If an odd number of people are entered, one person can be designated to be matched twice.
    Pairings can be saved as a plaintext file or as a CSV file.
.PARAMETER Name
    Specifies the names to pair.
.PARAMETER PairTwice
    Specifies the person to pair twice if an odd number of people are used.
.PARAMETER SaveAsType
    If specified, indicates that the file should be saved.  Valid values are Csv and Txt.
.PARAMETER OutputDirectory
    Specifies the directory to use when saving the output file.  Defaults to the script's directory.
.INPUTS
    Accepts a string array of names to pair.
.OUTPUTS
    An array of strings containing pairings.
    Optionally creates an output file.
.EXAMPLE
    .\Get-ManagerPairings.ps1 -Name 'Bill','Ted','Wayne','Garth','Lloyd','Harry'

    Pairs the listed people and displays the output in the console.
.EXAMPLE
    .\Get-ManagerPairings.ps1 -Name 'The Dude','Walter','Donny',Jeffrey','Maude','Bunny','Brandt' -PairTwice 'Bunny'

    Pairs the listed people with Bunny being paired with two people. Output is diplayed in the console.
.EXAMPLE
    Get-Content .\peopleList.txt | .\Get-ManagerPairings.ps1 -SaveAsType Txt

    Pairs the people listed in the the peopleList text file, displays the pairings in the console, and saves the results to a text file.
.EXAMPLE
    Get-Content .\peopleList.txt | .\Get-ManagerPairings.ps1 -SaveAsType csv

    The same as Example 3 but the results are saved as a CSV file.
.EXAMPLE
    .\Get-ManagerPairings.ps1 'Jerry','Bob','Phil','Pigpen','Bill','Mickey' -SaveAsType -OutputDirectory C:\Temp

    Pairs the listed people, displays the pairings in the console, and saves the results to a text file in the C:\Temp directory.
#>

#requires -Version 3.0

[CmdletBinding(DefaultParameterSetName = 'Default')]
param (
    [Parameter(Mandatory, ValueFromPipeline)]
    [string[]]
    $Name,

    [ValidateNotNullOrEmpty()]
    [string]
    $PairTwice,

    [Parameter(Mandatory, ParameterSetName = 'SaveData')]
    [ValidateSet('Txt','Csv')]
    [string]
    $SaveAsType,
    
    [Parameter(ParameterSetName = 'SaveData')]
    [ValidateNotNullOrEmpty()]
    [string]
    $OutputDirectory = $PSScriptRoot

)

begin {

    Import-Module -Name $PSScriptRoot\Event1.psm1 -ErrorAction Stop
    
    $userList = @()    

}

process {

    $userList += $Name

}

end {

    # Verify no duplicates exist in the name list

    If ( $userList.Count -ne ($userList | Select-Object -Unique).Count) {

        throw 'A duplicate name was found in the input list. Please ensure all names are unique and try again.'

    }

    # Check for an odd number of people, if so set the double if not already specified

    If ( $userList.Count % 2 -ne 0 ) {  
    
        If (!($PairTwice)) {
        
            Write-Warning 'An odd number of people were entered.'

            Write-Host
            Write-Host 'Names:'
            Write-Host

            for ($i = 0; $i -lt $userList.Count; $i++)
            {
                Write-Host ('{0,3:D}: {1}' -f $i, $userList[$i])
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
                    $number -ge 0 -and $number -lt $userList.Count)
                {
                    $PairTwice = $userList[$number]
                    break
                }
            }

        } # If (!($PairTwice))
    
    } # If ( $userList.Count % 2 -ne 0 )

    # Generate parings

    Write-Verbose 'Generating pairings...'

    try
    {
        $outputRaw = $userList | Get-Pairing -PairTwice $PairTwice -ErrorAction Stop
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

    # Create output for txt and csv if necessary

    $outputTxt = @('Generated Pairings:','')
    $outputCsv = @()
    
    $outputRaw | ForEach {
    
        $outputTxt += "$($_.First), $($_.Second)"

        If ($PSCmdlet.ParameterSetName -eq 'SaveData' -and $SaveAsType -eq 'Csv') {
        
            $props = [ordered]@{
                'First Person' = $_.First
                'Second Person' = $_.Second
            }

            $outputCsv += New-Object PsObject -Property $props

        }
    
    }

    $outputTxt

    If ($PSCmdlet.ParameterSetName -eq 'SaveData') {

        $dateStr = (Get-Date).ToShortDateString().Replace('/','-')
        $timeStr = (Get-Date).ToShorttimeString().Replace(':','.')

        $fileName = Join-Path -Path $OutputDirectory -ChildPath "Pairings Created On $dateStr At $timeStr.$SaveAsType"

        Write-Verbose "Saving results to '$fileName'"

        If ($SaveAsType -eq 'Csv') {
            $outputcsv | Export-Csv $fileName -NoTypeInformation
        }
        Else
        {
            $outputtxt | Out-File $fileName
        }
    
    }

} # end
