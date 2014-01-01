#requires -Version 3.0

function Get-Pairing
{
    <#
    .Synopsis
       Generates semi-random pairings of names.
    .DESCRIPTION
       Generates semi-random pairings of names from the list specified by the Name parameter.
       Some pairing behavior can be controlled via the other parameters described below.
    .PARAMETER Name
       The list of names to be paired.  For the purposes of the Games, all names are assumed to be unique,
       and the script will produce an error if any duplicates are specified.
    .PARAMETER PairTwice
       The name of a person who will be paired twice, if an overall odd number of Names are specified.
       If the number of Names is even, PairTwice is ignored.  If PairTwice is not specified and the number
       of Names is odd, the function will throw an error.
    .PARAMETER Primary
       An optional list of up to 5 Primary names who must never be paired with other Primary names.
       These names must be passed to both the Primary and Name parameters.
    .PARAMETER History
       An optional hashtable mapping names to collections of names.  If a name in the Name list is contained
       in the History table, that name will not be paired with any of the names already in its history.
    .EXAMPLE
       Get-Pairing -Name 'Dave','Bob','Gopi','Jason','Bruce','Brent','George','Paul','Robyn' -PairTwice 'Dave' -Primary 'Bob','Brent' -History @{ Dave = 'Gopi','Bob'; Bruce = 'Brent','Bob' }

       Generates pairings based on the names provided.  Dave will be paired twice (because the Name parameter
       is being passed an odd number of names.)  Dave will not be paired with either Gopi or Bob, and Bruce will
       not be paired with either Brent or Bob, due to the specified History table.
    .EXAMPLE
       Get-Content Names.txt | Get-Pairing

       So long as Names.txt contains an even number of names, generates completely random pairings (with no
       History or Primary functionality affecting them.)
       If Names.txt contains an odd number of names, Get-Pairing will produce an error.
    .NOTES
       It is possible for there to be no legal pairing solution, if the Primary and/or History features are
       used, and there are not enough names in the pool to satisfy their limitations.  The function does NOT
       try to bend these rules once it has exhausted all other possibilities.

       If this happens, the function throws an error and does not produce any pipeline output.
    .INPUTS
       [String]
    .OUTPUTS
       [pscustomobject]

       Custom objects with the properties "First" and "Second" are output for the pairings; these properties
       contain the names of the people in each pair.
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]
        $Name,

        [string]
        $PairTwice,

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
        [string[]]
        $Primary = @(),

        [ValidateNotNull()]
        [hashtable]
        $History = @{}
    )

    begin
    {
        $participantList = New-Object System.Collections.ArrayList
        $primaryList = New-Object System.Collections.ArrayList

        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    }

    process
    {
        foreach ($item in $Name)
        {
            $object = [pscustomobject]@{
                Name = $item
                Availability = 1
                History = $History[$item]
            }

            if ($PairTwice -eq $item)
            {
                $object.Availability = 2
            }

            if ($Primary -contains $item)
            {
                $null = $primaryList.Add($object)
            }
            else
            {
                $null = $participantList.Add($object)
            }
        }
    }

    end
    {
        #region Validate input

        $duplicate = @($primaryList; $participantList) |
                     Group-Object -Property Name |
                     Where Count -gt 1
        
        if ($null -ne $duplicate)
        {
            throw "Strings passed to the Name parameter must be unique."
        }

        $count = $primaryList.Count + $participantList.Count

        if ($count % 2 -eq 1)
        {            
            if ([string]::IsNullOrEmpty($PairTwice))
            {
                throw "When specifying an odd number of names, you must also specify a value for the PairTwice parameter."
            }
            else
            {
                $match = $(
                    $primaryList   | Where Name -eq $PairTwice
                    $participantList | Where Name -eq $PairTwice
                )

                if ($null -eq $match)
                {
                    throw "A PairTwice value of '$PairTwice' was specified, but this name was not found in the Name list."
                }
            }
        }

        $missing = New-Object System.Collections.ArrayList
        foreach ($string in $Primary)
        {
            $match = $primaryList | Where Name -eq $string

            if ($null -eq $match)
            {
                $null = $missing.Add($string)
            }
        }

        if ($missing.Count -gt 0)
        {
            Write-Warning "The following names were passed to the Primary parameter, but were missing from the Name parameter: $($missing -join ', ')"
        }

        #endregion

        #region Randomize lists and generate pairings

        $primaryList = @($primaryList | Sort-Object -Property { Get-Random -Minimum 1 -Maximum 10000 })
        $participantList = @($participantList | Sort-Object -Property { Get-Random -Minimum 1 -Maximum 10000 })

        $pairings = New-Object System.Collections.ArrayList

        if (GeneratePairings -Participant $participantList -Primary $primaryList -Pairings $pairings)
        {
            Write-Output $pairings
        }
        else
        {
            throw "No legal set of pairings could be generated based on the history and names provided."
        }

        #endregion

    } # end

} # function Get-Pairing

function Get-EmailAddress
{
    <#
    .Synopsis
       Retrieves email addresses from Active Directory.
    .DESCRIPTION
       For each specified SamAccountName, attempts to find a matching user account in Active Directory.  If its mail
       attribute is defined and contains a valid email address, the function returns that address.  If the function
       cannot find this information for a particular user, or if the mail attribute contains malformed data, this is
       indicated via the Warning stream.
    .PARAMETER SamAccountName
       One or more SamAccountName values associated with Active Directory user accounts.
    .EXAMPLE
       'User01','User02','User03' | Get-EmailAddress
    .EXAMPLE
       Get-EmailAddress -SamAccountName 'User01','User02','User03'
    .INPUTS
       String
    .OUTPUTS
       String
    .LINK
       Get-ADUser       
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]
        $SamAccountName
    )

    begin
    {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    }

    process
    {
        foreach ($string in $SamAccountName)
        {
            try
            {
                $user = Get-ADUser -Filter "SamAccountName -eq '$string'" -Properties mail -ErrorAction Stop
            }
            catch
            {
                $exception = $_.Exception

                while ($null -ne $exception.InnerException)
                {
                    $exception = $exception.InnerException
                }

                Write-Warning "Error retrieving Active Directory user object for '$string': $($exception.Message)"
                continue
            }

            $email = $user.mail

            if ([string]::IsNullOrEmpty($email))
            {
                Write-Warning "Could not find email address for user '$string' in Active Directory."
            }
            elseif ($null -eq ($email -as [mailaddress]))
            {
                Write-Warning "User '$string' has an AD mail address of '$email', which is not a valid format for an email address."
            }
            else
            {
                Write-Output $email
            }
        }
    }

} # function Get-EmailAddress

# Get-CallerPreference function from http://gallery.technet.microsoft.com/Inherit-Preference-82343b9d

# I wrote it, but unlike the rest of this module, it's written to be PowerShell 2.0-compatible, since
# it was to be used for more than just the Scripting Games.

function Get-CallerPreference
{
    <#
    .Synopsis
       Fetches "Preference" variable values from the caller's scope.
    .DESCRIPTION
       Script module functions do not automatically inherit their caller's variables, but they can be
       obtained through the $PSCmdlet variable in Advanced Functions.  This function is a helper function
       for any script module Advanced Function; by passing in the values of $ExecutionContext.SessionState
       and $PSCmdlet, Get-CallerPreference will set the caller's preference variables locally.
    .PARAMETER Cmdlet
       The $PSCmdlet object from a script module Advanced Function.
    .PARAMETER SessionState
       The $ExecutionContext.SessionState object from a script module Advanced Function.  This is how the
       Get-CallerPreference function sets variables in its callers' scope, even if that caller is in a different
       script module.
    .PARAMETER Name
       Optional array of parameter names to retrieve from the caller's scope.  Default is to retrieve all
       Preference variables as defined in the about_Preference_Variables help file (as of PowerShell 4.0)
       This parameter may also specify names of variables that are not in the about_Preference_Variables
       help file, and the function will retrieve and set those as well.
    .EXAMPLE
       Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

       Imports the default PowerShell preference variables from the caller into the local scope.
    .EXAMPLE
       Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name 'ErrorActionPreference','SomeOtherVariable'

       Imports only the ErrorActionPreference and SomeOtherVariable variables into the local scope.
    .EXAMPLE
       'ErrorActionPreference','SomeOtherVariable' | Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

       Same as Example 2, but sends variable names to the Name parameter via pipeline input.
    .INPUTS
       String
    .OUTPUTS
       None.  This function does not produce pipeline output.
    .LINK
       about_Preference_Variables
    #>

    [CmdletBinding(DefaultParameterSetName = 'AllVariables')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_.GetType().FullName -eq 'System.Management.Automation.PSScriptCmdlet' })]
        $Cmdlet,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.SessionState]
        $SessionState,

        [Parameter(ParameterSetName = 'Filtered', ValueFromPipeline = $true)]
        [string[]]
        $Name
    )

    begin
    {
        $filterHash = @{}
    }
    
    process
    {
        if ($null -ne $Name)
        {
            foreach ($string in $Name)
            {
                $filterHash[$string] = $true
            }
        }
    }

    end
    {
        # List of preference variables taken from the about_Preference_Variables help file in PowerShell version 4.0

        $vars = @{
            'ErrorView' = $null
            'FormatEnumerationLimit' = $null
            'LogCommandHealthEvent' = $null
            'LogCommandLifecycleEvent' = $null
            'LogEngineHealthEvent' = $null
            'LogEngineLifecycleEvent' = $null
            'LogProviderHealthEvent' = $null
            'LogProviderLifecycleEvent' = $null
            'MaximumAliasCount' = $null
            'MaximumDriveCount' = $null
            'MaximumErrorCount' = $null
            'MaximumFunctionCount' = $null
            'MaximumHistoryCount' = $null
            'MaximumVariableCount' = $null
            'OFS' = $null
            'OutputEncoding' = $null
            'ProgressPreference' = $null
            'PSDefaultParameterValues' = $null
            'PSEmailServer' = $null
            'PSModuleAutoLoadingPreference' = $null
            'PSSessionApplicationName' = $null
            'PSSessionConfigurationName' = $null
            'PSSessionOption' = $null

            'ErrorActionPreference' = 'ErrorAction'
            'DebugPreference' = 'Debug'
            'ConfirmPreference' = 'Confirm'
            'WhatIfPreference' = 'WhatIf'
            'VerbosePreference' = 'Verbose'
            'WarningPreference' = 'WarningAction'
        }

        foreach ($entry in $vars.GetEnumerator())
        {
            if (([string]::IsNullOrEmpty($entry.Value) -or -not $Cmdlet.MyInvocation.BoundParameters.ContainsKey($entry.Value)) -and
                ($PSCmdlet.ParameterSetName -eq 'AllVariables' -or $filterHash.ContainsKey($entry.Name)))
            {
                $variable = $Cmdlet.SessionState.PSVariable.Get($entry.Key)
                
                if ($null -ne $variable)
                {
                    if ($SessionState -eq $ExecutionContext.SessionState)
                    {
                        Set-Variable -Scope 1 -Name $variable.Name -Value $variable.Value -Force
                    }
                    else
                    {
                        $SessionState.PSVariable.Set($variable.Name, $variable.Value)
                    }
                }
            }
        }

        if ($PSCmdlet.ParameterSetName -eq 'Filtered')
        {
            foreach ($varName in $filterHash.Keys)
            {
                if (-not $vars.ContainsKey($varName))
                {
                    $variable = $Cmdlet.SessionState.PSVariable.Get($varName)
                
                    if ($null -ne $variable)
                    {
                        if ($SessionState -eq $ExecutionContext.SessionState)
                        {
                            Set-Variable -Scope 1 -Name $variable.Name -Value $variable.Value -Force
                        }
                        else
                        {
                            $SessionState.PSVariable.Set($variable.Name, $variable.Value)
                        }
                    }
                }
            }
        }

    } # end

} # function Get-CallerPreference

function GeneratePairings
{
    # Recursive utility function to search for a valid pairing solution based on the Primary / History functionality.
    # If a valid solution is found, returns $true and populates the $Pairings ArrayList with pair objects (PSCustomObjects
    # with "First" and "Second" properties.)  If no valid solution is found, returns $false.

    # This function is not exported, so comment-based help would be wasted here (Get-Help and Get-Command won't find this
    # function anyway.)

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [psobject[]]
        $Participant,

        [ValidateNotNull()]
        [psobject[]]
        $Primary = @(),

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.ArrayList]
        $Pairings
    )

    $availablePrimary = @($Primary | Where Availability -gt 0)
    $availableParticipant = @($Participant | Where Availability -gt 0)

    $availableCount = $availablePrimary.Count + $availableParticipant.Count

    if ($availableCount -eq 0)
    {
        return $true
    }

    if ($availableCount -eq 1)
    {
        # This condition occasionally happens if our "PairTwice" participant is the only one left that hasn't been paired.

        Write-Verbose "Only one participant remains in the available pool; backtracking."

        return $false
    }

    if ($availablePrimary.Count -gt 0)
    {
        # If someone in the Primary group can't be paired with anyone from the Participant group, the whole algorithm is going to fail anyway, so we can
        # shortcut some of the iterations by just trying to pair the first available Primary and returning false if it fails.

        $first = $availablePrimary[0]

        for ($i = 0; $i -lt $availableParticipant.Count; $i++)
        {
            $second = $availableParticipant[$i]

            if (TryPairing @PSBoundParameters -First $first -Second $second)
            {
                $pair = [pscustomobject]@{
                    First = $first.Name
                    Second = $second.Name
                }

                $null = $Pairings.Insert(0, $pair)

                return $true
            }
        }

        Write-Verbose "Primary participant $($first.Name) could not be paired with any non-primary participants; backtracking."
    }
    else
    {
        # Since there's no one left on the Primary list to try, enumerate every possible combination of the remaining Participants until we succeed or run out of options.

        for ($i = 0; $i -lt $availableParticipant.Count - 1; $i++)
        {
            for ($j = $i + 1; $j -lt $availableParticipant.Count; $j++)
            {
                $first = $availableParticipant[$i]
                $second = $availableParticipant[$j]

                if (TryPairing @PSBoundParameters -First $first -Second $second)
                {
                    $pair = [pscustomobject]@{
                        First = $first.Name
                        Second = $second.Name
                    }

                    $null = $Pairings.Insert(0, $pair)

                    return $true
                }
            }
        }

        Write-Verbose "No legal combination of non-primary participants could be found in this iteration; backtracking."
    }

    return $false

} # function GeneratePairings

function TryPairing
{
    # Helper function for GeneratePairings to minimize duplicated code and keep it readable.  TryPairing is responsible for
    # checking the History table, managing the Availability counters, and making the recursive calls to GeneratePairings to
    # see if a valid solution can be made, starting with the current pairing.

    # This function is not exported, so comment-based help would be wasted here (Get-Help and Get-Command won't find this
    # function anyway.)

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [psobject[]]
        $Participant,

        [ValidateNotNull()]
        [psobject[]]
        $Primary = @(),

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.ArrayList]
        $Pairings,

        [Parameter(Mandatory)]
        $First,

        [Parameter(Mandatory)]
        $Second
    )

    Write-Verbose "Trying pairing:  $($First.Name), $($Second.Name)"

    if ($First.History -notcontains $Second.Name -and $Second.History -notcontains $First.Name)
    {
        $first.Availability--
        $second.Availability--

        $success = GeneratePairings -Participant $Participant -Primary $Primary -Pairings $Pairings

        if ($success)
        {
            Write-Verbose "Pairing successful: $($First.Name), $($Second.Name)"

            return $true
        }
        else
        {
            $first.Availability++
            $second.Availability++

            Write-Verbose "$($First.Name) could not be paired with $($Second.Name), because the remaining participants could not be paired without violating History and/or Primary logic."
        }
    }
    else
    {
        Write-Verbose "$($First.Name) not paired with $($Second.Name) due to an identical pairing in recent history."
    }

    return $false

} # function TryPairing

Export-ModuleMember -Function 'Get-Pairing', 'Get-EmailAddress', 'Get-CallerPreference'
