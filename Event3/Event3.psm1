#requires -Version 4.0

Add-Type -Path $PSScriptRoot\Microsoft.Experimental.IO.dll -ErrorAction Stop

function Test-DepartmentGroups
{
    <#
    .Synopsis
       Makes sure all department, team and auditor groups exist in the specified domain.
    .DESCRIPTION
       Makes sure all department, team and auditor groups exist in the specified domain.  This function knows that for each listed Team, there should be both a Team and Team_lead group.
    .PARAMETER Domain
       The computer or domain name that is to be searched for the target groups.
    .PARAMETER Department
       The name of the Department whose groups are being checked.
    .PARAMETER Teams
       Optional list of teams in the specified Department.  For each Team listed, this function will look for both <Team> and <Team>_lead groups.
    .PARAMETER AdditionalGroups
       Optional list of extra groups that should exist.
    .EXAMPLE
       Test-DepartmentGroups -Department Finance -Domain SOMEDOMAIN -Teams 'Receipts', 'Payments', 'Accounting', 'Auditing' -AdditionalGroups 'Auditors'

       Checks the SOMEDOMAIN domain for the following groups:
       Finance
       Receipts
       Receipts_lead
       Payments
       Payments_lead
       Accounting
       Accounting_lead
       Auditing
       Auditing_lead
       Auditors
    .INPUTS
       None
    .OUTPUTS
       None
    .NOTES
       If all of the groups are found, this command generates no output.  If any groups cannot be translated to a SID, this command throws a terminating error.
    #>    

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Department,

        [Parameter(Mandatory)]
        [string]
        $Domain,

        [string[]]
        $Teams = @(),

        [string[]]
        $AdditionalGroups = @()
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    # region Set up list of groups according to current Department / Team / Auditor rules

    $groupList = New-Object System.Collections.Specialized.OrderedDictionary

    $groupList[$Department] = $true

    foreach ($team in $Teams)
    {
        $groupList[$team] = $true
        $groupList["${team}_lead"] = $true
    }

    foreach ($group in $AdditionalGroups)
    {
        if (-not $groupList.Contains($group))
        {
            $groupList[$group] = $true
        }
    }

    #endregion

    #region Check for each group's existence, throw error if any not found.

    $errors = New-Object System.Text.StringBuilder

    foreach ($group in $groupList.Keys)
    {
        $displayName = "$Domain\$group"
        $ntAccount = [System.Security.Principal.NTAccount]$displayName

        try
        {
            $null = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
        }
        catch
        {
            $exception = Get-InnerException -ErrorRecord $_
            $null = $errors.AppendFormat('{0,-35}{1}', $displayName, $exception.Message).AppendLine()
        }
    }

    if ($errors.Length -gt 0)
    {
        throw "Errors encountered locating the following groups:`r`n$errors"
    }

    #endregion
}

function New-DepartmentStructureInfo
{
    <#
    .Synopsis
       Generates objects which can be later sent to New-FolderStructure.
    .DESCRIPTION
       Based on the current scheme of folders and permissions for Departments, generates objects which can be piped to New-FolderStructure.
       New-DepartmentStructureInfo does not actually make any changes to the file system; it simply sets up the required input objects.
    .PARAMETER Path
       Path to the directory which should contain the new department's folder tree.
    .PARAMETER Department
       Name of the Department whose structure is to be defined.
    .PARAMETER Domain
       The domain or computer which contains the department and team groups.
    .PARAMETER Teams
       List of teams contained within this department.
    .PARAMETER AuditorGroups
       Optional list of groups which should have Read / Execute access to the entire Department folder structure.
    .EXAMPLE
       New-DepartmentStructureInfo -Path '\\Server\Share\Departments' -Department Finance -Domain SOMEDOMAIN -Teams 'Receipts', 'Payments', 'Accounting', 'Auditing' -AdditionalGroups 'Auditors'
    .INPUTS
       None.
    .OUTPUTS
       PSObject (Containing Path and SecurityDescriptor properties)
    .NOTES
       This function does not check for the existence of the Path folder or the various groups.  It is the caller's responsibility to call Test-DepartmentGroups and check on the existence of Path first.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Department,

        [Parameter(Mandatory)]
        [string]
        $Path,

        [Parameter(Mandatory)]
        [string]
        $Domain,

        [string[]]
        $Teams = @(),

        [string[]]
        $AuditorGroups = @()
    )

    $Path = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)

    New-DepartmentFolderInfo -Path $Path -Department $Department -Domain $Domain

    $departmentFolder = Join-Path -Path $Path -ChildPath $Department

    foreach ($team in $Teams)
    {
        New-TeamStructureInfo -Path $departmentFolder -Team $team -Department $Department -Domain $Domain -AuditorGroups $AuditorGroups
    }
}

function New-FolderStructure
{
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject[]]
        $InputObject
    )

    begin
    {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    }

    process
    {
        foreach ($object in $InputObject)
        {
            if (-not $PSCmdlet.ShouldProcess($object.Path, 'Create directory and set permissions'))
            {
                continue
            }

            if (-not (Test-Path -Path $object.Path -PathType Container))
            {
                Write-Verbose "Creating folder '$($object.Path)'..."

                try
                {
                    $null = New-Item -Path $object.Path -ItemType Directory -ErrorAction Stop -Confirm:$false -WhatIf:$false
                }
                catch
                {
                    $exception = Get-InnerException -ErrorRecord $_
                    Write-Error "Error creating directory '$($object.Path)': $($exception.Message)"
                    continue
                }
            }
            else
            {
                Write-Verbose "Folder '$($object.Path)' already exists."
            }

            Write-Verbose "Setting permissions on directory '$($object.Path)'..."

            try
            {
                Set-Acl -AclObject $object.SecurityDescriptor -LiteralPath $object.Path -ErrorAction Stop -Confirm:$false -WhatIf:$false
            }
            catch
            {
                    $exception = Get-InnerException -ErrorRecord $_
                    Write-Error "Error setting permissions on directory '$($object.Path)': $($exception.Message)"
                    continue
            }
        }
    }
}

function Test-DirectoryTreePermission
{
    <#
    .Synopsis
       Analyzes permissions of folder structure based on user input.
    .PARAMETER Path
       Path to the root directory of the tree that is to be checked.
    .PARAMETER ExpectedSD
       Hashtable mapping folder paths to [System.Security.AccessControl.DirectorySecurity] objects which describe the expected permissions for that path.
    .EXAMPLE
       Test-DirectoryTreePermission -Path '\\Server\Share\Departments\Finance' -ExpectedSD @{ '\\Server\Share\Departments\Finance' = $aDirectorySecurityObject }

       Assuming that $aDirectorySecurityObject refers to a valid [System.Security.AccessControl.DirectorySecurity] object, the function will check whether the permissions
       on the root folder '\\Server\Share\Departments\Finance' match that object.  For any child folders or files under '\\Server\Share\Departments\Finance', the function
       will report if they are set up to do anything other than inherit parent permissions.
    .INPUTS
       None
    .OUTPUTS
       PSObjects (With properties Path, ExpectedPermission, ActualPermission, and Correct).
    .NOTES
       Output objects will be generated for all paths defined in the ExpectedSD table, regardless of whether they are correct or not.  For other files and folders in the
       tree, output objects will only be generated if they are incorrect.

       For entries in the ExpectedSD table, permissions are considered to be correct if the DACL protection on the actual folder matches the protection setting of the
       ExpectedSD entry, and if all explicit ACEs match.  For directories that should be set to inherit parent permissions, inherited ACEs are ignored when comparing the ACLs
       (so if a parent folder has something "wrong", the child folder is still considered to be configured correctly, since it's doing what it should be doing:  inheriting ACEs.)

       Other than the entries in the ExpectedSD table, permissions are assumed to be correct if they are all inherited from the parent.  Any folder that blocks DACL inheritance
       or contains an explicit ACE is considered to be incorrect.

       At a minimum, the root folder specified by the $Path parameter must exist in the $ExpectedSD table.  Do not include trailing path separators in the keys of this table, and
       do not use relative paths.
    .LINK
       Repair-DirectoryTreePermission
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({
            ValidateInputFileSystemParameter -Path $_ -ParameterName Path -PathType Container
        })]
        [string]
        $Path,
        
        [Parameter(Mandatory)]
        [hashtable]
        $ExpectedSD
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    if (-not $ExpectedSD.ContainsKey($Path))
    {
        throw "Tree root '$Path' must exist as an entry in the ExpectedSD table."
    }

    WalkDirectoryTreePermissions @PSBoundParameters -CreateReport -ParentSD $ExpectedSD[$Path]
}

function Repair-DirectoryTreePermission
{
    <#
    .Synopsis
       Analyzes and repairs permissions of folder structure based on user input.
    .PARAMETER Path
       Path to the root directory of the tree that is to be checked.
    .PARAMETER ExpectedSD
       Hashtable mapping folder paths to [System.Security.AccessControl.DirectorySecurity] objects which describe the expected permissions for that path.
    .EXAMPLE
       Repair-DirectoryTreePermission -Path '\\Server\Share\Departments\Finance' -ExpectedSD @{ '\\Server\Share\Departments\Finance' = $aDirectorySecurityObject }

       Assuming that $aDirectorySecurityObject refers to a valid [System.Security.AccessControl.DirectorySecurity] object, the function will ensure that the permissions
       on the root folder '\\Server\Share\Departments\Finance' match that object.  For any child folders or files under '\\Server\Share\Departments\Finance', the function
       will reset them to inherit parent permissions and remove any explicit ACEs, if found.
    .INPUTS
       None
    .OUTPUTS
       None
    .NOTES
       To see which folders and files needed to be modified, use the -Verbose switch.  This function generates no output, otherwise.

       For entries in the ExpectedSD table, permissions are considered to be correct if the DACL protection on the actual folder matches the protection setting of the
       ExpectedSD entry, and if all explicit ACEs match.  For directories that should be set to inherit parent permissions, inherited ACEs are ignored when comparing the ACLs
       (so if a parent folder has something "wrong", the child folder is still considered to be configured correctly, since it's doing what it should be doing:  inheriting ACEs.)

       Other than the entries in the ExpectedSD table, permissions are assumed to be correct if they are all inherited from the parent.  Any folder that blocks DACL inheritance
       or contains an explicit ACE is considered to be incorrect.

       At a minimum, the root folder specified by the $Path parameter must exist in the $ExpectedSD table.  Do not include trailing path separators in the keys of this table, and
       do not use relative paths.
    .LINK
       Test-DirectoryTreePermission
    #>

    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({
            ValidateInputFileSystemParameter -Path $_ -ParameterName Path -PathType Container
        })]
        [string]
        $Path,
        
        [Parameter(Mandatory)]
        [hashtable]
        $ExpectedSD
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    if (-not $ExpectedSD.ContainsKey($Path))
    {
        throw "Tree root '$Path' must exist as an entry in the ExpectedSD table."
    }

    WalkDirectoryTreePermissions @PSBoundParameters -FixPermissions -ParentSD $ExpectedSD[$Path]
}

function Get-InnerException
{
    <#
    .Synopsis
       Returns the innermost Exception from either an Exception or ErrorRecord object.
    .DESCRIPTION
       Returns the innermost Exception from either an Exception or ErrorRecord object.
    .PARAMETER ErrorRecord
       An object of type [System.Management.Automation.ErrorRecord]
    .PARAMETER Exception
       An object of type [System.Exception] or any derived type.
    .EXAMPLE
       $exception = Get-InnerException -ErrorRecord $_

       Retrieves the original exception associated with the ErrorRecord in the $_ variable, as would be found in a Catch block.
    .EXAMPLE
       $innerException = Get-InnerException -Exception $exception

       Retrieves the original exception associated with the $exception variable.  If no InnerExceptions are found, $exception is returned.
    .INPUTS
       None.  This command does not accept pipeline input.
    .OUTPUTS
       System.Exception
    #>

    [CmdletBinding(DefaultParameterSetName = 'ErrorRecord')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'ErrorRecord')]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord,

        [Parameter(Mandatory, ParameterSetName = 'Exception')]
        [System.Exception]
        $Exception
    )

    if ($PSCmdlet.ParameterSetName -eq 'ErrorRecord')
    {
        $_exception = $ErrorRecord.Exception
    }
    else
    {
        $_exception = $Exception
    }

    while ($null -ne $_exception.InnerException)
    {
        $_exception = $_exception.InnerException
    }

    return $_exception
}

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
                        Set-Variable -Scope 1 -Name $variable.Name -Value $variable.Value -Force -WhatIf:$false -Confirm:$false
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
                            Set-Variable -Scope 1 -Name $variable.Name -Value $variable.Value -Force -WhatIf:$false -Confirm:$false
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


function WalkDirectoryTreePermissions
{
    # Recursive function to check a directory structure for proper permissions (either generating output objects
    # describing the permissions and any incorrect settings, fixing the permissions on disk, or both.)

    # Supports directories longer than the standard .NET Framework limit of 260 characters.

    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [string]
        $Path,
        
        [Parameter(Mandatory)]
        [hashtable]
        $ExpectedSD,
        
        [Parameter(Mandatory)]
        [System.Security.AccessControl.DirectorySecurity]
        $ParentSD,

        [switch]
        $CreateReport,

        [switch]
        $FixPermissions
    )

    VisitDirectory @PSBoundParameters

    $null = $PSBoundParameters.Remove('Path')
    $null = $PSBoundParameters.Remove('ParentSD')

    $securityDescriptor = $ExpectedSD[$Path]
    
    if ($null -eq $securityDescriptor)
    {
        $securityDescriptor = $ParentSD
    }
    
    foreach ($file in [Microsoft.Experimental.IO.LongPathDirectory]::EnumerateFiles($Path))
    {
        VisitFile -Path $file -ParentSD $securityDescriptor @PSBoundParameters
    }


    foreach ($directory in [Microsoft.Experimental.IO.LongPathDirectory]::EnumerateDirectories($Path))
    {
        WalkDirectoryTreePermissions -Path $directory -ParentSD $securityDescriptor @PSBoundParameters
    }

} # function WalkDirectoryTreePermissions

function VisitDirectory
{
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [string]
        $Path,
        
        [Parameter(Mandatory)]
        [hashtable]
        $ExpectedSD,
        
        [Parameter(Mandatory)]
        [System.Security.AccessControl.DirectorySecurity]
        $ParentSD,

        [switch]
        $CreateReport,

        [switch]
        $FixPermissions
    )
    
    # If there is no entry in $ExpectedSDs for this folder, then we assume that it should contain only inherited ACEs
    # (and the proper action to fix it would be to remove all explicit ACEs and restore inheritance.)  If there is an entry for
    # this folder in $ExpectedSDs, then it must exactly match the current folder's DACL, and the proper fix is simply
    # to apply the security descriptor from $ExpectedSDs.

    # NOTE:  This has a (hopefully desirable) side effect of limiting the number of output objects in the report.  If a parent
    # directory that's defined in the $ExpectedSD table has the wrong ACL, we'll only end up outputting that object.
    
    # Any child folders that are inheriting that bad ACL won't show up in the report, because they're doing what they're supposed
    # to be doing:  inheriting parent permissions (even if those permissions are wrong.)

    try
    {
        $_currentSD = [Microsoft.Experimental.IO.LongPathDirectory]::GetDacl($Path)
    }
    catch
    {
        $exception = Get-InnerException -ErrorRecord $_
        Write-Error "Error obtaining security descriptor for directory '$Path': $($exception.Message)"
        
        return
    }
    
    $explicitAces = $_currentSD.Access.Where({ -not $_.IsInherited })
    $currentSddl = DaclToString -SecurityDescriptor $_currentSD
    
    $_expectedSD = $ExpectedSD[$Path]
    
    if ($null -ne $_expectedSD)
    {
        $existsInExpectedSD = $true
        $sdIsCorrect = AreDiscretionaryAclsEqual -ReferenceObject $_expectedSD -CompareObject $_currentSD

        $expectedPermissionString = $_expectedSD.GetSecurityDescriptorSddlForm('Access')
    }
    else
    {
        $existsInExpectedSD = $false
        $sdIsCorrect = $explicitAces.Count -eq 0 -and -not $_currentSD.AreAccessRulesProtected
        $_expectedSD = $_currentSD

        $expectedPermissionString = '(Inherited from Parent)'

        $_expectedSD.SetAccessRuleProtection($false, $true)
        foreach ($ace in $explicitAces)
        {
            $_expectedSD.RemoveAccessRuleSpecific($ace)
        }
    }

    if ($CreateReport -and ($existsInExpectedSD -or -not $sdIsCorrect))
    {
        [pscustomobject] @{
            Path                = $Path
            ExpectedPermissions = $expectedPermissionString
            CurrentPermissions  = $currentSddl
            Correct             = $sdIsCorrect
        }
    }
    
    if ($FixPermissions -and -not $sdIsCorrect -and $PSCmdlet.ShouldProcess($Path, 'Update permissions'))
    {
        Write-Verbose "Correcting permissions for directory '$Path'..."

        try
        {
            [Microsoft.Experimental.IO.LongPathDirectory]::SetDacl($Path, $_expectedSD)
        }
        catch
        {
            $exception = Get-InnerException -ErrorRecord $_
            Write-Error "Error setting security descriptor for directory '$Path': $($exception.Message)"
        }
    }

} # function VisitDirectory

function VisitFile
{
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [string]
        $Path,
        
        [Parameter(Mandatory)]
        [hashtable]
        $ExpectedSD,
        
        [Parameter(Mandatory)]
        [System.Security.AccessControl.DirectorySecurity]
        $ParentSD,

        [switch]
        $CreateReport,

        [switch]
        $FixPermissions
    )

    # For files, we're just assuming that they should be inheriting permissions from the directories, period.
    # If any explicit ACEs are found or if inheritance is blocked, report and/or fix them.  If some parent folder
    # has the wrong permissions assigned, but the files are inheriting them, the file is treated as being
    # "correctly configured" for the purposes of the report.  When the parent directory's permission is fixed,
    # so will the file's.

    # As with the VisitDirectory function, I had trouble getting the "expected permissions" SDDL to display in the
    # report without actually committing the SD to disk first, so I've settled for just displaying "(Inherited from
    # Parent)" in the output object for that field.

    try
    {
        $securityDescriptor = [Microsoft.Experimental.IO.LongPathFile]::GetDacl($Path)
    }
    catch
    {
        $exception = Get-InnerException -ErrorRecord $_
        Write-Error "Error obtaining security descriptor for directory '$Path': $($exception.Message)"
        
        return
    }

    $explicitAces = $securityDescriptor.Access.Where({ -not $_.IsInherited })

    if ($explicitAces.Count -eq 0 -and -not $securityDescriptor.AreAccessRulesProtected)
    {
        return
    }

    $currentSddl = DaclToString -SecurityDescriptor $securityDescriptor

    $securityDescriptor.SetAccessRuleProtection($false, $true)
    foreach ($ace in $explicitAces)
    {
        $securityDescriptor.RemoveAccessRuleSpecific($ace)
    }

    if ($CreateReport)
    {
        [pscustomobject] @{
            Path                = $Path
            ExpectedPermissions = '(Inherited from Parent)'
            CurrentPermissions  = $currentSddl
            Correct             = $false
        }
    }
        
    if ($FixPermissions -and $PSCmdlet.ShouldProcess($Path, 'Update permissions'))
    {
        Write-Verbose "Correcting permissions for file '$Path'..."

        try
        {
            [Microsoft.Experimental.IO.LongPathFile]::SetDacl($Path, $securityDescriptor)
        }
        catch
        {
            $exception = Get-InnerException -ErrorRecord $_
            Write-Error "Error setting security descriptor for file '$Path': $($exception.Message)"
        }
    }

} # function VisitFile

function AreDiscretionaryAclsEqual
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemSecurity]
        $ReferenceObject,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemSecurity]
        $CompareObject
    )

    # For the purposes of this event, we consider ACLs equal if they are either both protected or both not protected, and
    # if all of their explicit ACEs are identical.

    if ($ReferenceObject.AreAccessRulesProtected -ne $CompareObject.AreAccessRulesProtected)
    {
        return $false
    }

    foreach ($ace in $ReferenceObject.Access)
    {
        if ($ace.IsInherited)
        {
            continue
        }

        $match = $CompareObject.Access.Where({
            -not $_.IsInherited -and
            $_.AccessControlType -eq $ace.AccessControlType -and
            $_.FileSystemRights -eq $ace.FileSystemRights -and
            $_.IdentityReference -eq $ace.IdentityReference -and
            $_.InheritanceFlags -eq $ace.InheritanceFlags -and
            $_.PropagationFlags -eq $ace.PropagationFlags
        })

        if ($match.Count -eq 0)
        {
            return $false
        }
    }

    foreach ($ace in $CompareObject.Access)
    {
        if ($ace.IsInherited)
        {
            continue
        }

        $match = $ReferenceObject.Access.Where({
            -not $_.IsInherited -and
            $_.AccessControlType -eq $ace.AccessControlType -and
            $_.FileSystemRights -eq $ace.FileSystemRights -and
            $_.IdentityReference -eq $ace.IdentityReference -and
            $_.InheritanceFlags -eq $ace.InheritanceFlags -and
            $_.PropagationFlags -eq $ace.PropagationFlags
        })

        if ($match.Count -eq 0)
        {
            return $false
        }
    }

    return $true
}

function ValidateInputFileSystemParameter
{
    # Ensures that the Path parameter is valid, exists, and is of the proper type (either File or Directory, depending on the
    # value of the PathType parameter).
    #
    # Either returns $true or throws an error; intended for use in ValidateScript blocks.
    
    # This function is not exported to the module's consumer.

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Path,

        [Parameter(Mandatory)]
        [string]
        $ParameterName,

        [ValidateSet('Leaf','Container')]
        [string]
        $PathType = 'Leaf'
    )

    if ($Path.IndexOfAny([System.IO.Path]::InvalidPathChars) -ge 0)
    {
        throw "$ParameterName argument contains invalid characters."
    }
    elseif (-not (Test-Path -LiteralPath $Path -PathType $PathType))
    {
        throw "$ParameterName '$Path' does not exist."
    }
    else
    {
        try
        {
            $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        }
        catch
        {
            $exception = Get-InnerException -ErrorRecord $_

            throw "Error reading ${ParameterName}: $($exception.Message)"
        }

        if ($PathType -eq 'Leaf')
        {
            $type = [System.IO.FileInfo]
            $name = 'File'
        }
        else
        {
            $type = [System.IO.DirectoryInfo]
            $name = 'Directory'
        }

        if ($item -isnot $type)
        {
            throw "$ParameterName '$Path' does not refer to a valid $name."
        }
        else
        {
            return $true
        }
    }
}

function DaclToString
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemSecurity]
        $SecurityDescriptor
    )

    # Creates an SDDL string which indicates whether the DACL is protected or not, and includes details of any
    # explicit ACEs.  (In other words, removes inherited ACEs from the normal output of
    # $SecurityDescriptor.GetSecurityDescriptorSddlForm('Access') ).

    $newSD = New-Object -TypeName ($SecurityDescriptor.GetType().FullName)

    $newSD.SetAccessRuleProtection($SecurityDescriptor.AreAccessRulesProtected, $false)

    $SecurityDescriptor.Access.Where({ -not $_.IsInherited }).ForEach({ $newSD.AddAccessRule($_) })

    return $newSD.GetSecurityDescriptorSddlForm('Access')
}

function New-TeamStructureInfo
{
    # Helper function for New-DepartmentStructureInfo

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Department,

        [Parameter(Mandatory)]
        [string]
        $Path,

        [Parameter(Mandatory)]
        [string]
        $Domain,

        [Parameter(Mandatory)]
        [string]
        $Team,

        [string[]]
        $AuditorGroups = @()
    )

    New-TeamFolderInfo -Department $Department -Path $Path -Domain $Domain -Team $Team

    $teamFolder = Join-Path -Path $Path -ChildPath "${Department}_$Team"

    New-TeamSharedFolderInfo -Path $teamFolder -Department $Department -Domain $Domain -Team $Team -AuditorGroups $AuditorGroups
    New-TeamPrivateFolderInfo -Path $teamFolder -Department $Department -Domain $Domain -Team $Team -AuditorGroups $AuditorGroups
    New-TeamLeadFolderInfo -Path $teamFolder -Department $Department -Domain $Domain -Team $Team -AuditorGroups $AuditorGroups
}

function New-DepartmentFolderInfo
{
    # Helper function for New-DepartmentStructureInfo

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Department,

        [Parameter(Mandatory)]
        [string]
        $Domain,

        [Parameter(Mandatory)]
        [string]
        $Path
    )

    #region Department folder
    
    $departmentPath = Join-Path -Path $Path -ChildPath $department

    $dirSec = New-Object System.Security.AccessControl.DirectorySecurity
    $dirSec.SetAccessRuleProtection($true, $false)

    $dirSec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        'BUILTIN\Administrators', 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
    )))

    $dirSec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        'NT AUTHORITY\Authenticated Users', 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
    )))

    [pscustomobject] @{
        Path = $departmentPath
        SecurityDescriptor = $dirSec
    }

    #endregion

    #region Department_Open folder

    $dirSec = New-Object System.Security.AccessControl.DirectorySecurity

    $dirSec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "$Domain\$Department", 'Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
    )))

    [pscustomobject] @{
        Path = Join-Path -Path $departmentPath -ChildPath "${Department}_Open"
        SecurityDescriptor = $dirSec
    }
    
    #endregion
}

function New-TeamFolderInfo
{
    # Helper function for New-DepartmentStructureInfo

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Department,

        [Parameter(Mandatory)]
        [string]
        $Team,

        [Parameter(Mandatory)]
        [string]
        $Domain,

        [Parameter(Mandatory)]
        [string]
        $Path,

        [string[]]
        $AuditorGroups = @()
    )

    #region Team folder

    $teamPath = Join-Path -Path $Path -ChildPath "${Department}_${Team}"

    $dirSec = New-Object System.Security.AccessControl.DirectorySecurity
    $dirSec.SetAccessRuleProtection($true, $false)

    $dirSec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        'BUILTIN\Administrators', 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
    )))

    $dirSec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "$Domain\$Department", 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
    )))

    foreach ($group in $AuditorGroups)
    {
        $dirSec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            "$Domain\$group", 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
        )))
    }

    [pscustomobject] @{
        Path = $teamPath
        SecurityDescriptor = $dirSec
    }
    
    #endregion
}

function New-TeamSharedFolderInfo
{
    # Helper function for New-DepartmentStructureInfo

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Department,

        [Parameter(Mandatory)]
        [string]
        $Team,

        [Parameter(Mandatory)]
        [string]
        $Domain,

        [Parameter(Mandatory)]
        [string]
        $Path,

        [string[]]
        $AuditorGroups = @()
    )

    #region TeamShared folder

    $teamSharedPath = Join-Path -Path $Path -ChildPath "$Team Shared Folder"

    $dirSec = New-Object System.Security.AccessControl.DirectorySecurity

    $dirSec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "$Domain\$Team", 'Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
    )))

    [pscustomobject] @{
        Path = $teamSharedPath
        SecurityDescriptor = $dirSec
    }
    
    #endregion
}

function New-TeamPrivateFolderInfo
{
    # Helper function for New-DepartmentStructureInfo

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Department,

        [Parameter(Mandatory)]
        [string]
        $Team,

        [Parameter(Mandatory)]
        [string]
        $Path,

        [Parameter(Mandatory)]
        [string]
        $Domain,

        [string[]]
        $AuditorGroups = @()

    )

    #region Team Private folder

    $teamPrivatePath = Join-Path -Path $Path -ChildPath "$Team Private Folder"

    $dirSec = New-Object System.Security.AccessControl.DirectorySecurity
    $dirSec.SetAccessRuleProtection($true, $false)

    $dirSec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        'BUILTIN\Administrators', 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
    )))

    $dirSec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "$Domain\$Team", 'Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
    )))

    foreach ($group in $AuditorGroups)
    {
        $dirSec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            "$Domain\$group", 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
        )))
    }

    [pscustomobject] @{
        Path = $teamPrivatePath
        SecurityDescriptor = $dirSec
    }
    
    #endregion
}

function New-TeamLeadFolderInfo
{
    # Helper function for New-DepartmentStructureInfo

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Department,

        [Parameter(Mandatory)]
        [string]
        $Team,

        [Parameter(Mandatory)]
        [string]
        $Domain,

        [Parameter(Mandatory)]
        [string]
        $Path,

        [string[]]
        $AuditorGroups = @()
    )

    #region Team Lead folder

    $teamLeadPath = Join-Path -Path $Path -ChildPath "$Team Lead Folder"

    $dirSec = New-Object System.Security.AccessControl.DirectorySecurity
    $dirSec.SetAccessRuleProtection($true, $false)

    $dirSec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        'BUILTIN\Administrators', 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
    )))

    $dirSec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "$Domain\${Team}_lead", 'Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
    )))

    foreach ($group in $AuditorGroups)
    {
        $dirSec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            "$Domain\$group", 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
        )))
    }

    [pscustomobject] @{
        Path = $teamLeadPath
        SecurityDescriptor = $dirSec
    }
    
    #endregion
}

$functions = @(
    'Test-DepartmentGroups', 'New-DepartmentStructureInfo', 'New-FolderStructure',
    'Test-DirectoryTreePermission', 'Repair-DirectoryTreePermission', 'Get-InnerException',
    'Get-CallerPreference'
)

Export-ModuleMember -Function $functions