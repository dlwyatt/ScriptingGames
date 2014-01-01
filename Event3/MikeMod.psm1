#requires -Version 4.0

function Create-FolderStructureAD 
{
    <#
    .SYNOPSIS
        Creates departmental folder structure on a fileshare based on Active Directory group memberships.
    .DESCRIPTION
        Creates departmental folder structure on a fileshare based on Active Directory group memberships.

        Takes an array of Active Directory department group names and a fileshare location to create the folder structure.
        Group names may be passed in via the pipeline.
    .PARAMETER DepartmentList
        Specifies the Active Directory department group names.
        If left empty, the Finance department will be used.
    .PARAMETER FileSharePath
        Specifies the path of the fileshare location where the departmental folder structure will be created.
    .INPUTS
        Accepts a string array of Active Directory group names and a string for fileshare location.
    .OUTPUTS
        Nothing.
    .EXAMPLE
        Create-FolderStructureAD -FileSharePath \\file\share

        Creates a folder structure for the Finance Active Directory group in the specified location.
    .EXAMPLE
        Create-FolderStructureAD -DepartmentList 'Executive Team','Information Technology','Sales' -FileSharePath \\file\share

        Creates a folder structure for the Executive Team, Information Technology, and Sales Active Directory groups in the specified location.
    .EXAMPLE
        'Payroll','Marketing','Office Administration' | Create-FolderStructureAD -FileSharePath \\file\share

        Creates a folder structure for the Payroll, Marketing, and Office Administration Active Directory groups in the specified location.
    #>

    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [string[]]
        $DepartmentList = @('Finance'),

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory)]
        [string]
        $FileSharePath,

        [Parameter()]
        [string[]]
        $AuditorList
    )

    begin 
    {
        if (-not (Test-Path $FileSharePath))
        {
            Write-Error "$FileSharePath not found. Check input and try again."
            break
        }
    }

    process 
    {

        # AUDITOR PERMISSIONS......
        
        foreach ($department in $DepartmentList)
        {
            try 
            {           
                $teamList = Get-ADGroupMember -Identity $department | Where ObjectClass -eq 'group'
            }

            catch
            {
                Write-Error "$department group not found in Active Directory. Check the department information and try again."
                continue
            }

            If ($AuditorList)
            {
                If ($teamList.Name -notcontains $AuditorList)
                {
                    Write-Error 'At least one of the specified Auditor groups was not found. Check the input and try again.'
                    break
                }
            }

            Write-Verbose "Creating folder structure for $department department."

            $rootPath = Join-Path -Path $FileSharePath -ChildPath $department

            if (-not (Test-Path ($rootPath)))
            {
            
                Write-Verbose "Creating $department directory in $FileSharePath"
                New-Item -Path $rootPath -ItemType Directory | Out-Null
                Set-FolderPermission -Folder $rootPath -GroupList $department -PermissionLevel Read -NoInherit
                Set-FolderPermission -Folder $rootPath -GroupList 'Domain Admins' -PermissionLevel FullControl -NoInherit
            
            }

            New-Item -Path (Join-Path -Path $rootPath -ChildPath "$($department)_Open") -ItemType Directory | Out-Null
            Set-FolderPermission -Folder (Join-Path -Path $rootPath -ChildPath "$($department)_Open") -GroupList 'Domain Users' -PermissionLevel Read
            Set-FolderPermission -Folder (Join-Path -Path $rootPath -ChildPath "$($department)_Open") -GroupList $department -PermissionLevel Modify
            Set-FolderPermission -Folder (Join-Path -Path $rootPath -ChildPath "$($department)_Open") -GroupList 'Domain Admins' -PermissionLevel FullControl

            foreach ($team in $teamList)
            {
            
                #Create dirs
                $teamPath = Join-Path -Path $rootPath -ChildPath "$($department)_$($team.Name)"
                New-Item -Path ($teamPath) -ItemType Directory | Out-Null
                New-Item -Path (Join-Path -Path $teamPath -ChildPath "$($team.Name) Shared Folder") -ItemType Directory | Out-Null
                New-Item -Path (Join-Path -Path $teamPath -ChildPath "$($team.Name) Private Folder") -ItemType Directory | Out-Null
                New-Item -Path (Join-Path -Path $teamPath -ChildPath "$($team.Name) Lead Folder") -ItemType Directory | Out-Null

                #Set perms
                Set-FolderPermission -Folder (Join-Path -Path $teamPath -ChildPath "$($team.Name) Shared Folder") -GroupList $team.Name -PermissionLevel Modify
                Set-FolderPermission -Folder (Join-Path -Path $teamPath -ChildPath "$($team.Name) Shared Folder") -GroupList $department -PermissionLevel Read
                Set-FolderPermission -Folder (Join-Path -Path $teamPath -ChildPath "$($team.Name) Shared Folder") -GroupList 'Domain Admins' -PermissionLevel FullControl

                Set-FolderPermission -Folder (Join-Path -Path $teamPath -ChildPath "$($team.Name) Private Folder") -GroupList $team.Name -PermissionLevel Modify -NoInherit
                Set-FolderPermission -Folder (Join-Path -Path $teamPath -ChildPath "$($team.Name) Private Folder") -GroupList 'Domain Admins' -PermissionLevel FullControl -NoInherit

                Set-FolderPermission -Folder (Join-Path -Path $teamPath -ChildPath "$($team.Name) Lead Folder") -GroupList "$($team.Name)_lead" -PermissionLevel Modify -NoInherit
                Set-FolderPermission -Folder (Join-Path -Path $teamPath -ChildPath "$($team.Name) Lead Folder") -GroupList 'Domain Admins' -PermissionLevel FullControl -NoInherit


            }
        }
    }
}


function Create-FolderStructureInput 
{
    <#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER 

    .PARAMETER

    .INPUTS

    .OUTPUTS

    .EXAMPLE

    #>

    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [string[]]
        $DepartmentList = 'Finance',

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory)]
        [string[]]
        $TeamList,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory)]
        [string]
        $FileSharePath,

        [Parameter()]
        [string[]]
        $AuditorList
    )

    begin 
    {
        if (-not (Test-Path $FileSharePath))
        {
            Write-Error "$FileSharePath not found. Check input and try again."
            break
        }
    }

    process 
    {
        
        # AUDITOR PERMISSIONS HAVE NOT BEEN DONE YET
        
        foreach ($department in $DepartmentList)
        {
            Write-Verbose "Creating folder structure for $department department."

            $rootPath = Join-Path -Path $FileSharePath -ChildPath $department

            if (-not (Test-Path ($rootPath)))
            {           
                Write-Verbose "Creating $department directory in $FileSharePath"
                New-Item -Path $rootPath -ItemType Directory | Out-Null
                Set-FolderPermission -Folder $rootPath -GroupList $department -PermissionLevel Read -NoInherit
                Set-FolderPermission -Folder $rootPath -GroupList 'Domain Admins' -PermissionLevel FullControl -NoInherit           
            }

            New-Item -Path (Join-Path -Path $rootPath -ChildPath "$($department)_Open") -ItemType Directory | Out-Null
            Set-FolderPermission -Folder (Join-Path -Path $rootPath -ChildPath "$($department)_Open") -GroupList 'Domain Users' -PermissionLevel Read
            Set-FolderPermission -Folder (Join-Path -Path $rootPath -ChildPath "$($department)_Open") -GroupList $department -PermissionLevel Modify
            Set-FolderPermission -Folder (Join-Path -Path $rootPath -ChildPath "$($department)_Open") -GroupList 'Domain Admins' -PermissionLevel FullControl

            foreach ($team in $teamList)
            {            
                Write-Verbose "Creating folders for $team"
                $teamPath = Join-Path -Path $rootPath -ChildPath "$($department)_$team"
                New-Item -Path ($teamPath) -ItemType Directory | Out-Null
                New-Item -Path (Join-Path -Path $teamPath -ChildPath "$team Shared Folder") -ItemType Directory | Out-Null
                New-Item -Path (Join-Path -Path $teamPath -ChildPath "$team Private Folder") -ItemType Directory | Out-Null
                New-Item -Path (Join-Path -Path $teamPath -ChildPath "$team Lead Folder") -ItemType Directory | Out-Null

                #Set perms
                Set-FolderPermission -Folder (Join-Path -Path $teamPath -ChildPath "$team Shared Folder") -GroupList $team -PermissionLevel Modify
                Set-FolderPermission -Folder (Join-Path -Path $teamPath -ChildPath "$team Shared Folder") -GroupList $department -PermissionLevel Read
                Set-FolderPermission -Folder (Join-Path -Path $teamPath -ChildPath "$team Shared Folder") -GroupList 'Domain Admins' -PermissionLevel FullControl

                Set-FolderPermission -Folder (Join-Path -Path $teamPath -ChildPath "$($team.Name) Private Folder") -GroupList $team -PermissionLevel Modify -NoInherit
                Set-FolderPermission -Folder (Join-Path -Path $teamPath -ChildPath "$($team.Name) Private Folder") -GroupList 'Domain Admins' -PermissionLevel FullControl -NoInherit

                Set-FolderPermission -Folder (Join-Path -Path $teamPath -ChildPath "$($team.Name) Lead Folder") -GroupList "$($team)_lead" -PermissionLevel Modify -NoInherit
                Set-FolderPermission -Folder (Join-Path -Path $teamPath -ChildPath "$($team.Name) Lead Folder") -GroupList 'Domain Admins' -PermissionLevel FullControl -NoInherit
            }

            if ($AuditorList)
            {
                foreach ($auditor in $AuditorList)
                {
                    Write-Verbose "Creating folders for $auditor"
                    $teamPath = Join-Path -Path $rootPath -ChildPath "$($department)_$auditor"
                    New-Item -Path ($teamPath) -ItemType Directory | Out-Null
                    New-Item -Path (Join-Path -Path $teamPath -ChildPath "$auditor Shared Folder") -ItemType Directory | Out-Null
                    New-Item -Path (Join-Path -Path $teamPath -ChildPath "$auditor Private Folder") -ItemType Directory | Out-Null
                    New-Item -Path (Join-Path -Path $teamPath -ChildPath "$auditor Lead Folder") -ItemType Directory | Out-Null

                }
            }
        }
    }
}

function Set-FolderPermission
{
    <#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER 

    .PARAMETER 

    .INPUTS

    .OUTPUTS

    .EXAMPLE
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]
        [string]
        $Folder,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory)]
        [string[]]
        $GroupList,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory)]
        [string]
        $PermissionLevel,

        [Parameter()]
        [switch]
        $NoInherit, 

        [Parameter()]
        [switch]
        $NoPropagate # Not really sure how to control this yet
    )

    process 
    {

        foreach ($group in $GroupList)
        {

            $acl = Get-Acl $Folder

            If ($NoInherit)
            {
                $acl.SetAccessRuleProtection($True, $False)
            }
            
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$group","$PermissionLevel", "ContainerInherit, ObjectInherit", "None", "Allow")
            $acl.AddAccessRule($rule)

            Set-Acl $Folder $acl

        }
    }
}