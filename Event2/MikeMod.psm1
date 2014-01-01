function Get-ProcessData {
    [CmdletBinding()]
    param ( )

    Get-Process | 
    Select-Object -Property Name,Path
}

function Get-ServiceData {
    [CmdletBinding()]
    param ( )

    $props = 'Name', 'Caption', 'PathName', 'StartMode'

    Get-CimInstance -ClassName Win32_Service -Filter 'State = "Running"' -Property $props | 
    Select-Object -Property $props
}

function Get-InstalledSoftwareData
{
    [CmdletBinding()]
    param ( )

    $rootPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    foreach ($path in $rootPaths)
    {
        if (-not (Test-Path -LiteralPath $path))
        {
            continue
        }

        $subkeys = Get-ChildItem -LiteralPath $path

        foreach ($subkey in $subkeys)
        {
            $details = Get-ItemProperty -LiteralPath $subkey.PSPath

            if ([string]::IsNullOrEmpty($details.DisplayName))
            {
                return
            }

            [pscustomobject] @{
                DisplayName     = $details.DisplayName
                DisplayVersion  = $details.DisplayVersion
                Publisher       = $details.Publisher
                InstallDate     = $details.InstallDate
                InstallLocation = $details.InstallLocation
            }
        }

    } # foreach ($path in $rootPaths)

} # function Get-InstalledSoftwareData

function Get-EnvironmentVariableData
{
    [CmdletBinding()]
    param ( )
    
    [pscustomobject] ([System.Environment]::GetEnvironmentVariables('Machine'))
}

function Get-SharedFolderData
{
    [CmdletBinding()]
    param ( )

    $props = 'Name', 'Path', 'Description'

    Get-CimInstance -ClassName Win32_Share -Property $props |
    Select-Object -Property $props
}

function Get-RegistryData
{
    [CmdletBinding()]
    param ( )

    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    foreach ($regKeyPath in $paths)
    {
        if (-not (Test-Path -LiteralPath $regKeyPath))
        {
            continue
        }

        try
        {
            $key = Get-Item -LiteralPath $regKeyPath -ErrorAction Stop
        }
        catch
        {
            $exception = Get-InnerException -ErrorRecord $_
            Write-Error "Error reading registry key '$regKeyPath': $($exception.Message)"

            continue
        }

        $props = @{
            Path = $regKeyPath
        }

        foreach ($valueName in $key.Property)
        {
            $props[$valueName] = $key.GetValue($valueName)
        }

        if ($props.PSBase.Count -gt 1)
        {
            [pscustomobject]$props
        }

    } # foreach ($regKeyPath in $paths)

} # function Get-RegistryData

function Get-FileData
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]
        $Path,

        [switch]
        $GetHash
    )

    process
    {
        foreach ($_path in $Path)
        {
            Get-ChildItem -LiteralPath $_path -File |
            ForEach-Object {
                $file = $_

                $props = @{
                    FullName = $file.FullName
                    Length = $file.Length
                    LastWriteTime = $file.LastWriteTime
                }

                if ($GetHash)
                {
                    try
                    {
                        $hash = Get-FileHash -LiteralPath $_.FullName -ErrorAction Stop
                    
                        $props['Hash'] = $hash.Hash
                        $props['ErrorMessage'] = $null
                    }
                    catch
                    {
                        $exception = Get-InnerException -ErrorRecord $_
                    
                        $props['Hash'] = $null
                        $props['ErrorMessage'] = $exception.Message
                    }                
                }

                [pscustomobject] $props

            } # ForEach-Object

        } # foreach ($_path in $Path)

    } # process    

} # function Get-FileData

