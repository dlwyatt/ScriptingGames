<#
.Synopsis
   Collects security footprint information.
.DESCRIPTION
   Collects security footprint information from the local computer, compresses and encrypts the results, and uploads them to a file share.
   The encryption requires one or more RSA certificates in the current user's certificate store.  Only the public key is required to run this script, though the private key is required for the IT Security staff to decrypt the files later.
.PARAMETER CertificateThumbprint
   One or more RSA certificate thumbprints in string form.  The corresponding certificates must be present in the current user's certificate store, and must not be expired.
.PARAMETER UploadPath
   The location where the encrypted security footprint data should be copied.  The current user must have permission to this location, and it must refer to a directory that already exists.
.PARAMETER LogFile
   The file which should receive a copy of the console output produced by the script (including timestamps.)
.PARAMETER Folder
   Causes the script to collect file counts and total size for all files on local hard disks.
.PARAMETER File
   Causes the script to collect detailed file information for files in the directories specified by the FilePaths parameter.
.PARAMETER Share
   Causes the script to collect a list of shared folders from the computer.
.PARAMETER Process
   Causes the script to collect a list of running processes.
.PARAMETER Service
   Causes the script to collect information about Windows services.
.PARAMETER Environment
   Causes the script to collect the values of the System environment variables.
.PARAMETER Registry
   Causes the script to collect certain registry data, such as the Run keys.
.PARAMETER InstalledSoftware
   Causes the script to collect information about installed programs.
.PARAMETER FileHash
   When the File switch is set, the FileHash switch causes the script to also save SHA256 hashes of the files it examines.
.PARAMETER FilePaths
   One or more directories that should be examined when the File switch is set.
.PARAMETER FileRecurse
   Causes the script to search all subdirectories of the paths in the FilePaths parameter when performing File collection.
.PARAMETER FileForce
   Causes the script to collect information about Hidden / System files when performing File collection.
.EXAMPLE
   .\UploadSecurityFootprint.ps1 -UploadPath '\\server\share\SecurityFootprints\' -CertificateThumbprint AB06BF2C9B61D687FFB445003C2AFFAB0C81DFF9 -LogFile c:\Logs\UploadSecurityFootprint.log -FilePaths 'c:\windows\system32' -FileHash -Verbose

   Performs a full data collection from the local computer, including file hashes of files in the c:\windows\system32 directory, and uploads the results to \\server\share\securityfootprints\ .  The private key of certificate AB06BF2C9B61D687FFB445003C2AFFAB0C81DFF9 will be required to decrypt the results.
   A log of all script activity will be kept in c:\Logs\UploadSecurityFootprint.log.  If the file already exists, the script will append to it.
.EXAMPLE
   .\UploadSecurityFootprint.ps1 -UploadPath '\\server\share\SecurityFootprints\' -CertificateThumbprint 'AB06BF2C9B61D687FFB445003C2AFFAB0C81DFF9','8E6A22DB9C6A56324E63F86F231765CC8B1A52C8' -InstalledSoftware -Process -Service

   Like Example 1, except this time the script only collects information about installed software, services, and running processes.  No log file is created, and the data is protected by two certificates instead of one.  It can be decrypted by either certificate's private key.
.INPUTS
   None.  This script does not accept pipeline input.
.OUTPUTS
   None.  This script does not produce pipeline output.
.NOTES
   The script requires the Event2.psm1 module, which for Games purposes, must be present in the same folder as the script.
   When the LogFile parameter is used, this script requires the PSLogging module from http://gallery.technet.microsoft.com/Enhanced-Script-Logging-27615f85 .  As with the Event2 module, the PSLogging module's folder must also be in the script's directory.
#>

#requires -Version 4.0
#requires -RunAsAdministrator

[CmdletBinding(DefaultParameterSetName = 'All')]
param (
    [Parameter(Mandatory)]
    [string[]]
    $CertificateThumbprint,

    [Parameter(Mandatory)]
    [string]
    $UploadPath,

    [string]
    $LogFile,

    [Parameter(ParameterSetName = 'Individual')]
    [switch]
    $Folder,

    [Parameter(ParameterSetName = 'Individual')]
    [switch]
    $File,

    [Parameter(ParameterSetName = 'Individual')]
    [switch]
    $Share,

    [Parameter(ParameterSetName = 'Individual')]
    [switch]
    $Process,

    [Parameter(ParameterSetName = 'Individual')]
    [switch]
    $Service,

    [Parameter(ParameterSetName = 'Individual')]
    [switch]
    $Environment,

    [Parameter(ParameterSetName = 'Individual')]
    [switch]
    $Registry,

    [Parameter(ParameterSetName = 'Individual')]
    [switch]
    $InstalledSoftware,

    [ValidateNotNullOrEmpty()]
    [string[]]
    $FilePaths = @(),

    [switch]
    $FileHash,

    [switch]
    $FileRecurse,

    [switch]
    $FileForce
) # param

function Collect-Data
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [scriptblock]
        $ScriptBlock,

        [Parameter(Mandatory)]
        [string]
        $OutputPath,

        [Parameter(Mandatory)]
        [string]
        $OutputFile,

        [hashtable]
        $Params = @{},

        [string]
        $Activity
    )

    $_filePath = Join-Path -Path $OutputPath -ChildPath $OutputFile

    if (-not [string]::IsNullOrEmpty($Activity))
    {
        Write-Verbose "Starting activity '$Activity'..."
    }

    try
    {
        & $ScriptBlock @Params |
        Export-Clixml -LiteralPath $_filePath
    }
    catch
    {
        Write-Error -ErrorRecord $_
    }

    if (-not [string]::IsNullOrEmpty($Activity))
    {
        Write-Verbose "Activity '$Activity' complete."
    }
}

$All = ($PSCmdlet.ParameterSetName -eq 'All')

#region Enable Logging

if (-not [string]::IsNullOrEmpty($LogFile))
{
    try
    {
        Import-Module -Name $PSScriptRoot\PSLogging -ErrorAction Stop
    }
    catch
    {
        throw "When using the LogFile parameter, this script requires the PSLogging module from http://gallery.technet.microsoft.com/Enhanced-Script-Logging-27615f85 ."
    }

    $logObject = Add-LogFile -Path $LogFile -StreamType All
}

#endregion

try
{
    #region Load dependencies

    Write-Verbose 'Loading script dependencies.'

    try
    {
        Import-Module -Name $PSScriptRoot\Event2.psm1 -ErrorAction Stop
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    }
    catch
    {
        $exception = Get-InnerException -ErrorRecord $_    
        throw "Error loading script dependencies: $($exception.Message)"
    }

    #endregion

    #region Validate Input

    # Input validation is performed here instead of in Validate blocks on the script parameters so the resulting errors (if any) will be contained in the log file.
    foreach ($thumbprint in $CertificateThumbprint)
    {
        $cert = Get-ChildItem -LiteralPath cert:\CurrentUser -Include $thumbprint -Recurse |
                Where-Object {
                    $_.PublicKey.Key -is [System.Security.Cryptography.RSACryptoServiceProvider] -and
                    $_.NotBefore -lt (Get-Date) -and $_.NotAfter -gt (Get-Date)
                }
        
        if ($null -eq $cert)
        {
            throw "CertificateThumbprint '$thumbprint' does not refer to a valid RSA certificate in the current user's certificate store."
        }
    }

    $resolvedPath = Resolve-Path -LiteralPath $UploadPath -ErrorAction Ignore
    
    if ($null -eq $resolvedPath -or $resolvedPath.Provider.Name -ne 'FileSystem' -or -not (Test-Path -LiteralPath $resolvedPath.Path -PathType Container))
    {
        throw "UploadPath directory '$UploadPath' does not exist."
    }

    #endregion

    #region Data collection

    Write-Verbose 'Creating temporary folder.'
    $tempFolder = New-TempFolder -ErrorAction Stop
    Write-Verbose "XML files will be temporarily stored in folder '$tempFolder'"

    if ($All -or $Folder)
    {
        Collect-Data -ScriptBlock ${function:Get-FolderData} -OutputPath $tempFolder -OutputFile 'FolderInfo.xml' -Activity 'Collect folder information'
    }

    if ($All -or $File)
    {
        if ($FilePaths.Count -eq 0)
        {
            Write-Error "The File collection option was requested, but no values were passed to the FilePaths parameter.  No file information will be collected."
        }
        else
        {
            Collect-Data -ScriptBlock ${function:Get-FileData} -OutputPath $tempFolder -OutputFile 'FileInfo.xml' -Activity 'Collect file information' -Params @{
                Path    = $FilePaths
                GetHash = $FileHash
                Recurse = $FileRecurse
                Force   = $FileForce
            }
        }
    }

    if ($All -or $Share)
    {
        Collect-Data -ScriptBlock ${function:Get-SharedFolderData} -OutputPath $tempFolder -OutputFile 'SharedFolderInfo.xml' -Activity 'Collect shared folder information'
    }

    if ($All -or $Process)
    {
        Collect-Data -ScriptBlock ${function:Get-ProcessData} -OutputPath $tempFolder -OutputFile 'ProcessInfo.xml' -Activity 'Collect running process information'
    }

    if ($All -or $Service)
    {
        Collect-Data -ScriptBlock ${function:Get-ServiceData} -OutputPath $tempFolder -OutputFile 'ServiceInfo.xml' -Activity 'Collect Windows service information'
    }

    if ($All -or $Environment)
    {
        Collect-Data -ScriptBlock ${function:Get-EnvironmentVariableData} -OutputPath $tempFolder -OutputFile 'EnvironmentVariables.xml' -Activity 'Collect environment variables'
    }

    if ($All -or $Registry)
    {
        Collect-Data -ScriptBlock ${function:Get-RegistryData} -OutputPath $tempFolder -OutputFile 'RegistryInfo.xml' -Activity 'Collect registry information'
    }

    if ($All -or $InstalledSoftware)
    {
        Collect-Data -ScriptBlock ${function:Get-InstalledSoftwareData} -OutputPath $tempFolder -OutputFile 'InstalledSoftware.xml' -Activity 'Collect list of installed software'
    }

    if (@(Get-ChildItem -LiteralPath $tempFolder).Count -eq 0)
    {
        Remove-Item -Path $tempFolder -Force -ErrorAction Ignore
        throw "No data was output to the temporary folder; nothing will be uploaded to the central share."
    }

    #endregion

    #region Compression / Encryption / Upload

    Write-Verbose 'Compressing, encrypting and uploading results...'

    $zipFile = [System.IO.Path]::GetTempFileName()
    $encryptedFile = [System.IO.Path]::GetTempFileName()
    
    Write-Verbose "Unencrypted zip file will be temporarily stored at '$zipFile'."
    Write-Verbose "Local copy of encrypted bin file will be temporarily stored at '$encryptedFile'."

    Compress-Folder -FolderPath $tempFolder -OutputFile $zipFile -ErrorAction Stop
    Protect-File -FilePath $zipFile -OutputFile $encryptedFile -CertificateThumbprint $CertificateThumbprint -ErrorAction Stop
    
    Write-Debug (
        "`r`n  {0,-30} : {1:D}`r`n  {2,-30} : {3:D}`r`n  {4,-30} : {5:D}" -f
        'Original XML files size', [uint64](Get-ChildItem -LiteralPath $tempFolder -File | Measure-Object -Property Length -Sum).Sum,
        'Compressed file size'   , (Get-Item -LiteralPath $zipFile).Length,
        'Encrypted file size'    , (Get-Item -LiteralPath $encryptedFile).Length
    )

    $dest = Join-Path -Path $UploadPath -ChildPath "$env:COMPUTERNAME-SecurityFootprint-$(Get-Date -Format yyyy_MM_dd_HH_mm_ss).bin"
    Copy-Item -LiteralPath $encryptedFile -Destination $dest -ErrorAction Stop

    Write-Verbose "Encrypted results successfully uploaded to '$dest'."

    #endregion
}
finally
{
    #region Clean up local files and disable logging.

    Write-Verbose 'Cleaning up local temp files.'

    if (-not [string]::IsNullOrEmpty($tempFolder))
    {
        Remove-Item -LiteralPath $tempFolder -Recurse -Force
    }
    
    if (-not [string]::IsNullOrEmpty($zipFile))
    {
        Remove-Item -LiteralPath $zipFile -Force
    }

    if (-not [string]::IsNullOrEmpty($encryptedFile))
    {
        Remove-Item -LiteralPath $encryptedFile -Force
    }

    if ($null -ne $logObject)
    {
        Disable-LogFile -InputObject $logObject
    }

    #endregion
}
