#requires -Version 4.0

function Get-ProcessData 
{
    <#
    .SYNOPSIS
        Returns specific details for running processes.
    .DESCRIPTION
        This function collects specific information about running processes.
        Name and Path information is returned.
    .EXAMPLE
        Get-ProcessData
    #>
    
    [CmdletBinding()]
    param ( )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    Get-Process | 
    Select-Object -Property Name,Path
}

function Get-ServiceData 
{
    <#
    .SYNOPSIS
        Returns specific details for running services.
    .DESCRIPTION
        This function collects specific information about running services.
        Name, Path, Start Mode, and the Caption information is returned.
    .EXAMPLE
        Get-ServiceData
    #>
   
    [CmdletBinding()]
    param ( )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $props = 'Name', 'Caption', 'PathName', 'StartMode'

    Get-CimInstance -ClassName Win32_Service -Filter 'State = "Running"' -Property $props | 
    Select-Object -Property $props
}

function Get-InstalledSoftwareData
{
    <#
    .SYNOPSIS
        Returns information about software installed on the local PC.
    .DESCRIPTION
        This function collects specific information about running services.
        Name, Path, Start Mode, and the Caption information is returned.
    .EXAMPLE
        Get-InstalledSoftwareData
    .NOTES
        The Uninstall registry key is used to gather this information.
        The Wow6432Node Uninstall registry key is also included for x64 OS installations.
        This key will be ignored on x86 installations.
    #>

    [CmdletBinding()]
    param ( )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

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
                continue
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
    <#
    .SYNOPSIS
        Returns system environment variables.
    .DESCRIPTION
        This function collects information about system environment variables.
    .EXAMPLE
        Get-EnvironmentVariableData
    #>

    [CmdletBinding()]
    param ( )
    
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    try
    {
        $hashTable = [System.Environment]::GetEnvironmentVariables('Machine')
        [pscustomobject] $hashTable
    }
    catch
    {
        Write-Error -ErrorRecord $_
    }

}

function Get-SharedFolderData
{
    <#
    .SYNOPSIS
        Returns specific details about shared folders on the local PC.
    .DESCRIPTION
        This function collects specific information about shared folders on the local PC.
        Name, Path, and Description information is returned.
    .EXAMPLE
        Get-SharedFolderData
    #>

    [CmdletBinding()]
    param ( )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $props = 'Name', 'Path', 'Description'

    # Shares of type 1 are printers; we're ignoring those.

    Get-CimInstance -ClassName Win32_Share -Property $props -Filter 'Type <> 1' |
    Select-Object -Property $props
}

function Get-RegistryData
{
    <#
    .SYNOPSIS
        Returns information about information contained in registry keys.
    .DESCRIPTION
        This function collects information about softeware that is set to run automatically via registry keys.
        All values found in these keys are returned.
    .EXAMPLE
        Get-RegistryData
    .NOTES
        HKEY_LOCAL_MACHINE Run and RunOnce registry keys are used to gather this information.
    #>

    [CmdletBinding()]
    param ( )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

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
    <#
    .Synopsis
       Gets information about files in specified folders.
    .DESCRIPTION
       Collects the path, size, last modified date, and optionally the SHA256 hash code for all files in one or more user-specified folders.
    .PARAMETER Path
       One or more directory paths to be searched.
    .PARAMETER GetHash
       Switch parameter that causes the command to attempt to generate hash codes for each of the files in the specified Path.
    .EXAMPLE
       Get-Content .\Directories.txt | Get-FileInfo -GetHash

       Searches the folders listed in the Directories.txt file.  All files found will include hash codes.
    .EXAMPLE
       Get-FileInfo -Path c:\windows\system32 -Recurse

       Gets basic file info (not including hash code) for all files in the C:\Windows\System32 directory (including all subdirectories.)
    .INPUTS
       String
    .OUTPUTS
       PSObject
    .NOTES
       The output objects contain an ErrorMessage field; if any problems were encountered when obtaining directory
       listings or reading files to obtain their hash code, they will be recorded in this property.  It is possible for
       the Hash, Length and/or LastWriteTime properties to be null, if errors occurred that prevented the command from
       gathering those data points.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]
        $Path,

        [switch]
        $GetHash,

        [switch]
        $Recurse,

        [switch]
        $Force
    )

    begin
    {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    }

    process
    {
        foreach ($_path in $Path)
        {
            if (-not (Test-Path -LiteralPath $_path -PathType Container))
            {
                Write-Warning "Get-FileData: Directory '$_path' does not exist."
                continue
            }

            Get-ChildItem -LiteralPath $_path -File -Recurse:$Recurse -Force:$Force -ErrorAction SilentlyContinue -ErrorVariable err |
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

            foreach ($record in $err)
            {
                $exception = Get-InnerException -ErrorRecord $_

                $props = @{
                    FullName = $record.TargetObject
                    Length = $null
                    LastWriteTime = $null
                    ErrorMessage = $exception.Message
                }

                if ($GetHash)
                {
                    $props['Hash'] = $null
                }

                [pscustomobject] $props
            }

        } # foreach ($_path in $Path)

    } # process    

} # function Get-FileData

function Get-FolderData
{
    <#
    .Synopsis
       Collects file count and size information from local drives.
    .DESCRIPTION
       For each folder in the file system of all fixed disks, outputs an object containing the path, file count, and total file size in the folder.  If errors occur when reading either the folder or the files within it, the object output for that folder will contain only the path and an error message.
    .EXAMPLE
       Get-FolderInfo
    .INPUTS
       None.  This command does not accept pipeline input.
    .OUTPUTS
       PSCustomObject
    .NOTES
       Enumerating all directories on the file system can take several minutes, and there is no way for the command to know ahead of time how many it has to process; therefore, there is no progress output.

       The objects output by this command have four properties:

       Path
       FileCount
       FileSize
       Error

       For most folders, Path, FileCount and FileSize will be populated, and Error will be null.  If the command encounters an error reading a particular folder or file, instead, Path and Error will be populated, and FileCount / FileSize will be null.
    #>

    [CmdletBinding()]
    param ( )

    filter FolderInfoFilter
    {
        $Directory = $_

        try
        {
            $measureInfo = $Directory.EnumerateFiles() | Measure-Object -Property Length -Sum

            [pscustomobject] @{
                Path = $Directory.FullName
                FileCount = $measureInfo.Count
                Size = [int64] $measureInfo.Sum
                Error = $null
            }
        }
        catch
        {
            $exception = Get-InnerException -ErrorRecord $_

            [pscustomobject] @{
                Path = $Directory.FullName
                FileCount = $null
                Size = $null
                Error = $exception.Message
            }
        }

    } # filter FolderInfoFilter

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    foreach ($drive in [System.IO.DriveInfo]::GetDrives())
    {
        if ($drive.DriveType -ne [System.IO.DriveType]::Fixed)
        {
            continue
        }

        $gciParams = @{
            LiteralPath = $drive.RootDirectory
            Directory = $true
            Recurse = $true
            Force = $true
            Attributes = '!ReparsePoint'
        }

        Get-ChildItem @gciParams -ErrorVariable gciErrors -ErrorAction SilentlyContinue |
        FolderInfoFilter

        foreach ($record in $gciErrors)
        {
            # PowerShell occasionally sticks Exceptions into the ErrorVariable instead of ErrorRecords, when terminating errors occur.
            # They're always duplicates for an ErrorRecord that is also in the collection, so if that happens here, we'll just ignore
            # them.

            if ($record -isnot [System.Management.Automation.ErrorRecord])
            {
                continue
            }

            $exception = Get-InnerException -ErrorRecord $record

            [pscustomobject] @{
                Path = $record.TargetObject
                FileCount = $null
                Size = $null
                Error = $exception.Message
            }
        }

    } # foreach ($drive in [System.IO.DriveInfo]::GetDrives())

} # function Get-FolderData

function New-TempFolder
{
    <#
    .Synopsis
       Creates a new temporary folder.
    .DESCRIPTION
       Finds an unused temporary folder name in the current user's %TEMP% directory, and attempts to create it.  If the folder creation was successful, the command returns the path to the new folder.
    .EXAMPLE
       $tempFolder = New-TempFolder

       Creates a new temporary folder and assigns its path to the $tempFolder variable.
    .INPUTS
       None.  This command does not accept pipeline input.
    .OUTPUTS
       String
    .NOTES
       If an error occurs while creating the folder, the command will throw a terminating error.
    #>

    [CmdletBinding()]
    param ( )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    do
    {
        $folderName = [System.IO.Path]::GetRandomFileName()
        $folderPath = Join-Path -Path $env:temp -ChildPath $folderName
    } until (-not (Test-Path -LiteralPath $folderPath))

    try
    {
        $null = New-Item -Path $folderPath -ItemType Directory -ErrorAction Stop
    }
    catch
    {
        $exception = Get-InnerException -ErrorRecord $_
        throw "Error creating temporary folder: $($exception.Message)"
    }

    return $folderPath
}

function Compress-Folder
{
    <#
    .Synopsis
       Compresses a folder to a Zip file.
    .DESCRIPTION
       Compresses a folder to a Zip file using Optimal compression.  The root folder is not included in the resulting zip file; only its contents.
    .PARAMETER FolderPath
       Path to the folder that is to be compressed.
    .PARAMETER OutputFile
       Path to the zip file that the command should create.
    .PARAMETER NoClobber
       If NoClobber is set and the file specified by OutputPath already exists, the command will throw an error.
    .PARAMETER Force
       If the file specified by OutputPath already exists and is read-only, the Force switch will cause the command to overwrite it anyway.
    .EXAMPLE
       Compress-Folder -FolderPath C:\LargeFolder -OutputFile C:\LargeFolder.zip -NoClobber

       Zips the contents of C:\LargeFolder into C:\LargeFolder.zip, unless C:\LargeFolder.zip already exists.
    .EXAMPLE
       Compress-Folder -FolderPath C:\LargeFolder -OutputFile C:\LargeFolder.zip -Force

       Zips the contents of C:\LargeFolder into C:\LargeFolder.zip, even if C:\LargeFolder.zip exists and is read-only.
    .INPUTS
       None.  This command does not accept pipeline input.
    .OUTPUTS
       None.  This command does not produce pipeline output.
    .NOTES
       If there is an error creating the zip file, or if any of the input parameters could not be validated, the command will throw a terminating error.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({
            ValidateInputFileSystemParameter -Path $_ -ParameterName FolderPath -PathType Container
        })]
        [string]
        $FolderPath,

        [Parameter(Mandatory)]
        [string]
        $OutputFile,

        [switch]
        $NoClobber,

        [switch]
        $Force
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop

    $_folderPath = (Resolve-Path -LiteralPath $FolderPath).Path
    $_outputFile = ValidateAndResolveOutputFileParameter -Path $OutputFile -ParameterName OutputFile -NoClobber:$NoClobber -Force:$Force

    try
    {
        [System.IO.Compression.ZipFile]::CreateFromDirectory($_folderPath,
                                                             $_outputFile,
                                                             [System.IO.Compression.CompressionLevel]::Optimal,
                                                             $false)
    }
    catch
    {
        $exception = Get-InnerException -ErrorRecord $_
        throw "Error compressing folder '$FolderPath' to '$OutputFile': $($exception.Message)"
    }

} # function Compress-Folder

#
# Protect-File and Unprotect-File produce and read encrypted binary files in a proprietary format, to keep file size to a minimum.  The format is as follows:
# 
# 10-byte fixed header:  0x54 0x72 0x6F 0x6C 0x6C 0x20 0x42 0x61 0x69 0x74
# 4 bytes: Number of copies of RSA-encrypted AES key / IV.  (Int32 in Little-Endian order.)
# 
# <count> repeat instances of key blobs in the following format:
#   4 bytes: Byte count of certificate thumbprint used to protect this copy of the key.  (Int32 in Little-Endian order)
#   <count> bytes:  Certificate Thumbprint
#   4 bytes: Byte count of RSA-encrypted AES key. (Int32 in Little-Endian order)
#   <count> bytes:  RSA-encrypted AES key.
#   4 bytes: Byte count of RSA-encrypted AES IV. (Int32 in Little-Endian order)
#   <count> bytes:  RSA-encrypted AES IV.
#
# The remainder of the file is the AES-encrypted payload.
#

function Protect-File
{
    <#
    .Synopsis
       Produces an encrypted copy of a file.
    .DESCRIPTION
       Encrypts the contents of a file using AES, and protects the randomly-generated AES encryption keys using one or more RSA public keys.  The original file is not modified; this command produces a new, encrypted copy of the file.
    .PARAMETER FilePath
       The original, decrypted file.
    .PARAMETER OutputFile
       The new encrypted file that is to be created.
    .PARAMETER CertificateThumbprint
       One or more RSA certificate thumbprints that will be used to protect the file.  The public keys of these certificates will be used in the encryption process, and their private keys will be required when calling the Unprotect-File command later.
       The certificates must be present somewhere in the current user's certificate store, and must be valid (not expired.)  For this command, only the public key is required.
    .PARAMETER NoClobber
       If the file specified by OutputFile already exists, the NoClobber switch causes the command to produce an error.
    .PARAMETER Force
       If the file specified by OutputFile already exists and is read-only, the NoClobber switch causes the command to overwrite it anyway.
    .EXAMPLE
       Protect-File -FilePath c:\SensitiveData.zip -OutputFile c:\SensitiveData.bin -CertificateThumbprint 'AB06BF2C9B61D687FFB445003C2AFFAB0C81DFF9' -NoClobber

       Encrypts C:\SensitiveData.zip into a new file C:\SensitiveData.bin.  The private key of RSA certificate AB06BF2C9B61D687FFB445003C2AFFAB0C81DFF9 will be required to decrypt the file.  If C:\SensitiveData.bin already exists, the command will produce an error and abort.
    .EXAMPLE
       Protect-File -FilePath c:\SensitiveData.zip -OutputFile c:\SensitiveData.bin -CertificateThumbprint 'AB06BF2C9B61D687FFB445003C2AFFAB0C81DFF9','8E6A22DB9C6A56324E63F86F231765CC8B1A52C8' -Force

       Like example 1, except the SensitiveData.bin file will be overwritten (even if it exists and is read-only), and the SensitiveData.bin file can be decrypted by either one of the two specified RSA certificates' private keys.
    .INPUTS
       None.  This command does not accept pipeline input.
    .OUTPUTS
       None.  This command does not produce pipeline output.
    .NOTES
       If any error occurs with parameter validation or with the file encryption, the command will produce a terminating error.
    .LINK
       Unprotect-File
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({
            ValidateInputFileSystemParameter -Path $_ -ParameterName FilePath
        })]
        [string]
        $FilePath,

        [Parameter(Mandatory)]
        [string]
        $OutputFile,

        [Parameter(Mandatory)]
        [string[]]
        $CertificateThumbprint,

        [switch]
        $NoClobber,

        [switch]
        $Force
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $_filePath = (Resolve-Path -LiteralPath $FilePath).Path
    $_outputFile = ValidateAndResolveOutputFileParameter -Path $OutputFile -ParameterName OutputFile -NoClobber:$NoClobber -Force:$Force

    try
    {
        $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider

        $keys = New-Object System.Collections.ArrayList

        #region Validate Input

        foreach ($thumbprint in $CertificateThumbprint)
        {
            $cert = Get-ChildItem -LiteralPath 'Cert:\CurrentUser' -Include $thumbprint -Recurse |
                    Where-Object {
                        $null -ne $_.PublicKey.Key -and $_.PublicKey.Key -is [System.Security.Cryptography.RSACryptoServiceProvider] -and
                        $_.NotBefore -lt (Get-Date) -and $_.NotAfter -gt (Get-Date)
                    } |
                    Select-Object -First 1

            if ($null -eq $cert)
            {
                throw "No valid RSA certificate with thumbprint '$thumbprint' was found in the current user's store."
            }
            
            try
            {
                $null = $keys.Add([pscustomobject] @{
                    Thumbprint = Get-ByteArrayFromString -String $cert.Thumbprint
                    Key        = $cert.PublicKey.Key.Encrypt($aes.Key, $true)
                    IV         = $cert.PublicKey.Key.Encrypt($aes.IV, $true)
                })
            }
            catch
            {
                $exception = Get-InnerException -ErrorRecord $_
                throw "Error using certificate '$thumbprint' to encrypt key info: $($exception.Message)"
            }
        }

        #endregion

        try
        {
            #region Create output file, write header and key blobs

            $outputStream = New-Object System.IO.FileStream($_outputFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
            $binaryWriter = New-Object System.IO.BinaryWriter($outputStream, [System.Text.Encoding]::ASCII, $true)

            $header = [System.Text.Encoding]::ASCII.GetBytes('Troll Bait')
            $binaryWriter.Write($header)

            $binaryWriter.Write($keys.Count)

            foreach ($key in $keys)
            {
                $binaryWriter.Write($key.Thumbprint.Count)
                $binaryWriter.Write($key.Thumbprint)

                $binaryWriter.Write($key.Key.Count)
                $binaryWriter.Write($key.Key)

                $binaryWriter.Write($key.IV.Count)
                $binaryWriter.Write($key.IV)
            }

            #endregion

            #region AES encrypt payload

            $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($outputStream, $aes.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)
            $inputStream = New-Object System.IO.FileStream($_filePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
            $buffer = New-Object byte[](1mb)

            while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0)
            {
                $cryptoStream.Write($buffer, 0, $read)
            }

            #endregion
        }
        catch
        {
            $exception = Get-InnerException -ErrorRecord $_
            throw "Error encrypting file '$FilePath' to '$OutputFile': $($exception.Message)"
        }
    }
    finally
    {
        if ($null -ne $binaryWriter) { $binaryWriter.Dispose() }
        if ($null -ne $cryptoStream) { $cryptoStream.Dispose() }
        if ($null -ne $inputStream)  { $inputStream.Dispose() }
        if ($null -ne $outputStream) { $outputStream.Dispose() }
        if ($null -ne $aes)          { $aes.Dispose() }
    }
}

function Unprotect-File
{
    <#
    .Synopsis
       Decrypts a file that was encrypted using Protect-File.
    .DESCRIPTION
       Using the private key of one of the certificates that was used when calling Protect-File, Unprotect-File decrypts its contents.  As with Protect-File, the original file is left intact, and the decrypted contents are stored in a new file.
    .PARAMETER FilePath
       The encrypted file.
    .PARAMETER OutputFile
       The new decrypted file that is to be created.
    .PARAMETER CertificateThumbprint
       An RSA certificate thumbprint that will be used to decrypt the file.  This certificate, including its public key, must be in the current user's certificate store, and this must be one of the certificates used when the file was originally encrypted with Protect-File.
    .PARAMETER NoClobber
       If the file specified by OutputFile already exists, the NoClobber switch causes the command to produce an error.
    .PARAMETER Force
       If the file specified by OutputFile already exists and is read-only, the NoClobber switch causes the command to overwrite it anyway.
    .EXAMPLE
       Unprotect-File -FilePath c:\SensitiveData.bin -OutputFile c:\SensitiveData.zip -CertificateThumbprint 'AB06BF2C9B61D687FFB445003C2AFFAB0C81DFF9' -NoClobber

       Decrypts C:\SensitiveData.bin into a new file C:\SensitiveData.zip.  The private key of RSA certificate AB06BF2C9B61D687FFB445003C2AFFAB0C81DFF9 will be used to decrypt the file.  If C:\SensitiveData.zip already exists, the command will produce an error and abort.
    .EXAMPLE
       Unprotect-File -FilePath c:\SensitiveData.bin -OutputFile c:\SensitiveData.zip -CertificateThumbprint '8E6A22DB9C6A56324E63F86F231765CC8B1A52C8' -Force

       Like example 1, except the SensitiveData.zip file will be overwritten (even if it exists and is read-only.)
    .INPUTS
       None.  This command does not accept pipeline input.
    .OUTPUTS
       None.  This command does not produce pipeline output.
    .NOTES
       If any error occurs with parameter validation or with the file decryption, the command will produce a terminating error.
    .LINK
       Protect-File
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({
            ValidateInputFileSystemParameter -Path $_ -ParameterName FilePath
        })]
        [string]
        $FilePath,

        [Parameter(Mandatory)]
        [string]
        $OutputFile,

        [Parameter(Mandatory)]
        [string]
        $CertificateThumbprint,

        [switch]
        $NoClobber,

        [switch]
        $Force
    )

    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $_filePath = (Resolve-Path -LiteralPath $FilePath).Path
    $_outputFile = ValidateAndResolveOutputFileParameter -Path $OutputFile -ParameterName OutputFile -NoClobber:$NoClobber -Force:$Force

    try
    {
        #region Validate input

        # NOTE:  I've observed that sometimes certificates do have a private key (when viewed in the MMC), and the HasPrivateKey property
        # of the .NET certificate object is also set to True, but for some reason the PrivateKey property is null.  Haven't nailed down
        # the cause of this yet, but it's annoying when I had intended for this script to use RSA certificates as a means for protecting
        # the data without having to manage the keys myself.

        # I gather that it may be possible to get at the private key through other means (Win32 API) even when this situation crops up,
        # but I don't think it's necessary to go quite that far for the Scripting Games.

        $cert = Get-ChildItem -LiteralPath 'Cert:\CurrentUser' -Include $CertificateThumbprint -Recurse |
                Where-Object {
                    $_.HasPrivateKey -and $_.PrivateKey -is [System.Security.Cryptography.RSACryptoServiceProvider] -and
                    $_.NotBefore -lt (Get-Date) -and $_.NotAfter -gt (Get-Date)
                } |
                Select-Object -First 1

        if ($null -eq $cert)
        {
            throw "No valid RSA certificate with thumbprint '$CertificateThumbprint' with a private key was found in the current user's store."
        }

        #endregion

        #region Parse header and key blobs

        $inputStream = New-Object System.IO.FileStream($_filePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $binaryReader = New-Object System.IO.BinaryReader($inputStream, [System.Text.Encoding]::ASCII, $true)

        try
        {
            $header = $binaryReader.ReadBytes(10)
        }
        catch
        {
            throw "File '$FilePath' contains invalid data."
        }

        if ([System.Text.Encoding]::ASCII.GetString($header) -ne 'Troll Bait')
        {
            throw "File '$FilePath' contains invalid data."
        }

        try
        {
            $certCount = $binaryReader.ReadInt32()
        }
        catch
        {
            throw "File '$FilePath' contains invalid data."
        }

        $matchingKey = $null

        for ($i = 0; $i -lt $certCount; $i++)
        {
            $object = [pscustomobject] @{
                Thumbprint = $null
                Key = $null
                IV = $null
            }

            try
            {
                $count = $binaryReader.ReadInt32()
                $thumbprintBytes = $binaryReader.ReadBytes($count)
                
                $count = $binaryReader.ReadInt32()
                $object.Key = $binaryReader.ReadBytes($count)

                $count = $binaryReader.ReadInt32()
                $object.IV = $binaryReader.ReadBytes($count)
            }
            catch
            {
                throw "File '$FilePath' contains invalid data."
            }

            $object.Thumbprint = Get-StringFromByteArray -ByteArray $thumbprintBytes
            
            if ($object.Thumbprint -eq $CertificateThumbprint)
            {
                $matchingKey = $object
            }
        }

        if ($null -eq $matchingKey)
        {
            throw "No key protected with certificate '$CertificateThumbprint' was found in protected file '$FilePath'"
        }

        #endregion

        #region Decrypt AES payload and save to decrypted output file.

        try
        {
            $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            $aes.Key = $cert.PrivateKey.Decrypt($matchingKey.Key, $true)
            $aes.IV = $cert.PrivateKey.Decrypt($matchingKey.IV, $true)
        }
        catch
        {
            $exception = Get-InnerException -ErrorRecord $_
            throw "Error decrypting file with certificate '$CertificateThumbprint': $($exception.Message)"
        }

        try
        {
            $outputStream = New-Object System.IO.FileStream($_outputFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)        
            $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($inputStream, $aes.CreateDecryptor(), [System.Security.Cryptography.CryptoStreamMode]::Read)

            $buffer = New-Object byte[](1mb)

            while (($read = $cryptoStream.Read($buffer, 0, $buffer.Length)) -gt 0)
            {
                $outputStream.Write($buffer, 0, $read)
            }
        }
        catch
        {
            $exception = Get-InnerException -ErrorRecord $_
            throw "Error decrypting file '$FilePath' to '$OutputFile': $($exception.Message)"
        }

        #endregion
    }
    finally
    {
        if ($null -ne $binaryReader) { $binaryReader.Dispose() }
        if ($null -ne $cryptoStream) { $cryptoStream.Dispose() }
        if ($null -ne $inputStream)  { $inputStream.Dispose() }
        if ($null -ne $outputStream) { $outputStream.Dispose() }
        if ($null -ne $aes)          { $aes.Dispose() }
    }
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

function ValidateAndResolveOutputFileParameter
{
    # Ensures that the Path is a valid FileSystem path.  Enforces typical behavior for -NoClobber and -Force parameters.
    # Attempts to create the parent directory of Path, if it does not already exist.
    # Also resolves relative paths according to PowerShell's current file system location.
    #
    # Either returns the resolved path, or throws an error (intended for use in Begin blocks.)

    # This function is not exported to the module's consumer.

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Path,

        [Parameter(Mandatory)]
        [string]
        $ParameterName,

        [switch]
        $NoClobber,

        [switch]
        $Force
    )

    if ($Path.IndexOfAny([System.IO.Path]::InvalidPathChars) -ge 0)
    {
        throw "$ParameterName argument contains in valid characters."
    }

    if (-not (Split-Path -Path $Path -IsAbsolute))
    {
        $_file = Join-Path -Path $PSCmdlet.SessionState.Path.CurrentFileSystemLocation -ChildPath ($Path -replace '^\.?\\?')
    }
    else
    {
        $_file = $Path
    }

    try
    {
        $fileInfo = [System.IO.FileInfo]$_file
    }
    catch
    {
        $exception = Get-InnerException -ErrorRecord $_
        throw "Error parsing $ParameterName path '$Path': $($exception.Message)"
    }

    if ($fileInfo.Exists)
    {
        if ($NoClobber)
        {
            throw "$ParameterName '$Path' already exists, and the NoClobber switch was passed."
        }
        else
        {
            try
            {
                Remove-Item -LiteralPath $_file -Force:$Force -ErrorAction Stop
            }
            catch
            {
                $exception = Get-InnerException -ErrorRecord $_
                throw "$ParameterName '$Path' already exists, and the following error occurred when attempting to delete it: $($exception.Message)"
            }
        }
    }

    if (-not $fileInfo.Directory.Exists)
    {
        try
        {
            $null = New-Item -Path $fileInfo.Directory.FullName -ItemType Directory -ErrorAction Stop
        }
        catch
        {
            $exception = Get-InnerException -ErrorRecord $_
            throw "Parent folder of $ParameterName '$Path' does not exist, and the following error occurred when attempting to create it: $($exception.Message)"
        }
    }

    return $fileInfo.FullName
}

function Get-StringFromByteArray
{
    # Converts byte array into a string of hexadecimal characters in the same order as the byte array
    # This function is not exported to the module's consumer.

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [byte[]]
        $ByteArray
    )

    $sb = New-Object System.Text.StringBuilder

    for ($i = 0; $i -lt $ByteArray.Length; $i++)
    {
        $null = $sb.Append($ByteArray[$i].ToString('x2', [Globalization.CultureInfo]::InvariantCulture))
    }

    return $sb.ToString()
}

function Get-ByteArrayFromString
{
    # Converts a string containing an even number of hexadecimal characters into a byte array.
    # This function is not exported to the module's consumer.

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            # Could use ValidatePattern for this, but ValidateScript allows for a more user-friendly error message.
            if ($_ -match '[^0-9A-F]')
            {
                throw 'String must only contain hexadecimal characters (0-9 and A-F).'
            }

            if ($_.Length % 2 -ne 0)
            {
                throw 'String must contain an even number of characters'
            }

            return $true
        })]
        [string]
        $String
    )

    $length = $String.Length / 2
    
    try
    {
        $bytes = New-Object byte[]($length)
    }
    catch
    {
        $exception = Get-InnerException -ErrorRecord $_
        throw "Error allocating byte array of size ${length}: $($exception.Message)"
    }

    for ($i = 0; $i -lt $length; $i++)
    {
        $bytes[$i] = [byte]::Parse($String.Substring($i * 2, 2), [Globalization.NumberStyles]::AllowHexSpecifier, [Globalization.CultureInfo]::InvariantCulture)
    }

    return ,$bytes
}

$functions = (
    'Get-FolderData', 'New-TempFolder', 'Compress-Folder', 'Protect-File', 'Unprotect-File', 'Get-InnerException',
    'Get-ProcessData', 'Get-ServiceData', 'Get-InstalledSoftwareData', 'Get-EnvironmentVariableData',
    'Get-SharedFolderData', 'Get-RegistryData', 'Get-FileData'
)

Export-ModuleMember -Function $functions

