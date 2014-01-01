#requires -Version 3.0

function Convert-GamesFile
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [string]
        $Path,

        [switch]
        $BackupOriginal
    )

    $contents = Get-Content -LiteralPath $Path -ErrorAction Stop

    # Check for Unicode characters

    $encoding = [Microsoft.PowerShell.Commands.FileSystemCmdletProviderEncoding]::Ascii

    foreach ($line in $contents)
    {
        if ([System.Text.Encoding]::UTF8.GetByteCount($line) -ne $line.Length)
        {
            Write-Warning "File '$Path' contains multi-byte characters."
            Write-Warning "File encoding will be Unicode, though this doesn't display as well on the Scripting Games site."
            
            $encoding = [Microsoft.PowerShell.Commands.FileSystemCmdletProviderEncoding]::Unicode
            break
        }
    }

    # Perform updates

    if ($BackupOriginal)
    {
        Copy-Item -LiteralPath $Path -Destination ("$Path.bak") -ErrorAction Stop
    }

    $contents | Set-Content -LiteralPath $Path -Encoding $encoding -ErrorAction Stop
}