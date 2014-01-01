#requires -Version 4.0

function Get-ComputersInSubnet
{
    <#
    .Synopsis
       Searches a subnet for Windows computers.
    .DESCRIPTION
       Pings all IP addresses on an IPv4 subnet.  For the IPs that responded to the ping, attempts to collect the Operating System and Service Pack of the computer with WMI.
       For each IP address in the subnet(s), a PSCustomObject is returned with the following properties:

       IPAddress
       RespondedToPing
       OperatingSystem
       ServicePack

       OperatingSystem and ServicePack may be empty strings, if the computer didn't respond to pings, or if no WSMAN / WMI session could be established.
    .PARAMETER Subnet
       The IPv4 subnet to be scanned, in CIDR format.  For example:  "192.168.0.0/24" would check IPs 192.168.0.1 through 192.168.0.254.
    .EXAMPLE
       Get-ComputersInSubnet -Subnet '192.168.0.0/24'

       Scans IPs 192.168.0.1 through 192.168.0.254.
    .EXAMPLE
       '192.168.0.0/24', '192.168.0.1/24', '10.0.0.0/22' | Get-ComputersInSubnet

       Performs three different subnet scans (ranges 192.168.0.1 - 192.168.0.254, 192.168.1.1 - 192.168.1.254, and 10.0.0.1 - 10.0.3.254).
    .INPUTS
       String
    .OUTPUTS
       PSCustomObject
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]
        $Subnet
    )

    begin
    {
        if (-not $PSBoundParameters.ContainsKey('Verbose'))
        {
            $VerbosePreference = $PSCmdlet.SessionState.PSVariable.GetValue('VerbosePreference')
        }

        if (-not $PSBoundParameters.ContainsKey('Debug'))
        {
            $DebugPreference = $PSCmdlet.SessionState.PSVariable.GetValue('DebugPreference')
        }

        if (-not $PSBoundParameters.ContainsKey('WarningAction'))
        {
            $WarningPreference = $PSCmdlet.SessionState.PSVariable.GetValue('WarningPreference')
        }

        if (-not $PSBoundParameters.ContainsKey('ErrorAction'))
        {
            $ErrorActionPreference = $PSCmdlet.SessionState.PSVariable.GetValue('ErrorActionPreference')
        }
    }

    process
    {
        foreach ($string in $Subnet)
        {
            Write-Verbose "Pinging computers in subnet $string"

            $pingResults = Get-SubnetAddresses -Subnet $string |
                           Select-Object -ExpandProperty IPAddressToString |
                           Test-ConnectionAsync -MaxConcurrent 150 -Quiet -Verbose:$false |
                           Sort-Object -Property @{ Expression = { Get-UInt32FromIPAddress -IPAddress ([ipaddress]$_.ComputerName) }; Descending = $false }
    
            $respondedCount = $pingResults |
                              Where-Object Success -eq $true |
                              Measure-Object |
                              Select-Object -ExpandProperty Count
            $current = 1

            Write-Verbose "Ping operation complete.  $respondedCount computers responded."

            foreach ($pingResult in $pingResults)
            {
                $outputObject = New-Object psobject -Property ([ordered]@{
                    IPAddress       = $pingResult.ComputerName
                    RespondedToPing = $pingResult.Success
                    OperatingSystem = ''
                    ServicePack     = ''
                })

                if ($pingResult.Success)
                {
                    Write-Progress -Activity "Querying active computers in subnet $string" -PercentComplete (100 * $current / $respondedCount) -Status "Computer $current of $respondedCount ($($pingResult.ComputerName))"
                    $current++

                    # It may be possible to improve performance here by parallelizing the DNS lookups and WMI queries in addition to the pings.
                    # We can revisit that if there's time; for now, it's sequential.

                    $target = Resolve-PtrRecord -IPAddress $outputObject.IPAddress -Verbose:$false

                    try
                    {
                        $cimSession = EstablishCimSession -ComputerName $target -Verbose:$false
                    }
                    catch
                    {
                        # Suppress "RPC Server is unavailable" errors; we will probably be pinging some non-Windows devices on the subnet.

                        if ($_.Exception -isnot [Microsoft.Management.Infrastructure.CimException] -or
                            ($_.Exception.ErrorData.error_Code -band 0xFFFF) -ne 1722)
                        {
                            Write-Error "Could not establish CIM session to '$target':`r`n$($_ | Out-String)"
                        }
                    }

                    if ($null -ne $cimSession)
                    {
                        $os = Get-CimInstance -CimSession $cimSession -ClassName Win32_OperatingSystem -Verbose:$false

                        if ($null -ne $os)
                        {
                            $outputObject.OperatingSystem = $os.Caption

                            if ($os.ServicePackMajorVersion -ne '0')
                            {
                                $outputObject.ServicePack = $os.ServicePackMajorVersion
                        
                                if ($os.ServicePackMinorVersion -ne '0')
                                {
                                    $outputObject.ServicePack += $os.ServicePackMinorVersion
                                }
                            }
                            else
                            {
                                $outputObject.ServicePack = 'No Service Pack'
                            }

                        }

                        Remove-CimSession -CimSession $cimSession -Verbose:$false
                        $cimSession = $null
                    }

                } # if ($pingResult.Success)

                Write-Output $outputObject

            } # foreach ($pingResult in $pingResults)

            Write-Progress -Activity "Querying active computers in subnet $string" -Completed
        
        } # foreach ($string in $Subnet)

    } # process

} # function Get-ComputersInSubnet

function Get-InventoryData
{
    <#
    .Synopsis
       Collects inventory data from one or more computers.
    .DESCRIPTION
       Collects inventory data from one or more computers using WMI (over WSMAN or DCOM, whichever works.)
    .PARAMETER ComputerName
       The name or IP address of the computer(s) to be queried.
    .PARAMETER HardwareInfo
       When the HardwareInfo switch is specified, the inventory will contain the following data for each computer:

       Manufacturer and Model of the computer.
       Total physical RAM.
       CPU information (Name, Speed, Architecture, Core and Logical Processor count for each physical CPU)
       Disk information (Drive Letter, Volume Name, Size, Free Space and File System for each logical drive on a local disk.)
    .PARAMETER LastHotfix
       When the LastHotfix switch is specified, the inventory will contain the date and time at which the most recent operating system patch was installed on each computer.
    .PARAMETER LastReboot
       When the LastReboot switch is specified, the inventory will contain the date and time at which each computer was last booted.
    .PARAMETER InstalledServerApps
       When the InstalledServerApps switch is specified, the inventory will contain boolean values indicating whether IIS, Exchange, SQL Server or SharePoint are installed on each computer.
    .PARAMETER WindowsComponents
       When the WindowsComponents switch is specified, the inventory will contain a list of installed Windows optional components
    .EXAMPLE
       Get-InventoryData.ps1 -ComputerName '192.168.0.1' -HardwareInfo

       Collects basic hardware information from computer 192.168.0.1.
    .EXAMPLE
       '192.168.0.1', '192.168.0.2', '192.168.0.3' | Get-InventoryData -HardwareInfo -LastHotfix -LastReboot -InstalledServerApps -WindowsComponents

       Collects full inventory data from 192.168.0.1, 192.168.0.2, and 192.168.0.3.
    .INPUTS
       String
    .OUTPUTS
       PSCustomObject
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]
        $ComputerName,

        [switch]
        $HardwareInfo,

        [switch]
        $LastHotfix,

        [switch]
        $LastReboot,

        [switch]
        $InstalledServerApps,

        [switch]
        $WindowsComponents
    )

    begin
    {
        if (-not $PSBoundParameters.ContainsKey('Verbose'))
        {
            $VerbosePreference = $PSCmdlet.SessionState.PSVariable.GetValue('VerbosePreference')
        }

        if (-not $PSBoundParameters.ContainsKey('Debug'))
        {
            $DebugPreference = $PSCmdlet.SessionState.PSVariable.GetValue('DebugPreference')
        }

        if (-not $PSBoundParameters.ContainsKey('WarningAction'))
        {
            $WarningPreference = $PSCmdlet.SessionState.PSVariable.GetValue('WarningPreference')
        }

        if (-not $PSBoundParameters.ContainsKey('ErrorAction'))
        {
            $ErrorActionPreference = $PSCmdlet.SessionState.PSVariable.GetValue('ErrorActionPreference')
        }
    }

    process
    {
        foreach ($computer in $ComputerName)
        {
            $target = Resolve-PtrRecord -IPAddress $computer
            
            try
            {
                $cimSession = EstablishCimSession -ComputerName $target
            }
            catch
            {
                Write-Error -ErrorRecord $_
                continue
            }

            $outputObject = New-Object psobject -Property @{ ComputerName = $target }

            if ($HardwareInfo)
            {
                $properties = 'TotalPhysicalMemory', 'Manufacturer', 'Model'
                $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $cimSession -Property $properties -Verbose:$false

                foreach ($property in $properties)
                {
                    Add-Member -InputObject $outputObject -NotePropertyName $property -NotePropertyValue $computerSystem.$property
                }

                $properties = 'Name', 'MaxClockSpeed', 'AddressWidth', 'NumberOfCores', 'NumberOfLogicalProcessors'
                Add-Member -InputObject $outputObject -NotePropertyName 'Processors' -NotePropertyValue @(
                    Get-CimInstance -ClassName Win32_Processor -CimSession $cimSession -Property $properties -Verbose:$false |
                    Select-Object -Property $properties
                )

                $properties = 'DeviceID', 'VolumeName', 'Size', 'FreeSpace', 'FileSystem'
                Add-Member -InputObject $outputObject -NotePropertyName 'LogicalDrives' -NotePropertyValue @(
                    Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType = 3' -CimSession $cimSession -Property $properties -Verbose:$false |
                    Select-Object -Property $properties
                )
            }

            if ($LastHotfix)
            {
                Add-Member -InputObject $outputObject -NotePropertyName LastHotfixInstalledOn -NotePropertyValue (
                    Get-CimInstance -ClassName Win32_QuickFixEngineering -CimSession $cimSession -Property InstalledOn -Verbose:$false |
                    Sort-Object -Property InstalledOn -Descending |
                    Select-Object -First 1 -ExpandProperty InstalledOn
                )
            }

            if ($LastReboot)
            {
                Add-Member -InputObject $outputObject -NotePropertyName LastBootUpTime -NotePropertyValue (
                    Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $cimSession -Property LastBootUpTime -Verbose:$false |
                    Select-Object -ExpandProperty LastBootUpTime
                )
            }

            if ($InstalledServerApps)
            {
                Add-Member -InputObject $outputObject -NotePropertyName IISInstalled -NotePropertyValue (
                    1 -eq (Get-CimInstance -ClassName Win32_OptionalFeature -Filter 'Name = "IIS-WebServerRole"' -CimSession $cimSession -Verbose:$false |
                           Select-Object -First 1 -ExpandProperty InstallState)
                )

                Add-Member -InputObject $outputObject -NotePropertyName SQLInstalled -NotePropertyValue (
                    $null -ne (Get-CimInstance -CimSession $cimSession -ClassName Win32_Service -Filter 'PathName LIKE "%sqlservr.exe%"' -Verbose:$false)
                )

                $registry = Get-CimClass -ClassName StdRegProv -Namespace root\default -CimSession $cimSession -Verbose:$false
                if ($null -ne $registry)
                {
                    Add-Member -InputObject $outputObject -NotePropertyName SharePointInstalled -NotePropertyValue $false
                    Add-Member -InputObject $outputObject -NotePropertyName ExchangeInstalled -NotePropertyValue $false

                    $baseKeys = 'Software\Microsoft\Windows\CurrentVersion\Uninstall',
                                'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
                    
                    :outerLoop
                    foreach ($baseKey in $baseKeys)
                    {
                        $result = Invoke-CimMethod -CimClass $registry -CimSession $cimSession -MethodName EnumKey -Verbose:$false -Arguments @{
                            sSubKeyName = $baseKey
                        }

                        if ($result.ReturnValue -eq 0)
                        {
                            $subKeys = $result.sNames

                            foreach ($subKey in $subKeys)
                            {
                                $subKeyPath = Join-Path -Path $baseKey -ChildPath $subKey

                                $result = Invoke-CimMethod -CimClass $registry -CimSession $cimSession -MethodName GetStringValue -Verbose:$false -Arguments @{
                                    sSubKeyName = $subKeyPath
                                    sValueName = 'DisplayName'
                                }

                                if ($result.ReturnValue -eq 0)
                                {
                                    $displayName = $result.sValue

                                    if ($displayName -like 'Microsoft SharePoint Server*')
                                    {
                                        $outputObject.SharePointInstalled = $true
                                    }
                                    elseif ($displayName -like 'Microsoft Exchange Server*')
                                    {
                                        $outputObject.ExchangeInstalled = $true
                                    }

                                    if ($outputObject.SharePointInstalled -and $outputObject.ExchangeInstalled)
                                    {
                                        break outerLoop
                                    }
                                }

                            } # foreach ($subKey in $subKeys)

                        } # if ($result.ReturnValue -eq 0)

                    } # foreach ($baseKey in $baseKeys)

                } # if ($null -ne $registry)

            } # if ($InstalledServerApps)

            if ($WindowsComponents)
            {
                Add-Member -InputObject $outputObject -NotePropertyName InstalledWindowsComponents -NotePropertyValue @(
                    Get-CimInstance -ClassName Win32_OptionalFeature -CimSession $cimSession -Filter 'InstallState = 1' -Property Caption -Verbose:$false |
                    ForEach-Object {
                        if (-not [string]::IsNullOrEmpty($_.Caption))
                        {
                            $_.Caption
                        }
                        else
                        {
                            $_.Name
                        }
                    } |
                    Sort-Object
                )
            }

            Write-Output $outputObject

            Remove-CimSession -CimSession $cimSession -Verbose:$false

        } # foreach ($computer in $ComputerName)

    } # process
} # function Get-InventoryData

function Export-InventoryToPowerPoint
{
    <#
    .Synopsis
       Saves inventory data to a PowerPoint presentation.
    .PARAMETER InputObject
       Objects generated by the Get-InventoryData.ps1 script (after being loaded with the Import-CliXml cmdlet).
    .PARAMETER Path
       The path and filename of the PowerPoint file that will be generated.
    .EXAMPLE
       Import-CliXml -Path .\192.168.0.0_24-2014-01-10_Inventory.xml | Export-InventoryToPowerPoint -Path .\Inventory.pptx
    .INPUTS
       PSCustomObject
    .OUTPUTS
       None.  This function does not generate pipeline output.
    .NOTES
       The PowerPoint file is ugly.  Really, really ugly.  If there are a lot of Windows Components installed, the text scrolls right off the slide.
       
       Working with PowerPoint is a pain, but at least the file has a pie chart!  Yay for pie charts!
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]
        $InputObject,

        [Parameter(Mandatory)]
        [string]
        $Path,

        [switch]
        $NoClobber
    )

    begin
    {
        Add-Type -AssemblyName Office -ErrorAction Stop
        Add-Type -AssemblyName Microsoft.Office.Interop.PowerPoint -ErrorAction Stop
        Add-Type -AssemblyName System.Windows.Forms.DataVisualization -ErrorAction Stop

        $folder = Split-Path -Path $Path -Parent

        if ([string]::IsNullOrEmpty($folder))
        {
            $folder = $PSCmdlet.SessionState.Path.CurrentFileSystemLocation
        }

        if (-not (Test-Path -Path $folder -PathType Container))
        {
            try
            {
                $null = New-Item -Path $folder -ItemType Directory -ErrorAction Stop
            }
            catch
            {
                throw "Error creating folder '$folder':`r`n$($_ | Out-String)"
            }
        }

        if ($NoClobber -and (Test-Path -Path $Path))
        {
            throw "File '$Path' exists, and the NoClobber switch was passed."
        }

        $objects = New-Object System.Collections.ArrayList
    }

    process
    {
        $objects.AddRange($InputObject)
    }

    end
    {
        try
        {
            $powerPoint = New-Object -ComObject PowerPoint.Application -ErrorAction Stop
            $presentation = $powerPoint.Presentations.Add([Microsoft.Office.Core.MsoTriState]::msoFalse)

            foreach ($layout in $presentation.SlideMaster.CustomLayouts)
            {
                switch ($layout.Name)
                {
                    'Blank'
                    {
                        $blankLayout = $layout
                    }

                    'Title Slide'
                    {
                        $titleLayout = $layout
                    }

                    'Picture with Caption'
                    {
                        $pictureLayout = $layout
                    }
                }
            }

            # Title Page

            $slide = $presentation.Slides.AddSlide(1, $titleLayout)
            $slide.Shapes.Item(1).TextFrame.TextRange.Text = 'Windows Inventory Report'
            $slide.Shapes.Item(2).TextFrame.TextRange.Text = "Generated on $(Get-Date -Format D)"

            $null = [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($slide)
            $slide = $null

            # Pie chart of machine count by operating system

            $slide = $presentation.Slides.AddSlide(2, $blankLayout)

            $chart = New-Object Windows.Forms.DataVisualization.Charting.Chart
            $chart.Size = New-Object Drawing.Size(540, 200)

            $area = New-Object Windows.Forms.DataVisualization.Charting.ChartArea
            $chart.ChartAreas.Add($area)

            $area.Area3DStyle.Enable3D = $true
            $area.Position.Auto = $false
            $area.Position.Y = 10
            $area.Position.Height = 90
            $area.Position.Width = 33

            $legend = New-Object Windows.Forms.DataVisualization.Charting.Legend
            $chart.Legends.Add($legend)

            $legend.Enabled = $true
            $legend.IsDockedInsideChartArea = $false
            $legend.DockedToChartArea = $area.Name

            $legend.Position.Auto = $false
            $legend.Position.Width = 67
            $legend.Position.Height = 90
            $legend.Position.X = 33
            $legend.Position.Y = 10
            $legend.TableStyle = 'Tall'

            $legend.Font = New-Object Drawing.Font(
                $legend.Font.FontFamily,
                10
            )

            $column = New-Object Windows.Forms.DataVisualization.Charting.LegendCellColumn
            $column.ColumnType = [Windows.Forms.DataVisualization.Charting.LegendCellColumnType]::SeriesSymbol
            $column.Alignment = [Drawing.ContentAlignment]::MiddleLeft
            $column.MinimumWidth = 150
            $column.MaximumWidth = 150
            $legend.CellColumns.Add($column)

            $column = New-Object Windows.Forms.DataVisualization.Charting.LegendCellColumn
            $column.ColumnType = [Windows.Forms.DataVisualization.Charting.LegendCellColumnType]::Text
            $column.Alignment = [Drawing.ContentAlignment]::MiddleLeft
            $column.MinimumWidth = 2500
            $column.MaximumWidth = 2500
            $legend.CellColumns.Add($column)

            $series = New-Object Windows.Forms.DataVisualization.Charting.Series
            $chart.Series.Add($series)

            $series.ChartType = [Windows.Forms.DataVisualization.Charting.SeriesChartType]::Pie
            $series['PieLabelStyle'] = 'Disabled'

            $title = New-Object Windows.Forms.DataVisualization.Charting.Title
            $title.IsDockedInsideChartArea = $false
            $title.DockedToChartArea = $area.Name
            $title.Font = New-Object Drawing.Font(
                $title.Font.FontFamily,
                $title.Font.SizeInPoints,
                [Drawing.FontStyle]::Bold
            )
            $title.Text = 'Computer Count by OS'
        
            $chart.Titles.Add($title)

            $objects |
            Where-Object { -not [string]::IsNullOrEmpty($_.OperatingSystem) } |
            Group-Object -Property OperatingSystem |
            Sort-Object -Property Count -Descending |
            ForEach-Object {
                $point = New-Object Windows.Forms.DataVisualization.Charting.DataPoint
                $point.AxisLabel = $_.Name
                $point.YValues = $_.Count

                $series.Points.Add($point)
            }

            $imageFileName = Get-TempImageFileName
            $chart.SaveImage($imageFileName, [Windows.Forms.DataVisualization.Charting.ChartImageFormat]::Png)

            $null = $slide.Shapes.AddPicture($imageFileName, [Microsoft.Office.Core.MsoTriState]::msoFalse, [Microsoft.Office.Core.MsoTriState]::msoTrue, 50, 140, 540, 200)

            $null = [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($slide)
            $slide = $null

            # Inventory Details of each machine
            foreach ($object in $objects)
            {
                $slide = $presentation.Slides.AddSlide($presentation.Slides.Count + 1, $blankLayout)

                $textBox = $slide.Shapes.AddTextBox([Microsoft.Office.Core.MsoTextOrientation]::msoTextOrientationHorizontal, 0, 0, 640, 480)

                $textBox.TextFrame.TextRange.Font.Name = 'Courier New'
                $textBox.TextFrame.TextRange.Font.Size = 11

                $textBox.TextFrame.TextRange.Text = InventoryToString -InputObject $object

                $null = [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($textBox)
                $null = [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($slide)
                $textBox = $null
                $slide = $null
            }

            $presentation.SaveAs($PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path))
        }
        finally
        {
            if ($null -ne $presentation)
            {
                $presentation.Close()
            }

            if ($null -ne $powerPoint)
            {
                $powerPoint.Quit()
            }

            $comObjects = @(
                'blankLayout'
                'titleLayout'
                'pictureLayout'
                'slide'
                'presentation'
                'powerPoint'
            )

            foreach ($variable in $comObjects)
            {
                $value = Get-Variable -Name $variable -ValueOnly -ErrorAction Ignore

                if ($null -ne $value)
                {
                    $null = [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($value)
                    Remove-Variable -Name $variable
                }
            }

            [GC]::Collect([GC]::MaxGeneration)

            if (-not [string]::IsNullOrEmpty($imageFileName))
            {
                Remove-Item -LiteralPath $imageFileName -ErrorAction Ignore
            }

        } # finally

    } # end

} # function Export-InventoryToPowerPoint

function Test-ConnectionAsync
{    
    <#
    .Synopsis
       Proxy function for Test-Connection that pings multiple hosts at a time.
    .PARAMETER MaxConcurrent
       Specifies the maximum number of Test-Connection commands to run at a time.
    .EXAMPLE
       Get-Content .\IPAddresses.txt | Test-ConnectionAsync -MaxConcurrent 250 -Quiet

       Pings the devices listed in the IPAddresses.txt file, up to 250 at a time.
    .NOTES
       Other than MaxConcurrent, all other parameters are identical to those in the Test-Connection cmdlet.  Refer to Get-Help Test-Connection for further details.
    .INPUTS
       String
    .OUTPUTS
       If the -Quiet parameter is not specified, the function outputs a collection of Win32_PingStatus objects, one for each ping result.
   
       If the -Quiet parameter is specified, the function outputs a collection of PSCustomObjects containing the properties "ComputerName" (a string with the address that was pinged) and "Success" (a boolean value indicating whether the computer responded to at least one ping successfully).
    .LINK
       Test-Connection
    #>
    
    [CmdletBinding(DefaultParameterSetName='Default')]
    param(
        [System.Management.AuthenticationLevel]
        ${Authentication},

        [Alias('Size','Bytes','BS')]
        [ValidateRange(0, 65500)]
        [System.Int32]
        ${BufferSize},

        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [Alias('CN','IPAddress','__SERVER','Server','Destination')]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        ${ComputerName},

        [ValidateRange(1, 4294967295)]
        [System.Int32]
        ${Count},

        [Parameter(ParameterSetName='Source')]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        ${Credential},

        [Parameter(ParameterSetName='Source', Mandatory=$true, Position=1)]
        [Alias('FCN','SRC')]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        ${Source},

        [System.Management.ImpersonationLevel]
        ${Impersonation},

        [Parameter(ParameterSetName='Default')]
        [Parameter(ParameterSetName='Source')]
        [ValidateRange(-2147483648, 1000)]
        [System.Int32]
        ${ThrottleLimit},

        [Alias('TTL')]
        [ValidateRange(1, 255)]
        [System.Int32]
        ${TimeToLive},

        [ValidateRange(1, 60)]
        [System.Int32]
        ${Delay},

        [ValidateScript({$_ -ge 1})]
        [System.UInt32]
        $MaxConcurrent = 20,

        [Parameter(ParameterSetName='Quiet')]
        [Switch]
        $Quiet
    )

    begin
    {
        if ($PSBoundParameters.ContainsKey('MaxConcurrent'))
        {
            $null = $PSBoundParameters.Remove('MaxConcurrent')
        }

        if ($PSBoundParameters.ContainsKey('Quiet'))
        {
            $null = $PSBoundParameters.Remove('Quiet')
        }

        if (-not $PSBoundParameters.ContainsKey('Verbose'))
        {
            $VerbosePreference = $PSCmdlet.SessionState.PSVariable.GetValue('VerbosePreference')
        }

        if (-not $PSBoundParameters.ContainsKey('Debug'))
        {
            $DebugPreference = $PSCmdlet.SessionState.PSVariable.GetValue('DebugPreference')
        }

        if (-not $PSBoundParameters.ContainsKey('WarningAction'))
        {
            $WarningPreference = $PSCmdlet.SessionState.PSVariable.GetValue('WarningPreference')
        }

        if (-not $PSBoundParameters.ContainsKey('ErrorAction'))
        {
            $ErrorActionPreference = $PSCmdlet.SessionState.PSVariable.GetValue('ErrorActionPreference')
        }

        $jobs = @{}
        $i = -1
    }

    process
    {
        # PSBoundParameters will be splatted to Test-Connection later, but one computer at a time.
        $null = $PSBoundParameters.Remove('ComputerName')

        foreach ($target in $ComputerName)
        {
            while ($true)
            {
                if (++$i -eq $MaxConcurrent)
                {
                    Start-Sleep -Milliseconds 100
                    $i = 0
                }

                if ($jobs[$i] -ne $null -and $jobs[$i].Job.JobStateInfo.State -ne [System.Management.Automation.JobState]::Running)
                {
                    $quietStatus = New-Object psobject -Property @{ 
                        ComputerName = $jobs[$i].Target
                        Success = $false
                    }
                    
                    if ($jobs[$i].Job.HasMoreData)
                    {
                        foreach ($ping in (Receive-Job $jobs[$i].Job))
                        {
                            if ($Quiet)
                            {
                                $quietStatus.ComputerName = $ping.Address
                                if ($ping.StatusCode -eq 0)
                                {
                                    $quietStatus.Success = $true
                                    break
                                }
                            }
                            
                            else
                            {
                                Write-Output $ping
                            }
                        }
                    }

                    if ($Quiet)
                    {
                        Write-Output $quietStatus
                    }

                    Remove-Job -Job $jobs[$i].Job -Force
                    $jobs[$i] = $null

                } # ($jobs[$i] -ne $null -and $jobs[$i].Job.JobStateInfo.State -ne [System.Management.Automation.JobState]::Running)

                if ($jobs[$i] -eq $null)
                {
                    Write-Verbose "Job ${i}: Pinging $target."

                    $job = Test-Connection -ComputerName $target -AsJob @PSBoundParameters
                    $jobs[$i] = New-Object psobject -Property @{
                        Target = $target
                        Job = $job
                    }

                    break
                }

            } # while ($true)

        } # foreach ($target in $ComputerName)

    } # process

    end
    {
        while ($true)
        {
            $foundActive = $false

            for ($i = 0; $i -lt $MaxConcurrent; $i++)
            {
                if ($jobs[$i] -ne $null)
                {
                    if ($jobs[$i].Job.JobStateInfo.State -ne [System.Management.Automation.JobState]::Running)
                    {
                        $quietStatus = New-Object psobject -Property @{ComputerName = $jobs[$i].Target; Success = $false}
                        
                        if ($jobs[$i].Job.HasMoreData)
                        {
                            foreach ($ping in (Receive-Job $jobs[$i].Job))
                            {
                                if ($Quiet)
                                {
                                    $quietStatus.ComputerName = $ping.Address
                                    if ($ping.StatusCode -eq 0)
                                    {
                                        $quietStatus.Success = $true
                                        break
                                    }
                                }

                                else
                                {
                                    Write-Output $ping
                                }
                            }
                        }

                        if ($Quiet)
                        {
                            Write-Output $quietStatus
                        }

                        Remove-Job -Job $jobs[$i].Job -Force
                        $jobs[$i] = $null

                    } # if ($jobs[$i].Job.JobStateInfo.State -ne [System.Management.Automation.JobState]::Running)
                    
                    else
                    {
                        $foundActive = $true
                    }

                } # if ($jobs[$i] -ne $null)

            } # for ($i = 0; $i -lt $MaxConcurrent; $i++)

            if (-not $foundActive)
            {
                break
            }

            Start-Sleep -Milliseconds 100

        } # while ($true)

    } # end

} # function Test-ConnectionAsync

function EstablishCimSession
{
    # Attempts to create a CIM session to the target computer using the default WSMAN protocol (if it is running at least stack version 3.0).  If that fails, tries again with DCOM.

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $ComputerName
    )

    $VerbosePreference = 'SilentlyContinue'

    $cimSession = $null
    
    $info = Test-WSMan -ComputerName $ComputerName -ErrorAction Ignore

    if ($null -ne $info)
    {
        if ($info.ProductVersion -match 'Stack:\s*(\d+)' -and [int]$matches[1] -ge 3)
        {
            $cimSession = New-CimSession -ComputerName $ComputerName -ErrorAction Ignore
        }
    }
    
    if ($null -eq $cimSession)
    {
        try
        {
            $option = New-CimSessionOption -Protocol Dcom
            $cimSession = New-CimSession -ComputerName $ComputerName -SessionOption $option -ErrorAction Stop
        }
        catch
        {
            throw
        }
    }


    return $cimSession
}

function Resolve-PtrRecord
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $IPAddress
    )
    
    try
    {
        $resolved = [System.Net.Dns]::GetHostEntry($IPAddress) |
                    Select-Object -First 1 -ExpandProperty HostName
    } catch { }

    if (-not [string]::IsNullOrEmpty($resolved))
    {
        return $resolved
    }
    else
    {
        return $IPAddress
    }
}

function Get-SubnetAddresses
{
    # Converts an IPv4 subnet address in CIDR notation (ie, 192.168.0.0/24) into a collection of [ipaddress] objects.

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Subnet
    )

    $ipaddress = $null

    # Validating the string format here instead of in a ValidateScript block allows us to use the
    # $ipaddress and $matches variables without having to perform the parsing twice.

    if ($Subnet -notmatch '^(?<Address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(?<Mask>\d{1,2})$')
    {
        throw "Subnet address '$Subnet' does not match the expected CIDR format (example:  192.168.0.0/24)"
    }

    if (-not [ipaddress]::TryParse($matches['Address'], [ref]$ipaddress))
    {
        throw "Subnet address '$Subnet' contains an invalid IPv4 address."
    }

    $maskDecimal = [int]$matches['Mask']

    if ($maskDecimal -gt 30)
    {
        throw "Subnet address '$Subnet' contains an invalid subnet mask (must be less than or equal to 30)."
    }

    $hostBitCount = 32 - $maskDecimal
        
    $netMask = [UInt32]0xFFFFFFFFL -shl $hostBitCount
    $hostMask = -bnot $netMask

    $networkAddress = (Get-UInt32FromIPAddress -IPAddress $ipaddress) -band $netMask
    $broadcastAddress = $networkAddress -bor $hostMask

    for ($address = $networkAddress + 1; $address -lt $broadcastAddress; $address++)
    {
        Get-IPAddressFromUInt32 -UInt32 $address
    }
}

function Get-UInt32FromIPAddress
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ipaddress]
        $IPAddress
    )

    $bytes = $IPAddress.GetAddressBytes()

    if ([BitConverter]::IsLittleEndian)
    {
        [Array]::Reverse($bytes)
    }

    return [BitConverter]::ToUInt32($bytes, 0)
}

function Get-IPAddressFromUInt32
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [UInt32]
        $UInt32
    )

    $bytes = [BitConverter]::GetBytes($UInt32)
            
    if ([BitConverter]::IsLittleEndian)
    {
        [Array]::Reverse($bytes)
    }

    return New-Object ipaddress(,$bytes)
}

function Get-TempImageFileName
{
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string]
        $Extension = 'png'
    )

    $Extension = $Extension -replace '^\.'

    if ($Extension.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0)
    {
        throw New-Object ArgumentException('Extension contains invalid characters.', 'Extension')
    }

    do
    {
        $number = Get-Random -Minimum 1 -Maximum 0xFFFFFF
        $imgPath = "$env:temp\img$($number.ToString('x6')).$Extension"
    } while (Test-Path -Path $imgPath)

    return $imgPath
}

function InventoryToString
{
    [CmdletBinding()]
    param (
        $InputObject
    )

    $sb = New-Object System.Text.StringBuilder

    $props = @{
        ComputerName = 'Computer Name'
        IPAddress = 'IP Address'
        OperatingSystem = 'Operating System'
        ServicePack = 'Service Pack'
        Model = 'Model'
        Manufacturer = 'Manufacturer'
        TotalPhysicalMemory = ''
    }

    if ($InputObject.PSObject.Properties['ComputerName'])
    {
        $null = $sb.AppendLine("Computer Name: $($InputObject.ComputerName)")
    }

    if ($InputObject.PSObject.Properties['OperatingSystem'])
    {
        $null = $sb.AppendLine("Operating System: $($InputObject.OperatingSystem)")
    }

    if ($InputObject.PSObject.Properties['ServicePack'])
    {
        $null = $sb.AppendLine("Service Pack: $($InputObject.ServicePack)")
    }

    if ($InputObject.PSObject.Properties['IPAddress'])
    {
        $null = $sb.AppendLine("IP Address: $($InputObject.IPAddress)")
    }

    if ($InputObject.PSObject.Properties['Manufacturer'])
    {
        $null = $sb.AppendLine("Manufacturer: $($InputObject.Manufacturer)")
    }

    if ($InputObject.PSObject.Properties['Model'])
    {
        $null = $sb.AppendLine("Model: $($InputObject.Model)")
    }

    if ($InputObject.PSObject.Properties['TotalPhysicalMemory'])
    {
        $null = $sb.AppendFormat("Memory: {0:F2} GB", $InputObject.TotalPhysicalMemory).AppendLine()
    }

    if ($InputObject.PSObject.Properties['Processors'])
    {
        $null = $sb.Append('Processors: ')
        $indent = ''

        foreach ($cpu in $InputObject.Processors)
        {
            $null = $sb.AppendFormat('{0}{1} ({2:F2} GHz, {3} core(s))', $indent, $cpu.Name, $cpu.MaxClockSpeed / 1000, $cpu.NumberOfCores).AppendLine()
            $indent = '            '
        }

        if ($indent -eq '')
        {
            $sb.AppendLine()
        }
    }

    if ($InputObject.PSObject.Properties['LogicalDrives'])
    {
        $null = $sb.Append('Drives: ')

        $indent = ''
        foreach ($drive in $InputObject.LogicalDrives)
        {
            $null = $sb.AppendFormat('{0}{1} ({2:F2} GB, {3:F2} GB free)', $indent, $drive.DeviceID, $drive.Size / 1GB, $drive.FreeSpace / 1GB ).AppendLine()
            $indent = '        '
        }

        if ($indent -eq '')
        {
            $sb.AppendLine()
        }
    }

    if ($InputObject.PSObject.Properties['LastBootUpTime'])
    {
        $null = $sb.AppendLine("Last Boot Time: $($InputObject.LastBootUpTime)")
    }

    if ($InputObject.PSObject.Properties['LastHotfixInstalledOn'])
    {
        $null = $sb.AppendFormat('Last Hotfix Install Date: {0:D}', $InputObject.LastHotfixInstalledOn).AppendLine()
    }

    if ($InputObject.PSObject.Properties['IISInstalled'])
    {
        $null = $sb.AppendLine("IIS Installed?: $($InputObject.IISInstalled)")
    }

    if ($InputObject.PSObject.Properties['SQLInstalled'])
    {
        $null = $sb.AppendLine("SQL Installed?: $($InputObject.SQLInstalled)")
    }

    if ($InputObject.PSObject.Properties['ExchangeInstalled'])
    {
        $null = $sb.AppendLine("Exchange Installed?: $($InputObject.ExchangeInstalled)")
    }

    if ($InputObject.PSObject.Properties['SharePointInstalled'])
    {
        $null = $sb.AppendLine("SharePoint Installed?: $($InputObject.SharePointInstalled)")
    }

    if ($InputObject.PSObject.Properties['InstalledWindowsComponents'])
    {
        $null = $sb.AppendLine('Installed Components:').AppendLine($InputObject.InstalledWindowsComponents -join ', ')
    }

    return $sb.ToString()
}

Export-ModuleMember -Function 'Get-ComputersInSubnet', 'Get-InventoryData', 'Export-InventoryToPowerPoint', 'Test-ConnectionAsync'
