#Requires -Version 5.0

# StrictMode 2.0 is possible but makes the creation of the LenovoPackage objects a lot uglier with no real benefit
Set-StrictMode -Version 1.0

enum Severity {
  Critical = 1
  Recommended = 2
  Optional = 3
}

enum DependencyParserState {
  DO_HAVE = 0
  DO_NOT_HAVE = 1
}

# Check for old Windows versions
$WINDOWSVERSION = Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Version
if ($WINDOWSVERSION -notmatch "^10\.") {
  throw "This module requires Windows 10."
}

$DependencyHardwareTable = @{
  '_OS'                = 'WIN' + (Get-CimInstance Win32_OperatingSystem).Version -replace "\..*"
  '_CPUAddressWidth'   = [wmisearcher]::new('SELECT AddressWidth FROM Win32_Processor').Get().AddressWidth
  '_Bios'              = (Get-CimInstance -ClassName Win32_BIOS).SMBIOSBIOSVersion
  '_PnPID'             = (Get-PnpDevice).DeviceID
  '_ExternalDetection' = $NULL
  #'_EmbeddedControllerVersion' = [Regex]::Match((Get-CimInstance -ClassName Win32_BIOS).SMBIOSBIOSVersion, "(?<=\()[\d\.]+")
}

[int]$XMLTreeDepth = 0

[System.IO.DirectoryInfo]$LSUClientPath = "$env:ProgramData\LSUClient"
[System.IO.FileInfo]$LSUClientHistoryPath = Join-Path -Path $LSUClientPath -ChildPath "lsu-history.xml"

class LenovoPackage {
  [string]$ID
  [string]$Category
  [string]$Title
  [version]$Version
  [string]$Vendor
  [Severity]$Severity
  [int]$RebootType
  [Uri]$URL
  [PackageExtractInfo]$Extracter
  [PackageInstallInfo]$Installer
  [bool]$IsApplicable
  [bool]$IsInstalled
}

class LenovoHistoryItem {
  [string]$ID
  [string]$Category
  [string]$Title
  [version]$Version
  [bool]$IsInstalled
  [datetime]$UpdatedAt
  [string]$ErrorMessage
}

class PackageExtractInfo {
  [string]$Command
  [string]$FileName
  [int64]$FileSize
  [string]$FileSHA

  PackageExtractInfo ([System.Xml.XmlElement]$PackageXML) {
    $this.Command = $PackageXML.ExtractCommand
    $this.FileName = $PackageXML.Files.Installer.File.Name
    $this.FileSize = $PackageXML.Files.Installer.File.Size
    $this.FileSHA = $PackageXML.Files.Installer.File.CRC
  }
}

class PackageInstallInfo {
  [bool]$Unattended
  [ValidateNotNullOrEmpty()]
  [string]$InstallType
  [int64[]]$SuccessCodes
  [string]$InfFile
  [string]$InstallCommand

  PackageInstallInfo ([System.Xml.XmlElement]$PackageXML, [string]$Category) {
    $this.InstallType = $PackageXML.Install.type
    $this.SuccessCodes = $PackageXML.Install.rc -split ','
    $this.InfFile = $PackageXML.Install.INFCmd.INFfile
    $this.InstallCommand = $PackageXML.Install.Cmdline.'#text'
    if (($PackageXML.Reboot.type -eq 3) -or
      ($Category -eq 'BIOS UEFI' -and $PackageXML.Install.Cmdline.'#text' -like "*winuptp.exe*") -or
      ($PackageXML.Install.type -eq 'INF')) {
      $this.Unattended = $true
    }
    else {
      $this.Unattended = $false
    }
  }
}

function Test-RunningAsAdmin {
  $Identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  return [bool]$Identity.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )
}

function Show-DownloadProgress {
  Param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [array]$Transfers
  )

  [char]$ESC = 0x1b
  [int]$TotalTransfers = $Transfers.Count
  [int]$InitialCursorYPos = $host.UI.RawUI.CursorPosition.Y
  [console]::CursorVisible = $false
  [console]::Write("[ {0}   ]  Downloading packages ...`r[ " -f (' ' * ($TotalTransfers.ToString().Length * 2 + 3)))
  while ($Transfers.IsCompleted -contains $false) {
    $i = $Transfers.Where{ $_.IsCompleted }.Count
    [console]::Write("`r[ {0,2} / $TotalTransfers /" -f $i)
    Start-Sleep -Milliseconds 75
    [console]::Write("`r[ {0,2} / $TotalTransfers $ESC(0q$ESC(B" -f $i)
    Start-Sleep -Milliseconds 75
    [console]::Write("`r[ {0,2} / $TotalTransfers \" -f $i)
    Start-Sleep -Milliseconds 65
    [console]::Write("`r[ {0,2} / $TotalTransfers |" -f $i)
    Start-Sleep -Milliseconds 65
  }
  [console]::SetCursorPosition(1, $InitialCursorYPos)
  if ($Transfers.Status -contains "Faulted" -or $Transfers.Status -contains "Canceled") {
    Write-Host "$ESC[91m    !    $ESC[0m] Downloaded $($Transfers.Where{ $_.Status -notin 'Faulted', 'Canceled'}.Count) / $($Transfers.Count) packages"
  }
  else {
    Write-Host "$ESC[92m    $([char]8730)    $ESC[0m] Downloaded all packages    "
  }
  [console]::CursorVisible = $true
}

function Test-MachineSatisfiesDependency {
  Param (
    [string]$DependencyKey,
    [string]$DependencyValue
  )

  # Return values:
  # 0  SUCCESS, Dependency is met
  # -1 FAILRE, Dependency is not met
  # -2 Unknown dependency kind - status uncertain

  if ($DependencyKey -notin $DependencyHardwareTable.Keys) {
    return -2;
  }

  foreach ($Value in $DependencyHardwareTable["$DependencyKey"]) {
    if ($Value -like "$DependencyValue*") {
      return 0
    }
  }

  return -1;
}

function Resolve-XMLDependencies {
  Param (
    [string]$PackageID,
    [Parameter ( Mandatory = $true )]
    [ValidateNotNullOrEmpty()]
    $XMLIN,
    [switch]$FailUnsupportedDependencies,
    [string]$DebugLogFile
  )

  $XMLTreeDepth++
  [DependencyParserState]$ParserState = 0

  foreach ($XMLTREE in $XMLIN) {
    switch -Regex ($XMLTREE.SchemaInfo.Name) {
      '^_' {
        $ITEM = $XMLTREE.SchemaInfo.Name
      }
      'Not' {
        $ParserState = $ParserState -bxor 1
        if ($DebugLogFile) {
          Add-Content -LiteralPath $DebugLogFile -Value "Switched state to: $ParserState"
        }
      }
    }

    $Results = if ($XMLTREE.HasChildNodes -and $XMLTREE.ChildNodes) {
      if ($DebugLogFile) {
        Add-Content -LiteralPath $DebugLogFile -Value "$('- ' * $XMLTreeDepth)$($XMLTREE.SchemaInfo.Name) has more children --> $($XMLTREE.ChildNodes)"
      }
      $subtreeresults = if ($XMLTREE.SchemaInfo.Name -eq '_ExternalDetection') {
        if ($DebugLogFile) {
          Add-Content -LiteralPath $DebugLogFile -Value "External command is RAW: $($XMLTREE.'#text')"
        }
        # Some commands Lenovo specifies include an unescaped & sign so we have to escape it
        $extCommand = $XMLTREE.'#text' -replace '^%PACKAGEPATH%\\?' -replace '&', '^&'
        $externalDetection = Start-Process -FilePath cmd.exe -WorkingDirectory "$env:Temp" -ArgumentList '/C', "$extCommand >nul" -PassThru -Wait -NoNewWindow
        if ($externalDetection.ExitCode -in ($XMLTREE.rc -split ',')) {
          $true
        }
        else {
          $false
        }
      }
      else {
        Resolve-XMLDependencies -XMLIN $XMLTREE.ChildNodes -FailUnsupportedDependencies:$FailUnsupportedDependencies -DebugLogFile:$DebugLogFile
      }
      #Write-Verbose "$PackageID : $('- ' * $XMLTreeDepth)Cleared $($XMLTREE.SchemaInfo.Name) with results: $subtreeresults`r`n"
      switch ($XMLTREE.SchemaInfo.Name) {
        'And' {
          if ($DebugLogFile) {
            Add-Content -LiteralPath $DebugLogFile -Value "$('- ' * $XMLTreeDepth)Tree was AND: Results: $subtreeresults"
          }
          if ($subtreeresults -contains $false) { $false } else { $true }
        }
        default {
          if ($DebugLogFile) {
            Add-Content -LiteralPath $DebugLogFile -Value "$('- ' * $XMLTreeDepth)Tree was OR: Results: $subtreeresults"
          }
          if ($subtreeresults -contains $true ) { $true } else { $false }
        }
      }
    }
    else {
      switch (Test-MachineSatisfiesDependency -DependencyKey $ITEM -DependencyValue $XMLTREE.innerText) {
        0 {
          $true
        }
        -1 {
          $false
        }
        -2 {
          Write-Verbose "Unsupported dependency encountered: $ITEM`r`n"
          if ($FailUnsupportedDependencies) { $false } else { $true }
        }
      }
      if ($DebugLogFile) {
        Add-Content -LiteralPath $DebugLogFile -Value "$('- ' * $XMLTreeDepth)$ITEM  :  $($XMLTREE.innerText)"
      }
    }
    if ($DebugLogFile) {
      Add-Content -LiteralPath $DebugLogFile -Value "Returning $($Results -bxor $ParserState) from node $($XMLTREE.SchemaInfo.Name)"
    }

    $Results -bxor $ParserState
    $ParserState = 0 # DO_HAVE
  }

  $XMLTreeDepth--
}

function Test-LSUHistoryPath {
  # create folder if it doesn't exist
  if (-not (Test-Path -Path $LSUClientPath -PathType Container)) {
    Write-Verbose "LSUClient directory did not exist, created it: '$LSUClientPath'`r`n"
    $null = New-Item -Path $LSUClientPath -Force -ItemType Directory
  }

  # create lsu-history.xml file if it doesn't exist
  if (-not (Test-Path -Path $LSUClientHistoryPath -PathType Leaf)) {
    Write-Verbose "LSU history file did not exist, created it: '$LSUClientHistoryPath'`r`n"
    $null = New-Item -Path $LSUClientHistoryPath -Force -ItemType File
    $initialArray = [System.Collections.ArrayList]::new()
    Save-LSUHistory -History $initialArray
  }
}

function Test-LSUCachePath {
    param (
        [string]$Filename
    )
    $path = Get-LSUCachePath -Filename $Filename
    Test-Path -Path $path -PathType Leaf
}

function Get-LSUHistory {
  # ensure history file existsp
  Test-LSUHistoryPath
  Try {
    # import data from file
    Import-CliXml $LSUClientHistoryPath
  }
  Catch {
    # the file was malformed so just return an empty array
    Write-Verbose "Error retrieving contents of history file"
    [System.Collections.ArrayList]::new()
  }
}

function Save-LSUHistory {
  [CmdletBinding()]
  Param (
    [LenovoHistoryItem[]]$History
  )
  # ensure history file exists
  Test-LSUHistoryPath
  # export new content to file
  Export-CliXml -InputObject $History -Path $LSUClientHistoryPath
}

function Update-LSUHistory {
  Param(
    [pscustomobject]$Package,
    [string]$ErrorMessage = ""
  )
  $history = Get-LSUHistory

  $historyItem = [LenovoHistoryItem]::new()
  $historyItem.ID = $Package.ID
  $historyItem.Title = $Package.Title
  $historyItem.Category = $Package.Category
  $historyItem.Version = $Package.Version
  $historyItem.IsInstalled = $Package.IsInstalled
  $historyItem.ErrorMessage = $ErrorMessage
  $historyItem.UpdatedAt = Get-Date

  # if the package doesn't exist in the file, then insert it
  # otherwise update the object with the new version
  $existingItem = $history | Where-Object { $_.ID -eq $Package.ID }
  if ($null -eq $existingItem) {
    $history += $historyItem
  }
  else {
    $index = $history.IndexOf($existingItem)
    $history[$index] = $historyItem
  }

  Save-LSUHistory -History $history
}

function Get-LSUCachePath {
    param (
        [string]$Filename
    )
    return "$LSUClientPath/$Filename"
}

function Update-LSUCache {
    param(
        [string]$Filename,
        [LenovoPackage[]]$Packages
    )
    # ensure cache file exists
    if (-not (Test-LSUCachePath -Filename $Filename)) {
        Write-Verbose "Cache file does not exist. Creating $Filename."
        New-LSUCache -Filename $Filename
    }
    # export new content to file
    $path = Get-LSUCachePath -Filename $Filename
    Export-Clixml -InputObject $Packages -Path $path
}

function New-LSUCache {
    param (
        [string]$Filename
    )
    $filePath = Get-LSUCachePath -Filename $Filename
    if (-not (Test-Path -Path $filePath -PathType Leaf)) {
        Write-Verbose "LSU cache file $Filename did not exist, created it: '$filePath'`r`n"
        $null = New-Item -Path $filePath -Force -ItemType File
    }
}

function Get-LSUCache {
    param (
        [string]$Filename
    )
    # ensure history file exists
    if (-not (Test-LSUCachePath -Filename $Filename)) {
        Write-Warning "Cache file does not exist"
        return
    }
    Try {
        # import data from file
        $path = Get-LSUCachePath -Filename $Filename
        Import-CliXml $path
    }
    Catch {
        Write-Verbose "Error retrieving contents of cache file"
    }
}

function Remove-LSUCache {
    param (
        [string]$Filename
    )
    $path = Get-LSUCachePath -Filename $Filename
    Remove-Item $path
}

function Get-LSUpdate {
  <#
        .SYNOPSIS
        Fetches available driver packages and updates for Lenovo computers

        .PARAMETER Model
        Specify an alternative Lenovo Computer Model to retrieve update packages for.
        You may want to use this together with '-All' so that packages are not filtered against your local machines configuration.

        .PARAMETER Proxy
        A URL to a web proxy (e.g. 'http://myproxy:3128')

        .PARAMETER All
        Return all updates, regardless of whether they are applicable to this specific machine or whether they are already installed.
        E.g. this will retrieve LTE-Modem drivers even for machines that do not have the optional LTE-Modem installed. Installation of such drivers will likely still fail.

        .PARAMETER FailUnsupportedDependencies
        Lenovo has different kinds of dependencies they specify for each package. This script makes a best effort to parse, understand and check these.
        However, new kinds of dependencies may be added at any point and some currently in use are not supported yet either. By default, any unknown
        dependency will be treated as met/OK. This switch will fail all dependencies we can't actually check. Typically, an update installation
        will simply fail if there really was a dependency missing.
    #>

  [CmdletBinding()]
  Param (
    [ValidatePattern('^\w{4}$')]
    [string]$Model,
    [Uri]$Proxy,
    [switch]$All,
    [switch]$FailUnsupportedDependencies,
    [ValidateScript( { try { [System.IO.File]::Create("$_").Dispose(); $true } catch { $false } })]
    [string]$DebugLogFile,
    [string]$CacheFile
  )

  # if cache exists return the contents of the cache file
  if ($CacheFile -ne $null) {
    Write-Verbose "Returning package updates from cache"
    $cachedPackages = Get-LSUCache -Filename $CacheFile
    if ($null -ne $cachedPackages) {
        return $cachedPackages
    }
  }

  if (-not (Test-RunningAsAdmin)) {
    Write-Warning "Unfortunately, this command produces most accurate results when run as an Administrator`r`nbecause some of the commands Lenovo uses to detect your computers hardware have to run as admin :("
  }

  $COMPUTERINFO = Get-CimInstance -ClassName CIM_ComputerSystem | Select-Object Manufacturer, Model

  if (-not $Model) {
    $MODELRGX = [regex]::Match($COMPUTERINFO.Model, '^\w{4}')
    if ($MODELRGX.Success -ne $true) {
      throw "Could not parse Lenovo Model number. Full string otained was: '$($COMPUTERINFO.Model)', aborting."
    }
    $Model = $MODELRGX.Value
  }

  Write-Verbose "Lenovo Model is: $Model`r`n"
  if ($DebugLogFile) {
    Add-Content -LiteralPath $DebugLogFile -Value "Lenovo Model is: $Model"
  }

  $webClient = [System.Net.WebClient]::new()
  if ($Proxy) {
    $webClient.Proxy = [System.Net.WebProxy]::new($Proxy)
  }

  try {
    $COMPUTERXML = $webClient.DownloadString("https://download.lenovo.com/catalog/${Model}_Win10.xml")
  }
  catch {
    if ($_.Exception.innerException.Response.StatusCode -eq [System.Net.HttpStatusCode]::NotFound) {
      throw "No information was found on this model of computer (invalid model number or not supported by Lenovo?)"
    }
    else {
      throw "An error occured when contacting download.lenovo.com:`r`n$($_.Exception.Message)"
    }
  }

  $UTF8ByteOrderMark = [System.Text.Encoding]::UTF8.GetString(@(195, 175, 194, 187, 194, 191))

  # Downloading with Net.WebClient seems to remove the BOM automatically, this only seems to be neccessary when downloading with IWR. Still I'm leaving it in to be safe
  [xml]$PARSEDXML = $COMPUTERXML -replace "^$UTF8ByteOrderMark"

  Write-Verbose "A total of $($PARSEDXML.packages.count) driver packages are available for this computer model."

  # get the current history of installed lenovo packages
  $packageHistory = Get-LSUHistory

  [LenovoPackage[]]$packagesCollection = foreach ($packageURL in $PARSEDXML.packages.package) {
    $packageXMLOrig = $webClient.DownloadString($packageURL.location)
    [xml]$packageXML = $packageXMLOrig -replace "^$UTF8ByteOrderMark"

    if ($packageXML.Package.Files.External) {
      foreach ($externalFile in $packageXML.Package.Files.External.ChildNodes) {
        $webClient.DownloadFile(($packageURL.location -replace "[^/]*$") + $externalFile.Name, (Join-Path -Path $env:Temp -ChildPath $externalFile.Name))
      }
    }

    if ($DebugLogFile) {
      Add-Content -LiteralPath $DebugLogFile -Value "Parsing dependencies for package: $($packageXML.Package.id)`r`n"
    }

    $version = if ([Version]::TryParse($packageXML.Package.version, [ref]$null)) { $packageXML.Package.version } else { '0.0.0.0' }

    # attempt to retrieve the current package from the history file so that we can determine if it is already installed
    # if the id and version matches, then we have already installed this package
    # otherwise consider it as uninstalled
    $packageFromHistory = $packageHistory | Where-Object { $_.ID -eq $packageXML.Package.id -and $_.Version -eq $version }

    [LenovoPackage]@{
      'ID'           = $packageXML.Package.id
      'Category'     = $packageURL.category
      'Title'        = $packageXML.Package.Title.Desc.'#text'
      'Version'      = $version
      'Vendor'       = $packageXML.Package.Vendor
      'Severity'     = $packageXML.Package.Severity.type
      'RebootType'   = $packageXML.Package.Reboot.type
      'URL'          = $packageURL.location
      'Extracter'    = $packageXML.Package
      'Installer'    = [PackageInstallInfo]::new($packageXML.Package, $packageURL.category)
      'IsApplicable' = Resolve-XMLDependencies -PackageID $packageXML.Package.id -XML $packageXML.Package.Dependencies -FailUnsupportedDependencies:$FailUnsupportedDependencies -DebugLogFile $DebugLogFile
      'IsInstalled'  = if ($null -eq $packageFromHistory) { $false } else { $packageFromHistory.IsInstalled }
    }
  }

  $webClient.Dispose()

  if ($All) {
    if ($CacheFile -ne $null) { Update-LSUCache -Filename $CacheFile -Packages $packagesCollection}
    return $packagesCollection
  }
  else {
    $filteredPackages = $packagesCollection.Where{ $_.IsApplicable -and -not $_.IsInstalled }
    if ($CacheFile -ne $null) { Update-LSUCache -Filename $CacheFile -Packages $filteredPackages}
    return $filteredPackages
  }
}

function Save-LSUpdate {
  <#
        .SYNOPSIS
        Downlodas a Lenovo update package to disk

        .PARAMETER Package
        The Lenovo package or packages to download

        .PARAMETER Proxy
        A URL to a web proxy (e.g. 'http://myproxy:3128')

        .PARAMETER ShowProgress
        Shows a progress animation during the downloading process, recommended for interactive use
        as downloads can be quite large and without any progress output the script may appear stuck

        .PARAMETER Force
        Redownload and overwrite packages even if they have already been downloaded previously

        .PARAMETER Path
        The target directory to which to download the packages to. In this directory,
        a subfolder will be created for each downloaded package.
    #>

  [CmdletBinding()]
  Param (
    [Parameter( Position = 0, ValueFromPipeline = $true, Mandatory = $true )]
    [pscustomobject]$Package,
    [Uri]$Proxy,
    [switch]$ShowProgress,
    [switch]$Force,
    [System.IO.DirectoryInfo]$Path = "$env:TEMP\LSUPackages"
  )

  begin {
    $transfers = [System.Collections.Generic.List[System.Threading.Tasks.Task]]::new()
    if ($Proxy) {
      $proxyObject = [System.Net.WebProxy]::new($Proxy)
    }
  }

  process {
    foreach ($PackageToGet in $Package) {
      $DownloadDirectory = Join-Path -Path $Path -ChildPath $PackageToGet.id

      if (-not (Test-Path -Path $DownloadDirectory -PathType Container)) {
        Write-Verbose "Destination directory did not exist, created it: '$DownloadDirectory'`r`n"
        $null = New-Item -Path $DownloadDirectory -Force -ItemType Directory
      }

      $PackageDownload = $PackageToGet.URL -replace "[^/]*$"
      $PackageDownload = [String]::Concat($PackageDownload, $PackageToGet.Extracter.FileName)
      $DownloadPath = Join-Path -Path $DownloadDirectory -ChildPath $PackageToGet.Extracter.FileName

      if ($Force -or -not (Test-Path -Path $DownloadPath -PathType Leaf) -or (
          (Get-FileHash -Path $DownloadPath -Algorithm SHA256).Hash -ne $PackageToGet.Extracter.FileSHA)) {
        # Checking if this package was already downloaded, if yes skipping redownload
        $webClient = [System.Net.WebClient]::new()
        if ($Proxy) {
          $webClient.Proxy = $proxyObject
        }
        $transfers.Add( $webClient.DownloadFileTaskAsync($PackageDownload, $DownloadPath) )
      }
    }
  }

  end {
    if ($ShowProgress -and $transfers) {
      Show-DownloadProgress -Transfers $transfers
    }
    else {
      while ($transfers.IsCompleted -contains $false) {
        Start-Sleep -Milliseconds 500
      }
    }

    if ($transfers.Status -contains "Faulted" -or $transfers.Status -contains "Canceled") {
      $errorString = "Not all packages could be downloaded, the following errors were encountered:"
      foreach ($transfer in $transfers.Where{ $_.Status -in "Faulted", "Canceled" }) {
        $errorString += "`r`n$($transfer.AsyncState.AbsoluteUri) : $($transfer.Exception.InnerExceptions.Message)"
      }
      Write-Error $errorString
    }

    foreach ($webClient in $transfers) {
      $webClient.Dispose()
    }
  }
}

function Expand-LSUpdate {
  Param (
    [Parameter( Position = 0, ValueFromPipeline = $true, Mandatory = $true )]
    [pscustomobject]$Package,
    [Parameter( Mandatory = $true )]
    [ValidateScript( { Test-Path -LiteralPath $_ -PathType Container })]
    [string]$Path
  )

  $ExtractCMD = $Package.Extracter.Command -replace "%PACKAGEPATH%", ('"{0}"' -f $Path)
  $ExtractARGS = $ExtractCMD -replace "^$($Package.Extracter.FileName)"

  if (Get-ChildItem -Path $Path -File) {
    Start-Process -FilePath $Package.Extracter.FileName -Verb RunAs -WorkingDirectory $Path -Wait -ArgumentList $ExtractARGS
  }
  else {
    Write-Warning "This package was not downloaded or deleted (empty folder), skipping extraction ...`r`n"
  }
}

function Install-LSUpdate {
  <#
        .SYNOPSIS
        Installs a Lenovo update package. Downloads it if not previously downloaded.

        .PARAMETER Package
        The Lenovo package object to install

        .PARAMETER Path
        If you previously downloaded the Lenovo package to a custom directory, specify its path here so that the package can be found
    #>

  [CmdletBinding()]
  Param (
    [Parameter( Position = 0, ValueFromPipeline = $true)]
    [pscustomobject]$Package,
    [string]$PackageId,
    [string]$CacheFile,
    [ValidateScript( { Test-Path -LiteralPath $_ -PathType Container })]
    [System.IO.DirectoryInfo]$Path = "$env:TEMP\LSUPackages"
  )

  process {
    # if packageId and a cache file was provided then get the package from the cache
    if ($null -ne $PackageId -and $null -ne $CacheFile) {
        $cache = Get-LSUCache -Filename $CacheFile
        $Package = $cache | Where-Object { $_.ID -eq $PackageId }
        if ($null -eq $Package) {
            Write-Error "$PackageId not found in cache $CacheFile"
            return
        }
    }
    foreach ($PackageToProcess in $Package) {
      $PackageDirectory = Join-Path -Path $Path -ChildPath $PackageToProcess.id
      if (-not (Test-Path -LiteralPath (Join-Path -Path $PackageDirectory -ChildPath $PackageToProcess.Extracter.FileName) -PathType Leaf)) {
        Write-Verbose "Package '$($PackageToProcess.id)' was not yet downloaded or deleted, downloading ..."
        Save-LSUpdate -Package $PackageToProcess -Path $Path
      }

      Expand-LSUpdate -Package $PackageToProcess -Path $PackageDirectory

      Write-Verbose "Installing package $($PackageToProcess.ID) ...`r`n"

      $errorMessage = "";

      if ($PackageToProcess.Category -eq 'BIOS UEFI') {
        # We are dealing with a BIOS Update
        if (Test-Path -LiteralPath "$PackageDirectory\winuptp.exe") {
          if (Test-Path -LiteralPath "$PackageDirectory\winuptp.log" -PathType Leaf) {
            Remove-Item -LiteralPath "$PackageDirectory\winuptp.log" -Force
          }

          $installProcess = Start-Process -FilePath "$PackageDirectory\winuptp.exe" -Wait -Verb RunAs -WorkingDirectory $PackageDirectory -PassThru -ArgumentList "-s"
          if ($installProcess.ExitCode -notin $PackageToProcess.Installer.SuccessCodes) {
            $LenovoBIOSUpdateLog = (Get-Content -LiteralPath "$PackageDirectory\winuptp.log" -Raw).Trim()
            $errorMessage = "Unattended BIOS/UEFI Update FAILED with return code $($installProcess.ExitCode)!`r`nThe following log was created:`r`n$LenovoBIOSUpdateLog`r`n"
            Write-Warning $errorMessage
          }
          else {
            Write-Host "BIOS UPDATE SUCCESS: An immediate full power cycle / reboot is strongly recommended to allow the BIOS update to complete!`r`n"
            $Package.IsInstalled = $true
          }
        }
        else {
          $errorMessage = "Either this is not a BIOS Update or it's an unsupported installer for one, skipping installation ...`r`n"
          Write-Warning $errorMessage
        }
      }
      else {
        switch ($PackageToProcess.Installer.InstallType) {
          'CMD' {
            $InstallCMD = $PackageToProcess.Installer.InstallCommand -replace "%PACKAGEPATH%", $PackageDirectory
            # Correct typo from Lenovo ... yes really...
            $InstallCMD = $InstallCMD -replace '-overwirte', '-overwrite'

            $installProcess = Start-Process -FilePath cmd.exe -Wait -Verb RunAs -WorkingDirectory $PackageDirectory -PassThru -ArgumentList '/c', "$InstallCMD"
            if ($installProcess.ExitCode -notin $PackageToProcess.Installer.SuccessCodes) {
              $errorMessage = "Installation of package '$($PackageToProcess.id) - $($PackageToProcess.Title)' FAILED with return code $($installProcess.ExitCode)!`r`n"
              Write-Warning $errorMessage
            }
            else {
              $Package.IsInstalled = $true
            }
          }
          'INF' {
            $installProcess = Start-Process -FilePath pnputil.exe -Wait -Verb RunAs -WorkingDirectory $PackageDirectory -PassThru -ArgumentList "/add-driver $($PackageToProcess.Installer.InfFile) /install"
            # pnputil is a documented Microsoft tool and Exit code 0 means SUCCESS while 3010 means SUCCESS but reboot required,
            # however Lenovo does not always include 3010 as an OK return code - that's why we manually check against it here
            if ($installProcess.ExitCode -notin $PackageToProcess.Installer.SuccessCodes -and $installProcess.ExitCode -notin 0, 3010) {
              $errorMessage = "Installation of package '$($PackageToProcess.id) - $($PackageToProcess.Title)' FAILED with return code $($installProcess.ExitCode)!`r`n"
              Write-Warning $errorMessage
            }
            else {
              $Package.IsInstalled = $true
            }
          }
          default {
            $errorMessage = "Unsupported package installtype '$_', skipping installation ...`r`n"
            Write-Warning $errorMessage
          }
        }
      }

      # update history file
      Update-LSUHistory -Package $Package -ErrorMessage $errorMessage
    }
  }
}
