# $OriginalErrorActionPreference = $ErrorActionPreference
# $ErrorActionPreference = 'Stop'

if ($Host.Version.Major -eq 5) {
    # Progress bar can significantly impact cmdlet performance
    # https://github.com/PowerShell/PowerShell/issues/2138
    $Script:ProgressPreference = "SilentlyContinue"
}

# ------------------------------------------------------------------------ #
# Query GitHub API for the newest release (including pre-releases)
# ------------------------------------------------------------------------ #

$apiUrl = 'https://api.github.com/repos/microsoft/winget-cli/releases'
$releases = Invoke-RestMethod -Uri $apiUrl -Headers @{ 'User-Agent' = 'PowerShell' }
$latest = $releases[0]
try { $VersionInstalled = & winget --version }
catch {
    Write-Verbose "winget.exe is not runnable: $($_.Exception.Message)"
}

$VersionAvailable = $latest.tag_name

if ($VersionInstalled -eq $VersionAvailable) {    
    Write-Verbose "Winget $VersionInstalled is already installed, exiting..."
    # $ErrorActionPreference = $OriginalErrorActionPreference
    return
}

if ($VersionInstalled -gt $VersionAvailable) {
    Write-Host ''
    Write-Warning "Installed $VersionInstalled is newer than the newest GitHub Release $VersionAvailable"
    Write-Host ''
    return
}

# ------------------------------------------------------------------------ #
# AppInstaller (winget)
# ------------------------------------------------------------------------ #
$WingetPkg = 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
$bundleAsset = $latest.assets | Where-Object { $_.name -eq $WingetPkg }
if (-not $bundleAsset) { Write-Error "Could not find msixbundle asset in latest release." }
$WingetUrl = $bundleAsset.browser_download_url

# --- Skip download if local bundle exist and matches remote ---
if (Test-Path $WingetPkg) {
    if ((Get-FileHash $WingetPkg).Hash.ToLower() -eq ($bundleAsset.digest -replace '^sha256:')) {
        Write-Host 'Local bundle is current — skipping download.' -ForegroundColor Green
        $bundlePath = $WingetPkg
    }
    Write-Debugelse {
        Write-Host "Local bundle is outdated — downloading from $WingetUrl..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $WingetUrl -OutFile $WingetPkg
        $bundlePath = $WingetPkg
    }
}
else {
    Write-Debug "No local bundle — will install directly from $WingetUrl"
    $bundlePath = $WingetUrl
}


# ============================================================================ #
# Beginning of installation process
# ============================================================================ #
# Install winget assuming dependencies are already installed
Write-Output "Installing winget..."
try { Add-AppxPackage $bundlePath -ForceUpdateFromAnyVersion -ForceApplicationShutdown -Verbose }

# Install with dependencies (slower)
Catch {
    # ------------------------------------------------------------------------ #
    # Dependencies (only when winget is absent)
    # ------------------------------------------------------------------------ #

    $DepsZip = 'DesktopAppInstaller_Dependencies.zip'
    $depAsset = $latest.assets | Where-Object { $_.name -eq $DepsZip }
    if (-not $depAsset) { throw 'Could not find the dependencies ZIP asset in the latest release.' }

    $winget_dependencies_url = $depAsset.browser_download_url
    # --- Skip download of the DesktopAppInstaller_Dependencies.zip if hash hasn't changed and local files exist ---
    # Check also path set by TCPU in case script ran in total commander PowerUser evironment
    $cacheDir = if ($env:P -and (Test-Path "$env:P\Web-Install\Winget")) { "$env:P\Web-Install\Winget" } else { $env:TEMP }
    $DepsZip = Join-Path $cacheDir $DepsZip
    if (Test-Path $DepsZip) {
        if ((Get-FileHash $DepsZip).Hash.ToLower() -eq ($depAsset.digest -replace '^sha256:')) {
            Write-Verbose "$DepsZip is current — skipping download."
        }
        else {
            Write-Debug "Downloading winget dependencies from $winget_dependencies_url to $cacheDir`n`n"
            Invoke-WebRequest -Uri $winget_dependencies_url -OutFile $DepsZip       
            Expand-Archive $DepsZip
        }
    }

    # Get OS details using Get-CimInstance because the registry key for Name is not always correct with Windows 11
    try {
        $osDetails = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    }
    catch {
        throw "Unable to run the command ""Get-CimInstance -ClassName Win32_OperatingSystem"". If you're using Window Sandbox, this may be related to a known issue with winget on Windows Sandbox: https://github.com/microsoft/Windows-Sandbox/issues/67"
    }
    
    # Get architecture details of the OS (not the processor)
    # Get only the numbers
    $arch = ($osDetails.OSArchitecture -replace "[^\d]").Trim()
    
    # If 32-bit or 64-bit replace with x32 and x64
    if ($arch -eq "32") { $arch = "x86" }
    elseif ($arch -eq "64") { $arch = "x64" }

    $deps = Get-ChildItem -Path $arch -Recurse -Filter "*.appx" | Select-Object -ExpandProperty FullName    

    # Now install winget with dependencies
    Add-AppxPackage $bundlePath -DependencyPath $deps -Verbose
}

# ============================================================================ #
#  Done
# ============================================================================ #

# --- Verify & fix PATH shim if needed ---
# Winget usually shims to %LOCALAPPDATA%\Microsoft\WindowsApps
$wingetPath = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
if (Test-Path $wingetPath) {
    Write-Host "`nDone! Running 'winget update' to check for available updates." -ForegroundColor Green
    & $wingetPath update --accept-source-agreements
    Write-Host "`nUpdate all?" -ForegroundColor Cyan
    $response = Read-Host "Press [Enter] to update, type anything else to exit"
    if ($response -eq '') {
        & $wingetPath update --all
    }
}
else {
    # Try to find a versioned install under Program Files\WindowsApps
    $found = Get-ChildItem "$env:ProgramFiles\WindowsApps" -Filter "Microsoft.DesktopAppInstaller_*_$arch__8wekyb3d8bbwe" -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending | Select-Object -First 1
    if ($found) {
        $exe = Join-Path $found.FullName 'winget.exe'
        if (Test-Path $exe) { & $exe --version }
    }
    ""
    Write-Host "If 'winget' is still not recognized, open a NEW PowerShell window or sign out/in." -ForegroundColor Yellow
}