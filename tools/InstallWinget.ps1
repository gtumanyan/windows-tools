# Store current value
$OriginalErrorActionPreference = $ErrorActionPreference

# Set to silently continue
$ErrorActionPreference = 'SilentlyContinue'

if ($Host.Version.Major -eq 5) {
    # Progress bar can significantly impact cmdlet performance
    # https://github.com/PowerShell/PowerShell/issues/2138
    $Script:ProgressPreference = "SilentlyContinue"
}

# --- Query GitHub API for the newest release (including pre-releases) ---
$apiUrl = 'https://api.github.com/repos/microsoft/winget-cli/releases'
$releases = Invoke-RestMethod -Uri $apiUrl -Headers @{ 'User-Agent' = 'PowerShell' }
$latest = $releases[0]
$currentVersion = winget --version
$remoteVersion = $latest.tag_name
if ($currentVersion -eq $remoteVersion) {    
    Write-Output ""
    Write-Output ("Current Version:  {0,-40}" -f $currentVersion)
    Write-Output ("Status:           {0,-40}" -f "Up to date.") 
    return
}
if ($currentVersion) { Write-Output "$remoteVersion is available." }
else {
    Write-Output "Winget is missing." 

    # ------------------------------------------------------------------------ #
    # Dependencies
    # ------------------------------------------------------------------------ #

    $DepsZip = 'DesktopAppInstaller_Dependencies.zip'
    $depAsset = $latest.assets | Where-Object { $_.name -eq $DepsZip }
    if (-not $depAsset) { throw 'Could not find Dependencies ZIP asset in latest release.' }
    $DepsUrl = $depAsset.browser_download_url
    # --- Skip download of the DesktopAppInstaller_Dependencies.zip if hash hasn't changed and local files exist ---
    # Check also path set by TCPU in case script ran in total commander PowerUser evironment
    if (Test-Path $env:P\Web-Install\Winget\$DepsZip) {
        if ((Get-FileHash $DepsZip).Hash.ToLower() -eq ($depAsset.digest -replace '^sha256:')) {
            Write-Verbose '$DepsZip is current — skipping download.'
        }
        else {
            Write-Host 'Downloading dependencies from $DepsUrl...' -ForegroundColor Yellow
            Invoke-WebRequest -Uri $DepsUrl -OutFile $DepsZip

            
            Expand-Archive $DepsZip
        }
    } 
    else {
        Write-Output "Downloading winget dependencies..."
        Write-Debug "Downloading winget dependencies from $DepsUrl to $deps`n`n"
        $DepsZip = Join-Path $env:TEMP 'DesktopAppInstaller_Dependencies.zip'
        Invoke-WebRequest -Uri $DepsUrl -OutFile $DepsZip
        
        Expand-Archive -Path $DepsZip -DestinationPath $deps -Force
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
    if ($arch -eq "32") {
        $arch = "x86"
    }
    elseif ($arch -eq "64") {
        $arch = "x64"
    }

    $deps = Get-ChildItem -Path $arch -Recurse -Filter "*.appx" |
    Select-Object -ExpandProperty FullName    
}


# ------------------------------------------------------------------------ #
# AppInstaller (winget)
# ------------------------------------------------------------------------ #
$WingetPkg = 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
$bundleAsset = $latest.assets | Where-Object { $_.name -eq $WingetPkg }
$WingetUrl = $bundleAsset.browser_download_url
if (-not $bundleAsset) { throw 'Could not find msixbundle asset in latest release.' }

# --- Skip download if the bundle hasn't changed and local files exist ---
if (Test-Path $WingetPkg) {
    if ((Get-FileHash $WingetPkg).Hash.ToLower() -eq ($bundleAsset.digest -replace '^sha256:')) {
        Write-Host 'Local bundle is current — skipping download.' -ForegroundColor Green
        $bundlePath = $WingetPkg
    }
    else {
        Write-Host 'Local bundle is outdated — downloading from $WingetUrl...' -ForegroundColor Yellow
        Invoke-WebRequest -Uri $WingetUrl -OutFile $WingetPkg
        $bundlePath = $WingetPkg
    }
}
else {
    Write-Host 'No local bundle — will install directly from $WingetUrl.' -ForegroundColor Cyan
    $bundlePath = $WingetUrl
}

# Reset to original value
$ErrorActionPreference = $OriginalErrorActionPreference

# --- Install winget
Write-Output "Installing winget $remoteVersion..."
# Assume dependencies are already installed
Try {Add-AppxPackage $bundlePath -ForceUpdateFromAnyVersion -ForceApplicationShutdown -Verbose}
# Install with dependencies (slower)
Catch {Add-AppxPackage $bundlePath -DependencyPath $deps -Verbose}

# --- Verify & fix PATH shim if needed ---
# Winget usually shims to %LOCALAPPDATA%\Microsoft\WindowsApps
$wingetPath = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
if (Test-Path $wingetPath) {
    & $wingetPath update
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
    Write-Host "`nIf 'winget' is still not recognized, open a NEW PowerShell window or sign out/in." -ForegroundColor Yellow
}
