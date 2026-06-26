# Run in Elevated PowerShell
$ErrorActionPreference = 'Continue'
# $ProgressPreference    = 'SilentlyContinue'

$Arch = 'x64'  # change to 'arm64' on ARM devices

# --- 1) Query GitHub API for the newest release (including pre-releases) ---
$apiUrl = 'https://api.github.com/repos/microsoft/winget-cli/releases'
$releases = Invoke-RestMethod -Uri $apiUrl -Headers @{ 'User-Agent' = 'PowerShell' }
$latest = $releases[0]
$remoteVersion = $latest.tag_name
if ((winget --version) -ge $remoteVersion) {    
    Write-Host "Winget is already up-to-date. Nothing to install." -ForegroundColor Green
    return
}

Write-Host "Winget is missing or outdated" -ForegroundColor Yellow

$depZip = 'DesktopAppInstaller_Dependencies.zip'
$depAsset = $latest.assets | Where-Object { $_.name -eq $depZip }
if (-not $depAsset) { throw 'Could not find Dependencies ZIP asset in latest release.' }
$bundle = 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
$bundleAsset = $latest.assets | Where-Object { $_.name -eq $bundle }
if (-not $bundleAsset) { throw 'Could not find msixbundle asset in latest release.' }

# --- Skip download if the bundle hasn't changed and local files exist ---
if ((Get-FileHash  $bundle).Hash.ToLower() -eq ($bundleAsset.digest -replace '^sha256:')) {
    Write-Host 'Actual bundle files found — skipping download.' -ForegroundColor Green
}
else {
    Write-Host 'Downloading new release files...' -ForegroundColor Yellow
    # --- Skip download of the DesktopAppInstaller_Dependencies.zip if hash hasn't changed and local files exist ---
    if ((Get-FileHash $depZip).Hash.ToLower() -ne ($depAsset.digest -replace '^sha256:')) {
        Invoke-WebRequest -Uri $depAsset.browser_download_url  -OutFile $depZip 
        Expand-Archive -Path $depZip -DestinationPath . -Force
    }
    Invoke-WebRequest -Uri $bundleAsset.browser_download_url -OutFile $bundle
}

# --- 2) Collect all arch-matching .appx deps from the ZIP ---
$deps = Get-ChildItem -Path . -Recurse -Filter "*.appx" |
        Where-Object { $_.Name -match $Arch } |
        Select-Object -ExpandProperty FullName

if (-not $deps) { throw "No ${Arch} .appx dependencies found in dependency ZIP." }

# --- 3) Install App Installer (winget) with all deps at once ---
Add-AppxPackage -Path $bundle -DependencyPath $deps

# --- 4) Verify & fix PATH shim if needed ---
# Winget usually shims to %LOCALAPPDATA%\Microsoft\WindowsApps
$wingetPath = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
if (Test-Path $wingetPath) {
    & $wingetPath update
} else {
    # Try to find a versioned install under Program Files\WindowsApps
    $found = Get-ChildItem "$env:ProgramFiles\WindowsApps" -Filter "Microsoft.DesktopAppInstaller_*_${Arch}__8wekyb3d8bbwe" -Directory -ErrorAction SilentlyContinue |
             Sort-Object Name -Descending | Select-Object -First 1
    if ($found) {
        $exe = Join-Path $found.FullName 'winget.exe'
        if (Test-Path $exe) { & $exe --version }
    }
    Write-Host "`nIf 'winget' is still not recognized, open a NEW PowerShell window or sign out/in." -ForegroundColor Yellow
}