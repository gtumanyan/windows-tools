# Run in Elevated PowerShell
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$Arch = 'x64'  # change to 'arm64' on ARM devices

# --- 1) Query GitHub API for the newest release (including pre-releases) ---
$apiUrl = 'https://api.github.com/repos/microsoft/winget-cli/releases'
$releases = Invoke-RestMethod -Uri $apiUrl -Headers @{ 'User-Agent' = 'PowerShell' }
$latest = $releases[0]
Write-Host "Using release: $($latest.tag_name)" -ForegroundColor Cyan

$bundleAsset = $latest.assets | Where-Object { $_.name -eq 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle' }
$depAsset    = $latest.assets | Where-Object { $_.name -eq 'DesktopAppInstaller_Dependencies.zip' }

if (-not $bundleAsset) { throw 'Could not find msixbundle asset in latest release.' }
if (-not $depAsset)    { throw 'Could not find Dependencies ZIP asset in latest release.' }

$depZip    = 'DesktopAppInstaller_Dependencies.zip'
$bundle    = 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
$checkFile = 'check.txt'

# --- Skip download if the bundle URL hasn't changed and local files exist ---
$cachedUrl = if (Test-Path $checkFile) { (Get-Content $checkFile -Raw -ErrorAction SilentlyContinue).Trim() } else { '' }
$latestUrl = $bundleAsset.browser_download_url

if ($cachedUrl -eq $latestUrl -and (Test-Path $bundle) -and (Test-Path $depZip)) {
    Write-Host 'Files already up-to-date — skipping download.' -ForegroundColor Green
} else {
    Write-Host 'Downloading new release files...' -ForegroundColor Yellow
    Invoke-WebRequest -Uri $depAsset.browser_download_url  -OutFile $depZip
    Invoke-WebRequest -Uri $bundleAsset.browser_download_url -OutFile $bundle
    Set-Content -Path $checkFile -Value $latestUrl -NoNewline
}

Expand-Archive -Path $depZip -DestinationPath . -Force

# --- 2) Collect all arch-matching .appx deps from the ZIP ---
$deps = Get-ChildItem -Path . -Recurse -Filter "*.appx" |
        Where-Object { $_.Name -match $Arch } |
        Select-Object -ExpandProperty FullName

if (-not $deps) { throw "No ${Arch} .appx dependencies found in dependency ZIP." }

# --- 3) Install App Installer (winget) with all deps at once ---
Add-AppxPackage -Path $bundle -DependencyPath $deps `
  -ForceUpdateFromAnyVersion -ForceApplicationShutdown

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